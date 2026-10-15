package scanner

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// DefaultTimeout bounds one image scan, including a first-run database
// download. Large images, where Trivy exports and reads every layer and
// checks every file for secrets, can take several minutes on a NAS.
const DefaultTimeout = 15 * time.Minute

// ErrScanTimeout indicates a scan did not finish within the reviewer's timeout.
var ErrScanTimeout = errors.New("scan did not finish in time")

// maxCachedResults caps how many image results the reviewer keeps in memory.
const maxCachedResults = 256

// cacheLifetime is how long a cached result is reused. An image's contents
// never change, but the vulnerability database does, so an old result can
// miss advisories published since.
const cacheLifetime = 12 * time.Hour

// Review is the security comparison of a pending update.
type Review struct {
	// Current is the scan of the running image.
	Current *Result `json:"current"`
	// Latest is the scan of the image the update switches to.
	Latest *Result `json:"latest"`
	// Diff lists the findings the update fixes, introduces, and leaves in place.
	Diff Diff `json:"diff"`
	// Gate is the severity gate the review was checked against.
	Gate Gate `json:"gate"`
	// Hold is true when the gate holds the update back.
	Hold bool `json:"hold"`
}

// Reviewer scans both images of a pending update and applies the severity
// gate. Results are cached by image ID for cacheLifetime, so a container that
// stays stale across scans is not rescanned every time.
//
// Scans run one at a time. Every Trivy run shares one cache volume whose
// databases are locked by the process using them, so parallel scanners only
// queue on the lock while their timeouts run down.
type Reviewer struct {
	scanner Scanner
	gate    Gate
	timeout time.Duration
	now     func() time.Time
	// slot holds a token while a scan runs; the timeout starts once it is held.
	slot chan struct{}

	mu    sync.Mutex
	cache map[string]cachedResult
	order []string
}

// cachedResult is a scan result and when the reviewer stored it.
type cachedResult struct {
	result   *Result
	storedAt time.Time
}

// NewReviewer creates a Reviewer.
//
// Parameters:
//   - scanner: Backend that scans one image.
//   - gate: Severity gate. GateOff never holds an update.
//   - timeout: Bound for each image scan. Non-positive means DefaultTimeout.
//
// Returns:
//   - *Reviewer: Reviewer.
func NewReviewer(scanner Scanner, gate Gate, timeout time.Duration) *Reviewer {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	return &Reviewer{
		scanner: scanner,
		gate:    gate,
		timeout: timeout,
		now:     time.Now,
		slot:    make(chan struct{}, 1),
		cache:   make(map[string]cachedResult),
	}
}

// Name returns the scanner backend's name.
//
// Returns:
//   - string: Backend name, such as "trivy".
func (r *Reviewer) Name() string {
	return r.scanner.Name()
}

// ReviewUpdate scans the running and the new image and compares them. The
// new image is scanned first: if that fails there is nothing to compare and
// the review fails. A failed scan of the running image is not an error; the
// review then treats every finding of the new image as introduced, which
// errs on the side of holding when a gate is set.
//
// Parameters:
//   - ctx: Context for both scans.
//   - currentImage: Image ID of the running container.
//   - latestImage: Image ID the update switches to.
//
// Returns:
//   - *Review: Comparison and gate decision.
//   - error: Non-nil when the new image could not be scanned.
func (r *Reviewer) ReviewUpdate(
	ctx context.Context,
	currentImage, latestImage string,
) (*Review, error) {
	latest, err := r.scan(ctx, latestImage)
	if err != nil {
		return nil, err
	}

	current, err := r.scan(ctx, currentImage)
	if err != nil {
		current = nil
	}

	diff := Compare(current, latest)

	return &Review{
		Current: current,
		Latest:  latest,
		Diff:    diff,
		Gate:    r.gate,
		Hold:    diff.Blocks(r.gate),
	}, nil
}

// Scan scans one image, using the cached result when there is one.
//
// Parameters:
//   - ctx: Context for the scan.
//   - image: Image ID or name.
//
// Returns:
//   - *Result: Scan result.
//   - error: Non-nil when the scan fails.
func (r *Reviewer) Scan(ctx context.Context, image string) (*Result, error) {
	return r.scan(ctx, image)
}

// Rescan scans one image even when a cached result exists, and caches the
// new result. Use it when the caller wants findings against the latest
// vulnerability database.
//
// Parameters:
//   - ctx: Context for the scan.
//   - image: Image ID or name.
//
// Returns:
//   - *Result: Scan result.
//   - error: Non-nil when the scan fails.
func (r *Reviewer) Rescan(ctx context.Context, image string) (*Result, error) {
	r.mu.Lock()
	delete(r.cache, image)
	r.mu.Unlock()

	return r.scan(ctx, image)
}

// scan returns the cached result for image, or scans it under the timeout.
//
// Parameters:
//   - ctx: Context for the scan.
//   - image: Image ID or name.
//
// Returns:
//   - *Result: Scan result.
//   - error: Non-nil when the scan fails.
func (r *Reviewer) scan(ctx context.Context, image string) (*Result, error) {
	if image == "" {
		return nil, fmt.Errorf("%w: no image", ErrScanFailed)
	}

	r.mu.Lock()
	cached, ok := r.cache[image]
	r.mu.Unlock()

	if ok && r.now().Sub(cached.storedAt) < cacheLifetime {
		return cached.result, nil
	}

	select {
	case r.slot <- struct{}{}:
	default:
		ReportProgress(ctx, "Waiting for another scan to finish")

		select {
		case r.slot <- struct{}{}:
		case <-ctx.Done():
			return nil, fmt.Errorf("scanning %s with %s: %w", image, r.scanner.Name(), ctx.Err())
		}
	}

	defer func() { <-r.slot }()

	// Another caller may have scanned the image while this one waited.
	r.mu.Lock()
	cached, ok = r.cache[image]
	r.mu.Unlock()

	if ok && r.now().Sub(cached.storedAt) < cacheLifetime {
		return cached.result, nil
	}

	scanCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	result, err := r.scanner.Scan(scanCtx, image)
	if err != nil {
		if ctx.Err() == nil && errors.Is(scanCtx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf(
				"scanning %s with %s: %w after %s; large images may need a longer --scan-timeout",
				image,
				r.scanner.Name(),
				ErrScanTimeout,
				r.timeout,
			)
		}

		return nil, fmt.Errorf("scanning %s with %s: %w", image, r.scanner.Name(), err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.cache[image]; !exists {
		r.order = append(r.order, image)
	}

	r.cache[image] = cachedResult{result: result, storedAt: r.now()}

	for len(r.order) > maxCachedResults {
		delete(r.cache, r.order[0])
		r.order = r.order[1:]
	}

	return result, nil
}
