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

// maxTimings caps how many recent scan durations the reviewer keeps for its
// estimates.
const maxTimings = 16

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
	// timings holds how long recent scans took, oldest first.
	timings []time.Duration
	// took maps an image to how long its last scan took.
	took map[string]time.Duration
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
		took:    make(map[string]time.Duration),
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
	ReportProgress(ctx, "Scanning the new image")

	latest, err := r.scan(ctx, latestImage)
	if err != nil {
		return nil, err
	}

	ReportProgress(ctx, "Scanning the running image to compare")

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

// Expected estimates how long scanning image would take now: nothing when a
// fresh result is cached, as long as its last scan when it was scanned
// before, or else the average of recent scans.
//
// Parameters:
//   - image: Image ID or name.
//
// Returns:
//   - time.Duration: Expected scan time.
//   - bool: False when the reviewer has nothing to base an estimate on.
func (r *Reviewer) Expected(image string) (time.Duration, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if cached, ok := r.cache[image]; ok && r.now().Sub(cached.storedAt) < cacheLifetime {
		return 0, true
	}

	if took, ok := r.took[image]; ok {
		return took, true
	}

	if len(r.timings) == 0 {
		return 0, false
	}

	var sum time.Duration
	for _, took := range r.timings {
		sum += took
	}

	return sum / time.Duration(len(r.timings)), true
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

	began := r.now()

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
	r.recordTiming(image, r.now().Sub(began))

	for len(r.order) > maxCachedResults {
		delete(r.cache, r.order[0])
		r.order = r.order[1:]
	}

	return result, nil
}

// recordTiming keeps how long a successful scan took, for Expected. The
// caller holds r.mu.
//
// Parameters:
//   - image: Image ID or name.
//   - took: Scan duration.
func (r *Reviewer) recordTiming(image string, took time.Duration) {
	if took <= 0 {
		return
	}

	if _, known := r.took[image]; !known && len(r.took) >= maxCachedResults {
		clear(r.took)
	}

	r.took[image] = took

	r.timings = append(r.timings, took)
	if len(r.timings) > maxTimings {
		r.timings = r.timings[len(r.timings)-maxTimings:]
	}
}
