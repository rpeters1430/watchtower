package scanner

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubScanner struct {
	mu       sync.Mutex
	results  map[string]*Result
	errs     map[string]error
	calls    map[string]int
	deadline bool
}

func (s *stubScanner) Name() string { return "stub" }

func (s *stubScanner) Scan(ctx context.Context, ref string) (*Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.calls == nil {
		s.calls = map[string]int{}
	}

	s.calls[ref]++

	_, s.deadline = ctx.Deadline()

	err := s.errs[ref]
	if err != nil {
		return nil, err
	}

	return s.results[ref], nil
}

func newStub(t *testing.T) *stubScanner {
	t.Helper()

	return &stubScanner{results: map[string]*Result{
		"sha256:old": parseFixture(t, "trivy-current.json"),
		"sha256:new": parseFixture(t, "trivy-next.json"),
	}}
}

func TestReviewerReviewUpdate(t *testing.T) {
	t.Parallel()

	stub := newStub(t)
	reviewer := NewReviewer(stub, GateCritical, time.Minute)

	review, err := reviewer.ReviewUpdate(t.Context(), "sha256:old", "sha256:new")
	require.NoError(t, err)

	assert.Equal(t, []string{"CVE-2024-0001", "CVE-2024-0003"}, findingIDs(review.Diff.Fixed))
	assert.True(t, review.Hold)
	assert.Equal(t, GateCritical, review.Gate)
	assert.True(t, stub.deadline)

	// A second review of the same images is served from the cache.
	_, err = reviewer.ReviewUpdate(t.Context(), "sha256:old", "sha256:new")
	require.NoError(t, err)
	assert.Equal(t, 1, stub.calls["sha256:old"])
	assert.Equal(t, 1, stub.calls["sha256:new"])
}

func TestReviewerGateOff(t *testing.T) {
	t.Parallel()

	review, err := NewReviewer(newStub(t), GateOff, 0).
		ReviewUpdate(t.Context(), "sha256:old", "sha256:new")
	require.NoError(t, err)
	assert.False(t, review.Hold)
	assert.NotEmpty(t, review.Diff.Introduced)
}

func TestReviewerLatestScanFails(t *testing.T) {
	t.Parallel()

	stub := newStub(t)
	stub.errs = map[string]error{"sha256:new": errFake}

	_, err := NewReviewer(stub, GateCritical, 0).
		ReviewUpdate(t.Context(), "sha256:old", "sha256:new")
	require.ErrorIs(t, err, errFake)
	assert.Zero(t, stub.calls["sha256:old"])
}

func TestReviewerCurrentScanFails(t *testing.T) {
	t.Parallel()

	stub := newStub(t)
	stub.errs = map[string]error{"sha256:old": errFake}

	review, err := NewReviewer(stub, GateOff, 0).
		ReviewUpdate(t.Context(), "sha256:old", "sha256:new")
	require.NoError(t, err)
	assert.Nil(t, review.Current)
	assert.Empty(t, review.Diff.Fixed)
	assert.Len(t, review.Diff.Introduced, len(review.Latest.Findings))
}

func TestReviewerEmptyImage(t *testing.T) {
	t.Parallel()

	_, err := NewReviewer(newStub(t), GateOff, 0).Scan(t.Context(), "")
	require.ErrorIs(t, err, ErrScanFailed)
}

func TestReviewerCacheLimit(t *testing.T) {
	t.Parallel()

	stub := &stubScanner{results: map[string]*Result{}}
	reviewer := NewReviewer(stub, GateOff, 0)

	for i := range maxCachedResults + 10 {
		_, err := reviewer.Scan(t.Context(), string(rune('a'+i%26))+time.Duration(i).String())
		require.NoError(t, err)
	}

	assert.Len(t, reviewer.cache, maxCachedResults)
	assert.Len(t, reviewer.order, maxCachedResults)
}

func TestReviewerCacheExpires(t *testing.T) {
	t.Parallel()

	stub := newStub(t)
	reviewer := NewReviewer(stub, GateOff, time.Minute)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	reviewer.now = func() time.Time { return now }

	_, err := reviewer.Scan(t.Context(), "sha256:old")
	require.NoError(t, err)

	now = now.Add(cacheLifetime - time.Minute)
	_, err = reviewer.Scan(t.Context(), "sha256:old")
	require.NoError(t, err)
	assert.Equal(t, 1, stub.calls["sha256:old"], "a fresh result is reused")

	now = now.Add(2 * time.Minute)
	_, err = reviewer.Scan(t.Context(), "sha256:old")
	require.NoError(t, err)
	assert.Equal(t, 2, stub.calls["sha256:old"], "an old result is scanned again")
}

func TestReviewerRescan(t *testing.T) {
	t.Parallel()

	stub := newStub(t)
	reviewer := NewReviewer(stub, GateOff, time.Minute)

	_, err := reviewer.Scan(t.Context(), "sha256:old")
	require.NoError(t, err)

	_, err = reviewer.Rescan(t.Context(), "sha256:old")
	require.NoError(t, err)
	assert.Equal(t, 2, stub.calls["sha256:old"])
	assert.Equal(t, "stub", reviewer.Name())
}

// slowScanner blocks until its context ends, and records how many scans ran at once.
type slowScanner struct {
	mu      sync.Mutex
	running int
	peak    int
	release chan struct{}
}

func (s *slowScanner) Name() string { return "slow" }

func (s *slowScanner) Scan(ctx context.Context, _ string) (*Result, error) {
	s.mu.Lock()
	s.running++
	s.peak = max(s.peak, s.running)
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.running--
		s.mu.Unlock()
	}()

	select {
	case <-s.release:
		return &Result{}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestReviewerTimeoutError(t *testing.T) {
	t.Parallel()

	reviewer := NewReviewer(&slowScanner{release: make(chan struct{})}, GateOff, 10*time.Millisecond)

	_, err := reviewer.Scan(t.Context(), "sha256:big")
	require.ErrorIs(t, err, ErrScanTimeout)
	assert.Contains(t, err.Error(), "--scan-timeout")
}

func TestReviewerRunsOneScanAtATime(t *testing.T) {
	t.Parallel()

	slow := &slowScanner{release: make(chan struct{})}
	reviewer := NewReviewer(slow, GateOff, time.Minute)

	var wg sync.WaitGroup

	for _, image := range []string{"sha256:a", "sha256:b", "sha256:c"} {
		wg.Go(func() {
			_, err := reviewer.Scan(t.Context(), image)
			assert.NoError(t, err)
		})
	}

	for range 3 {
		slow.release <- struct{}{}
	}

	wg.Wait()
	assert.Equal(t, 1, slow.peak)
}

func TestReviewerQueuedScanHonoursContext(t *testing.T) {
	t.Parallel()

	slow := &slowScanner{release: make(chan struct{})}
	reviewer := NewReviewer(slow, GateOff, time.Minute)

	started := make(chan struct{})

	go func() {
		close(started)
		_, _ = reviewer.Scan(t.Context(), "sha256:first")
	}()

	<-started
	require.Eventually(t, func() bool {
		slow.mu.Lock()
		defer slow.mu.Unlock()

		return slow.running == 1
	}, time.Second, time.Millisecond)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := reviewer.Scan(ctx, "sha256:second")
	require.ErrorIs(t, err, context.Canceled)
	require.NotErrorIs(t, err, ErrScanTimeout)

	slow.release <- struct{}{}
}
