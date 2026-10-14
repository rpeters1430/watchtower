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
