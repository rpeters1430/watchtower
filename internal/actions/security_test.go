package actions

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mockActions "github.com/nicholas-fedor/watchtower/internal/actions/mocks"
	"github.com/nicholas-fedor/watchtower/internal/logging"
	"github.com/nicholas-fedor/watchtower/pkg/scanner"
	"github.com/nicholas-fedor/watchtower/pkg/session"
	"github.com/nicholas-fedor/watchtower/pkg/types"
)

var errScanBroken = errors.New("scanner broken")

type fakeReviewer struct {
	mu      sync.Mutex
	reviews map[string]*scanner.Review
	errs    map[string]error
	calls   []string
}

func (f *fakeReviewer) ReviewUpdate(_ context.Context, current, latest string) (*scanner.Review, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.calls = append(f.calls, current+"->"+latest)

	err := f.errs[latest]
	if err != nil {
		return nil, err
	}

	return f.reviews[latest], nil
}

func securityFixture() (*scanner.Review, *scanner.Review) {
	fixed := []scanner.Finding{
		{ID: "CVE-2024-0001", Kind: scanner.KindVulnerability, Severity: scanner.SeverityCritical, Package: "libssl3"},
		{ID: "CVE-2024-0003", Kind: scanner.KindVulnerability, Severity: scanner.SeverityHigh, Package: "curl"},
	}
	introduced := []scanner.Finding{
		{ID: "CVE-2024-0004", Kind: scanner.KindVulnerability, Severity: scanner.SeverityCritical, Package: "libxml2"},
	}

	clean := &scanner.Review{
		Latest: &scanner.Result{},
		Diff:   scanner.Diff{Fixed: fixed},
		Gate:   scanner.GateCritical,
	}
	held := &scanner.Review{
		Latest: &scanner.Result{Findings: introduced},
		Diff:   scanner.Diff{Fixed: fixed, Introduced: introduced},
		Gate:   scanner.GateCritical,
		Hold:   true,
	}

	return clean, held
}

func staleContainer(
	t *testing.T,
	progress *session.Progress,
	id, name, image string,
	latest types.ImageID,
) types.Container {
	t.Helper()

	c := mockActions.CreateMockContainer(id, name, image, time.Now())
	c.SetStale(true)
	progress.AddScanned(logging.NopLogger(), c, latest, types.UpdateParams{})

	return c
}

func TestReviewSecurityHoldsGatedUpdates(t *testing.T) {
	t.Parallel()

	clean, held := securityFixture()
	reviewer := &fakeReviewer{
		reviews: map[string]*scanner.Review{"sha256:web-new": clean, "sha256:db-new": held},
		errs:    map[string]error{"sha256:cache-new": errScanBroken},
	}

	progress := &session.Progress{}
	web := staleContainer(t, progress, "web-id", "/web", "sha256:web-old", "sha256:web-new")
	db := staleContainer(t, progress, "db-id", "/db", "sha256:db-old", "sha256:db-new")
	cache := staleContainer(t, progress, "cache-id", "/cache", "sha256:cache-old", "sha256:cache-new")
	built := staleContainer(t, progress, "git-id", "/git", "sha256:git-old", "")

	fresh := mockActions.CreateMockContainer("fresh-id", "/fresh", "sha256:fresh", time.Now())

	// Scans log from several goroutines, so the buffer needs a synchronized writer.
	var buf bytes.Buffer

	log := zerolog.New(zerolog.SyncWriter(&buf))
	reviews := reviewSecurity(
		&log,
		t.Context(),
		[]types.Container{web, db, cache, built, fresh},
		progress,
		types.UpdateParams{SecurityReviewer: reviewer},
	)

	assert.ElementsMatch(t, []string{
		"sha256:web-old->sha256:web-new",
		"sha256:db-old->sha256:db-new",
		"sha256:cache-old->sha256:cache-new",
	}, reviewer.calls)

	require.Len(t, reviews, 2)

	// The clean update and the update whose scan failed both go ahead.
	assert.True(t, web.IsStale())
	assert.True(t, cache.IsStale())
	assert.True(t, built.IsStale())
	assert.Contains(t, buf.String(), "Could not scan the new image")

	// The gated update is held and reported as skipped with its findings.
	assert.False(t, db.IsStale())

	status := (*progress)[db.ID()]
	assert.Equal(t, session.SkippedStateString, status.State())
	assert.Contains(t, status.Error(), "CVE-2024-0004 (critical)")
	assert.Equal(t, session.ScannedStateString, (*progress)[web.ID()].State())
}

func TestReviewSecurityDisabled(t *testing.T) {
	t.Parallel()

	progress := &session.Progress{}
	c := staleContainer(t, progress, "web-id", "/web", "sha256:old", "sha256:new")

	reviews := reviewSecurity(logging.NopLogger(), t.Context(), []types.Container{c}, progress, types.UpdateParams{})
	assert.Nil(t, reviews)
	assert.True(t, c.IsStale())
}

func TestLogSecurityFixes(t *testing.T) {
	t.Parallel()

	clean, held := securityFixture()

	progress := &session.Progress{}
	web := staleContainer(t, progress, "web-id", "/web", "sha256:web-old", "sha256:web-new")
	db := staleContainer(t, progress, "db-id", "/db", "sha256:db-old", "sha256:db-new")
	progress.MarkForUpdate(logging.NopLogger(), web.ID())

	log, buf := logging.NewTestLogger(logging.InfoLevel)
	logSecurityFixes(log, progress, map[types.ContainerID]*scanner.Review{
		web.ID(): clean,
		// Not updated, so nothing is logged for it.
		db.ID(): held,
	})

	out := buf.String()
	assert.Contains(t, out, "Update changed known vulnerabilities")
	assert.Contains(t, out, "container=web")
	assert.Contains(t, out, "CVE-2024-0001 (critical), CVE-2024-0003 (high)")
	assert.NotContains(t, out, "CVE-2024-0004")
}

func TestFindingList(t *testing.T) {
	t.Parallel()

	findings := make([]scanner.Finding, maxListedFindings+3)
	for i := range findings {
		findings[i] = scanner.Finding{ID: "CVE", Severity: scanner.SeverityLow}
	}

	list := findingList(findings)
	assert.Contains(t, list, "CVE (low)")
	assert.Contains(t, list, "and 3 more")
	assert.Empty(t, findingList(nil))
}
