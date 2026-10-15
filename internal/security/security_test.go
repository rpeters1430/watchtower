package security

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/watchtower/pkg/scanner"
)

var errScan = errors.New("scanner exited with status 1")

type stubScanner struct {
	mu      sync.Mutex
	results map[string]*scanner.Result
	calls   map[string]int
	release chan struct{}
}

func (s *stubScanner) Name() string { return "stub" }

func (s *stubScanner) ReviewUpdate(_ context.Context, current, latest string) (*scanner.Review, error) {
	diff := scanner.Compare(s.results[current], s.results[latest])

	return &scanner.Review{
		Current: s.results[current],
		Latest:  s.results[latest],
		Diff:    diff,
		Gate:    scanner.GateOff,
	}, nil
}

func (s *stubScanner) Rescan(ctx context.Context, image string) (*scanner.Result, error) {
	scanner.ReportProgress(ctx, "Reading "+image)

	if s.release != nil {
		<-s.release
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.calls == nil {
		s.calls = map[string]int{}
	}

	s.calls[image]++

	result, ok := s.results[image]
	if !ok {
		return nil, errScan
	}

	return result, nil
}

var (
	critical = scanner.Finding{
		ID: "CVE-1", Kind: scanner.KindVulnerability, Severity: scanner.SeverityCritical,
		Package: "openssl", InstalledVersion: "3.0.1", FixedVersion: "3.0.2",
	}
	high = scanner.Finding{
		ID: "CVE-2", Kind: scanner.KindVulnerability, Severity: scanner.SeverityHigh, Package: "zlib",
	}
	medium = scanner.Finding{
		ID: "CVE-3", Kind: scanner.KindVulnerability, Severity: scanner.SeverityMedium,
		Package: "curl", FixedVersion: "8.1",
	}
)

func newStub() *stubScanner {
	return &stubScanner{results: map[string]*scanner.Result{
		"sha256:old": {Scanner: "stub", Image: "sha256:old", Findings: []scanner.Finding{critical, high}},
		"sha256:new": {Scanner: "stub", Image: "sha256:new", Findings: []scanner.Finding{high, medium}},
	}}
}

func waitForJob(t *testing.T, service *Service) Job {
	t.Helper()

	var job Job

	require.Eventually(t, func() bool {
		job = service.Job()

		return !job.Running
	}, 5*time.Second, 5*time.Millisecond)

	return job
}

func TestServiceAppliesRuntimeGate(t *testing.T) {
	t.Parallel()

	gate := scanner.GateOff
	service := NewService(nil, newStub(), OpenStore(nil, ""), Options{
		Gate: func() scanner.Gate { return gate },
	})

	review, err := service.ReviewUpdate(t.Context(), "sha256:old", "sha256:new")
	require.NoError(t, err)
	assert.False(t, review.Hold)

	gate = scanner.GateMedium
	review, err = service.ReviewUpdate(t.Context(), "sha256:old", "sha256:new")
	require.NoError(t, err)
	assert.True(t, review.Hold, "the update adds a medium finding")
	assert.Equal(t, scanner.GateMedium, review.Gate)

	assert.False(t, service.Enabled())
	assert.Equal(t, "stub", service.ScannerName())
}

func TestRecordReview(t *testing.T) {
	t.Parallel()

	stub := newStub()
	service := NewService(nil, stub, OpenStore(nil, ""), Options{})

	review, err := service.ReviewUpdate(t.Context(), "sha256:old", "sha256:new")
	require.NoError(t, err)

	// A waiting update: the report is the running image, with the update's comparison.
	service.RecordReview("/web", "nginx", "sha256:old", "sha256:new", review, false)

	report, ok := service.Store().Get("web")
	require.True(t, ok)
	assert.Equal(t, "sha256:old", report.ImageID)
	assert.Equal(t, 1, report.Counts.Critical)
	assert.Equal(t, 1, report.Fixable)
	require.NotNil(t, report.Update)
	assert.Equal(t, 1, report.Update.FixedCounts.Critical)
	assert.Equal(t, 1, report.Update.IntroducedCounts.Medium)
	assert.Equal(t, "CVE-1", report.Update.Fixed[0].ID)

	// Summaries leave out the finding lists but keep the counts.
	summary := service.Store().Summaries()[0]
	assert.Nil(t, summary.Findings)
	assert.Nil(t, summary.Update.Fixed)
	assert.Equal(t, 1, summary.Update.FixedCounts.Critical)

	// After the update the container runs the new image, with no update waiting,
	// and records what the update fixed.
	service.now = func() time.Time { return time.Now().Add(time.Minute) }
	service.RecordReview("web", "nginx", "sha256:old", "sha256:new", review, true)

	report, _ = service.Store().Get("web")
	assert.Equal(t, "sha256:new", report.ImageID)
	assert.Nil(t, report.Update)
	assert.Equal(t, 0, report.Counts.Critical)
	require.NotNil(t, report.LastUpdate)
	assert.Equal(t, "sha256:old", report.LastUpdate.PreviousImageID)
	assert.Equal(t, 1, report.LastUpdate.FixedCounts.Critical)
	assert.Equal(t, "CVE-1", report.LastUpdate.Fixed[0].ID)

	summary = service.Store().Summaries()[0]
	assert.Nil(t, summary.LastUpdate.Fixed)
	assert.Equal(t, 1, summary.LastUpdate.FixedCounts.Critical)
}

func TestStartScansEachImageOnce(t *testing.T) {
	t.Parallel()

	stub := newStub()
	service := NewService(nil, stub, OpenStore(nil, ""), Options{})

	job, err := service.Start(t.Context(), []Target{
		{Name: "/web", Image: "nginx", ImageID: "sha256:old"},
		{Name: "web-2", Image: "nginx", ImageID: "sha256:old"},
		{Name: "broken", Image: "gone", ImageID: "sha256:missing"},
		{Name: "built", Image: "local"},
	})
	require.NoError(t, err)
	assert.Equal(t, 3, job.Total)

	job = waitForJob(t, service)
	assert.Equal(t, 3, job.Done)
	assert.Equal(t, 1, job.Failed)
	assert.NotNil(t, job.FinishedAt)
	assert.Equal(t, 1, stub.calls["sha256:old"])

	web, ok := service.Store().Get("web")
	require.True(t, ok)
	assert.Equal(t, 2, web.Counts.Total())

	broken, _ := service.Store().Get("broken")
	assert.Contains(t, broken.Error, "status 1")
}

func TestStartKeepsWaitingUpdate(t *testing.T) {
	t.Parallel()

	stub := newStub()
	service := NewService(nil, stub, OpenStore(nil, ""), Options{})

	review, err := service.ReviewUpdate(t.Context(), "sha256:old", "sha256:new")
	require.NoError(t, err)
	service.RecordReview("web", "nginx", "sha256:old", "sha256:new", review, false)

	service.now = func() time.Time { return time.Now().Add(time.Minute) }
	_, err = service.Start(t.Context(), []Target{{Name: "web", Image: "nginx", ImageID: "sha256:old"}})
	require.NoError(t, err)
	waitForJob(t, service)

	report, _ := service.Store().Get("web")
	require.NotNil(t, report.Update, "the same image still has the same update waiting")
	assert.Equal(t, "sha256:new", report.Update.LatestImageID)

	// Now apply update and run an on-demand scan; verify LastUpdate is kept.
	service.RecordReview("web", "nginx", "sha256:old", "sha256:new", review, true)
	service.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	_, err = service.Start(t.Context(), []Target{{Name: "web", Image: "nginx", ImageID: "sha256:new"}})
	require.NoError(t, err)
	waitForJob(t, service)

	report, _ = service.Store().Get("web")
	require.NotNil(t, report.LastUpdate, "the last update info is kept across on-demand scans")
	assert.Equal(t, "sha256:old", report.LastUpdate.PreviousImageID)
}

func TestStartRejectsOverlapAndEmpty(t *testing.T) {
	t.Parallel()

	stub := newStub()
	stub.release = make(chan struct{})
	service := NewService(nil, stub, OpenStore(nil, ""), Options{})

	_, err := service.Start(t.Context(), nil)
	require.ErrorIs(t, err, ErrNothingToScan)

	_, err = service.Start(t.Context(), []Target{{Name: "web", ImageID: "sha256:old"}})
	require.NoError(t, err)

	_, err = service.Start(t.Context(), []Target{{Name: "web", ImageID: "sha256:old"}})
	require.ErrorIs(t, err, ErrBusy)

	close(stub.release)
	waitForJob(t, service)
}

func TestStorePersists(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := OpenStore(nil, dir)
	require.True(t, store.Persistent())

	when := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	store.Record(Report{Name: "web", ImageID: "sha256:old", ScannedAt: when, Counts: scanner.Counts{High: 2}})
	// An older report never replaces a newer one.
	store.Record(Report{Name: "web", ImageID: "sha256:older", ScannedAt: when.Add(-time.Hour)})

	assert.FileExists(t, filepath.Join(dir, FileName))

	reopened := OpenStore(nil, dir)
	report, ok := reopened.Get("web")
	require.True(t, ok)
	assert.Equal(t, "sha256:old", report.ImageID)
	assert.Equal(t, 2, report.Counts.High)

	// Reports of containers not scanned for a long time drop out.
	reopened.Record(Report{Name: "db", ScannedAt: when.Add(retention + time.Hour)})
	_, ok = reopened.Get("web")
	assert.False(t, ok)
}

func TestNewReportCapsFindings(t *testing.T) {
	t.Parallel()

	findings := make([]scanner.Finding, maxFindings+5)
	report := newReport("web", "nginx", "sha256:x", &scanner.Result{Findings: findings}, nil, time.Now())

	assert.Len(t, report.Findings, maxFindings)
	assert.True(t, report.Truncated)
	assert.Equal(t, maxFindings+5, report.Counts.Total())
}

func TestStartRecordsActivity(t *testing.T) {
	t.Parallel()

	service := NewService(nil, newStub(), OpenStore(nil, ""), Options{})

	_, err := service.Start(t.Context(), []Target{
		{Name: "web", Image: "nginx", ImageID: "sha256:old"},
		{Name: "broken", Image: "gone", ImageID: "sha256:missing"},
	})
	require.NoError(t, err)

	job := waitForJob(t, service)
	assert.Empty(t, job.Step, "a finished job has no current step")

	messages := make([]string, 0, len(job.Activity))
	problems := 0

	for _, entry := range job.Activity {
		messages = append(messages, entry.Message)

		if entry.Problem {
			problems++
			assert.Equal(t, []string{"broken"}, entry.Containers)
		}
	}

	assert.Equal(t, "Started scanning 2 containers", messages[0])
	assert.Contains(t, messages, "Scanning web")
	assert.Contains(t, messages, "Reading sha256:old", "steps the scanner reports are kept")
	assert.Contains(t, messages, "Finished web in 0s: 2 findings (1 critical, 1 high)")
	assert.Equal(t, 1, problems)
}

func TestStepDropsRepeatsAndCaps(t *testing.T) {
	t.Parallel()

	service := NewService(nil, newStub(), OpenStore(nil, ""), Options{})

	service.mu.Lock()
	service.step(nil, "Downloading", false)
	service.step(nil, "Downloading", false)
	assert.Len(t, service.job.Activity, 1)

	for i := range maxActivity + 5 {
		service.step(nil, strconv.Itoa(i), false)
	}
	service.mu.Unlock()

	job := service.Job()
	assert.Len(t, job.Activity, maxActivity)
	assert.Equal(t, strconv.Itoa(maxActivity+4), job.Step)
}

func TestEstimateUsesPreviousAndAverageDurations(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	service := NewService(nil, newStub(), OpenStore(nil, ""), Options{})
	service.now = func() time.Time { return now }

	started := now.Add(-30 * time.Second)

	service.mu.Lock()
	defer service.mu.Unlock()

	service.job = Job{Running: true, CurrentStartedAt: &started}
	service.plan = plan{
		current:  "sha256:a",
		queue:    []string{"sha256:b", "sha256:c"},
		previous: map[string]time.Duration{"sha256:a": time.Minute, "sha256:b": 2 * time.Minute},
	}

	// a: 1m - 30s elapsed, b: 2m from its last scan, c: average of earlier scans (1m30s).
	finish := service.estimate()
	require.NotNil(t, finish)
	assert.Equal(t, now.Add(30*time.Second+2*time.Minute+90*time.Second), *finish)

	// This job's own scans win over earlier ones for unknown images.
	service.plan.taken = []time.Duration{10 * time.Second}
	assert.Equal(t, now.Add(30*time.Second+2*time.Minute+10*time.Second), *service.estimate())

	// An overrunning scan still leaves a little time.
	late := now.Add(-5 * time.Minute)
	service.job.CurrentStartedAt = &late
	assert.Equal(t, now.Add(minRemaining+2*time.Minute+10*time.Second), *service.estimate())

	// Nothing to go on: no estimate.
	service.plan = plan{queue: []string{"sha256:z"}}
	service.job.CurrentStartedAt = nil
	assert.Nil(t, service.estimate())
}
