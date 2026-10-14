package activity

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdleTrackerReportsNothing(t *testing.T) {
	t.Parallel()

	tracker := New()

	// Outside a scan, steps and pulls are not recorded.
	tracker.SetStep("app", "example/app:latest", StepStopping)
	tracker.StartPull("example/app:latest").Observe("layer", "Downloading", 1, 2)

	snapshot := tracker.Snapshot()
	assert.False(t, snapshot.Running)
	assert.Empty(t, snapshot.StartedAt)
	assert.Empty(t, snapshot.Containers)
}

func TestScanRecordsStepsInOrder(t *testing.T) {
	t.Parallel()

	tracker := New()
	tracker.BeginScan()

	tracker.SetStep("/web", "example/web:latest", StepStopping)
	tracker.SetStep("db", "example/db:16", StepStopping)
	tracker.SetStep("web", "", StepStarting)

	snapshot := tracker.Snapshot()
	require.True(t, snapshot.Running)
	assert.NotEmpty(t, snapshot.StartedAt)
	require.Len(t, snapshot.Containers, 2)
	assert.Equal(t, "web", snapshot.Containers[0].Name)
	assert.Equal(t, "example/web:latest", snapshot.Containers[0].Image)
	assert.Equal(t, StepStarting, snapshot.Containers[0].Step)
	assert.Equal(t, "db", snapshot.Containers[1].Name)

	tracker.SetStep("web", "", StepUpdated)
	tracker.EndScan()

	snapshot = tracker.Snapshot()
	assert.False(t, snapshot.Running)
	assert.Empty(t, snapshot.Containers)

	// The outcome stays available after the scan, for clients that poll.
	require.NotNil(t, snapshot.LastScan)
	assert.NotEmpty(t, snapshot.LastScan.FinishedAt)
	require.Len(t, snapshot.LastScan.Containers, 2)
	assert.Equal(t, StepUpdated, snapshot.LastScan.Containers[0].Step)

	tracker.BeginScan()
	assert.Nil(t, tracker.Snapshot().LastScan, "a running scan does not report the previous one")
}

func TestPullProgressFollowsDockerStream(t *testing.T) {
	t.Parallel()

	const image = "ghcr.io/example/app:latest"

	tracker := New()
	tracker.BeginScan()
	tracker.SetStep("app", image, StepPulling)

	pull := tracker.StartPull(image)
	assert.Equal(t, PhaseStarting, pullOf(t, tracker).Phase)

	// Messages as the Docker 29 containerd image store sends them: a layer can
	// start with Downloading, and extraction reports seconds, not bytes.
	pull.Observe("3.12-slim", "Pulling from library/python", 0, 0)
	pull.Observe("aaa", "Pulling fs layer", 0, 0)
	pull.Observe("bbb", "Downloading", 400, 1000)
	pull.Observe("aaa", "Downloading", 100, 200)

	progress := pullOf(t, tracker)
	assert.Equal(t, PhaseDownloading, progress.Phase)
	assert.Equal(t, 2, progress.Layers)
	assert.Equal(t, int64(500), progress.DownloadedBytes)
	assert.Equal(t, int64(1200), progress.TotalBytes)

	pull.Observe("aaa", "Download complete", 0, 0)
	pull.Observe("bbb", "Download complete", 0, 0)
	pull.Observe("bbb", "Extracting", 1, 0)
	pull.Observe("aaa", "Pull complete", 0, 0)

	progress = pullOf(t, tracker)
	assert.Equal(t, PhaseExtracting, progress.Phase)
	assert.Equal(t, int64(1200), progress.DownloadedBytes)
	assert.Equal(t, 2, progress.LayersDownloaded)
	assert.Equal(t, 1, progress.LayersDone)

	// A late Downloading message must not move a finished layer backwards.
	pull.Observe("aaa", "Downloading", 10, 200)
	pull.Observe("bbb", "Pull complete", 0, 0)

	progress = pullOf(t, tracker)
	assert.Equal(t, PhaseFinishing, progress.Phase)
	assert.Equal(t, 2, progress.LayersDone)

	pull.Finish(nil)
	assert.Equal(t, PhaseDone, pullOf(t, tracker).Phase)
}

func TestPullFailureAndAlreadyExists(t *testing.T) {
	t.Parallel()

	pull := New().StartPull("example/app:latest")
	pull.Observe("aaa", "Already exists", 0, 0)
	pull.Observe("bbb", "Waiting", 0, 0)

	summary := pull.Summary()
	assert.Equal(t, PhaseDownloading, summary.Phase)
	assert.Equal(t, 1, summary.LayersDone)

	pull.Finish(errors.New("unauthorized"))
	assert.Equal(t, PhaseFailed, pull.Summary().Phase)
}

func TestOverlappingScansEndTogether(t *testing.T) {
	t.Parallel()

	tracker := New()
	tracker.BeginScan()
	tracker.BeginScan()
	tracker.SetStep("app", "example/app", StepUpdated)

	tracker.EndScan()
	assert.True(t, tracker.Snapshot().Running)
	assert.Len(t, tracker.Snapshot().Containers, 1)

	tracker.EndScan()
	tracker.EndScan()
	assert.False(t, tracker.Snapshot().Running)
}

func pullOf(t *testing.T, tracker *Tracker) Pull {
	t.Helper()

	snapshot := tracker.Snapshot()
	require.Len(t, snapshot.Containers, 1)
	require.NotNil(t, snapshot.Containers[0].Pull)

	return *snapshot.Containers[0].Pull
}
