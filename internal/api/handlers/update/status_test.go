package update

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/watchtower/internal/activity"
)

func TestStatusReportsActivity(t *testing.T) {
	t.Parallel()

	tracker := activity.New()
	app := fiber.New()
	app.Get(StatusPath, Status(tracker.Snapshot))

	idle := getStatus(t, app)
	assert.False(t, idle.Running)
	assert.Empty(t, idle.StartedAt)
	assert.NotNil(t, idle.Containers, "containers is an empty list, not null, when idle")
	assert.Equal(t, "v1", idle.APIVersion)

	tracker.BeginScan()
	tracker.SetStep("app", "example/app:latest", activity.StepPulling)
	tracker.StartPull("example/app:latest").Observe("layer", "Downloading", 25, 100)

	busy := getStatus(t, app)
	require.True(t, busy.Running)
	assert.NotEmpty(t, busy.StartedAt)
	require.Len(t, busy.Containers, 1)
	assert.Equal(t, activity.StepPulling, busy.Containers[0].Step)
	require.NotNil(t, busy.Containers[0].Pull)
	assert.Equal(t, activity.PhaseDownloading, busy.Containers[0].Pull.Phase)
	assert.Equal(t, int64(25), busy.Containers[0].Pull.DownloadedBytes)
}

func getStatus(t *testing.T, app *fiber.App) StatusResponse {
	t.Helper()

	resp, err := app.Test(httptest.NewRequestWithContext(t.Context(), http.MethodGet, StatusPath, nil))
	require.NoError(t, err)

	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Decode loosely first so a null list is caught rather than hidden.
	var raw map[string]any
	require.NoError(t, json.Unmarshal(body, &raw))
	require.NotNil(t, raw["containers"])

	var status StatusResponse
	require.NoError(t, json.Unmarshal(body, &status))

	return status
}
