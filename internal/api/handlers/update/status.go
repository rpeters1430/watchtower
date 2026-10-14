package update

import (
	"fmt"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/nicholas-fedor/watchtower/internal/activity"
)

// StatusPath is the route of the update status endpoint.
const StatusPath = "/v1/update/status"

// StatusResponse is the body of the update status endpoint.
type StatusResponse struct {
	// Running is true while an update scan is in progress, scheduled or requested.
	Running bool `json:"running"`
	// StartedAt is when the running scan began, in RFC 3339. Omitted when idle.
	StartedAt string `json:"started_at,omitempty"`
	// Containers lists what the scan is doing to each container it has started on.
	Containers []activity.Container `json:"containers"`
	// LastScan is how the most recent scan ended. Omitted while a scan runs.
	LastScan *activity.FinishedScan `json:"last_scan,omitempty"`
	// Timestamp is when the response was produced.
	Timestamp string `json:"timestamp"`
	// APIVersion is the API version of the response.
	APIVersion string `json:"api_version"`
}

// Status returns a handler that reports what the running update scan is doing.
//
// Parameters:
//   - snapshot: Returns the current activity, usually activity.Default().Snapshot.
//
// Returns:
//   - fiber.Handler: Handler for GET /v1/update/status.
func Status(snapshot func() activity.Snapshot) fiber.Handler {
	return func(c fiber.Ctx) error {
		return status(c, snapshot)
	}
}

// status writes the activity snapshot.
//
//	@Summary		Get update progress
//	@Description	Reports whether an update scan is running and, for each container in progress, the step (pulling, stopping, starting, updated, failed) and download progress. Cheap to poll.
//	@Tags			update
//	@Produce		json
//	@Success		200	{object}	StatusResponse	"Current update activity"
//	@Failure		401	{string}	string			"Missing or invalid API token"
//	@Security		BearerAuth
//	@Router			/v1/update/status [get]
func status(c fiber.Ctx, snapshot func() activity.Snapshot) error {
	current := snapshot()

	err := c.Status(fiber.StatusOK).JSON(StatusResponse{
		Running:    current.Running,
		StartedAt:  current.StartedAt,
		Containers: current.Containers,
		LastScan:   current.LastScan,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		APIVersion: "v1",
	})
	if err != nil {
		return fmt.Errorf("failed to send JSON response: %w", err)
	}

	return nil
}
