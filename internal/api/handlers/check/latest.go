package check

import (
	"fmt"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/rs/zerolog"

	"github.com/nicholas-fedor/watchtower/internal/metrics"
)

// LatestResponse is the response returned by GET /v1/check.
//
// Parameters/returns are documented by the handler's Swagger annotations.
type LatestResponse struct {
	// Containers holds the latest known status of each container.
	Containers []metrics.ContainerStatus `json:"containers"`
	// Count is the number of containers.
	Count int `json:"count"`
	// CheckedAt is when the most recent check or scan finished, or null before the first one.
	CheckedAt *time.Time `json:"checked_at"`
	// Timestamp is when the response was produced.
	Timestamp string `json:"timestamp"`
	// APIVersion is the API version of the response.
	APIVersion string `json:"api_version"`
}

// LatestHandler serves GET /v1/check.
type LatestHandler struct {
	log *zerolog.Logger

	// Path is the HTTP route path for the endpoint.
	Path string
	// statuses returns the latest known container statuses.
	statuses func() []metrics.ContainerStatus
}

// NewLatest creates a handler that reports the latest known check results.
//
// Parameters:
//   - log: Logger for request messages. Nil disables logging.
//   - statuses: Function returning the latest known container statuses.
//
// Returns:
//   - *LatestHandler: The handler.
func NewLatest(log *zerolog.Logger, statuses func() []metrics.ContainerStatus) *LatestHandler {
	if log == nil {
		nop := zerolog.Nop()
		log = &nop
	}

	return &LatestHandler{log: log, Path: "/v1/check", statuses: statuses}
}

// Handle responds with the latest known update status of each container,
// as recorded by the most recent check or scan that looked at it.
//
//	@Summary		Latest check results
//	@Description	Returns each container's status from the latest check or scan that looked at it, without contacting any registry.
//	@Tags			check
//	@Produce		json
//	@Success		200	{object}	LatestResponse	"Latest known container statuses"
//	@Failure		401	{string}	string			"Missing or invalid API token"
//	@Security		BearerAuth
//	@Router			/v1/check [get]
func (h *LatestHandler) Handle(c fiber.Ctx) error {
	h.log.Debug().
		Str("method", c.Method()).
		Str("path", c.Path()).
		Str("notify", "no").
		Msg("Received HTTP API latest check request")

	statuses := h.statuses()
	if statuses == nil {
		statuses = []metrics.ContainerStatus{}
	}

	var checkedAt *time.Time

	for _, status := range statuses {
		if checkedAt == nil || status.Timestamp.After(*checkedAt) {
			at := status.Timestamp
			checkedAt = &at
		}
	}

	err := c.Status(fiber.StatusOK).JSON(LatestResponse{
		Containers: statuses,
		Count:      len(statuses),
		CheckedAt:  checkedAt,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		APIVersion: "v1",
	})
	if err != nil {
		return fmt.Errorf("failed to send JSON response: %w", err)
	}

	return nil
}
