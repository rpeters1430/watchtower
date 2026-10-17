package images

import (
	"context"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/rs/zerolog"

	"github.com/nicholas-fedor/watchtower/pkg/types"
)

// PruneTimeout bounds one prune request. Removing many images can take a
// while on slow storage, longer than other read endpoints are given.
const PruneTimeout = 5 * time.Minute

// ImageStore is the part of the Docker client the usage and prune endpoints use.
type ImageStore interface {
	GetImageDiskUsage(ctx context.Context) (types.ImageDiskUsage, error)
	PruneImages(ctx context.Context, all bool) (types.ImagePruneReport, error)
}

// UsageResponse is the body of GET /v1/images/usage.
type UsageResponse struct {
	// TotalSize is the number of bytes all images use.
	TotalSize int64 `json:"total_size"`
	// Reclaimable is the number of bytes removing unused images would free.
	Reclaimable int64 `json:"reclaimable"`
	// TotalCount is the number of images on the host.
	TotalCount int64 `json:"total_count"`
	// ActiveCount is the number of images at least one container uses.
	ActiveCount int64 `json:"active_count"`
	// Timestamp is when the response was produced.
	Timestamp string `json:"timestamp"`
	// APIVersion is the API version of the response.
	APIVersion string `json:"api_version"`
}

// PruneResponse is the body of POST /v1/images/prune.
type PruneResponse struct {
	// All is true when every unused image was removed, not only dangling ones.
	All bool `json:"all"`
	// ImagesDeleted is the number of images deleted.
	ImagesDeleted int `json:"images_deleted"`
	// Untagged lists the image references that were untagged.
	Untagged []string `json:"untagged"`
	// SpaceReclaimed is the number of bytes freed.
	SpaceReclaimed int64 `json:"space_reclaimed"`
	// Timestamp is when the response was produced.
	Timestamp string `json:"timestamp"`
	// APIVersion is the API version of the response.
	APIVersion string `json:"api_version"`
}

// PruneHandler serves GET /v1/images/usage and POST /v1/images/prune.
type PruneHandler struct {
	log        *zerolog.Logger
	store      ImageStore
	updateLock chan bool

	UsagePath string
	PrunePath string
}

// NewPruneHandler creates the usage and prune handler.
//
// Parameters:
//   - log: Logger for requests. Nil disables logging.
//   - store: Docker client.
//   - updateLock: Lock shared with update scans, so a prune never removes an
//     image an update has pulled but not started yet. Nil means no lock.
//
// Returns:
//   - *PruneHandler: Handler ready to register.
func NewPruneHandler(log *zerolog.Logger, store ImageStore, updateLock chan bool) *PruneHandler {
	if log == nil {
		nop := zerolog.Nop()
		log = &nop
	}

	return &PruneHandler{
		log:        log,
		store:      store,
		updateLock: updateLock,
		UsagePath:  "/v1/images/usage",
		PrunePath:  "/v1/images/prune",
	}
}

// Usage responds with how much space images use and how much is reclaimable.
//
//	@Summary		Image disk usage
//	@Description	Returns how much disk space Docker images use on the host and how much removing unused images would free.
//	@Tags			images
//	@Produce		json
//	@Success		200	{object}	UsageResponse	"Image disk usage"
//	@Failure		500	{string}	string			"Failed to read image disk usage"
//	@Failure		401	{string}	string			"Missing or invalid API token"
//	@Security		BearerAuth
//	@Router			/v1/images/usage [get]
func (h *PruneHandler) Usage(c fiber.Ctx) error {
	usage, err := h.store.GetImageDiskUsage(c.Context())
	if err != nil {
		h.log.Error().Err(err).Str("notify", "no").Msg("Failed to read image disk usage for API")

		return sendText(c, fiber.StatusInternalServerError, "failed to read image disk usage")
	}

	return sendJSON(c, fiber.StatusOK, UsageResponse{
		TotalSize:   usage.TotalSize,
		Reclaimable: usage.Reclaimable,
		TotalCount:  usage.TotalCount,
		ActiveCount: usage.ActiveCount,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		APIVersion:  "v1",
	})
}

// Prune removes images no container uses.
//
//	@Summary		Remove unused images
//	@Description	Removes images that no container uses, like docker image prune. By default only dangling (untagged) images are removed; all=true removes every unused image, including scanner images,
//
// which are downloaded again when next needed. Refused while an update is running.
//
//	@Tags			images
//	@Produce		json
//	@Param			all	query		bool			false	"Remove every unused image, not only dangling ones"
//	@Success		200	{object}	PruneResponse	"What was removed"
//	@Failure		400	{string}	string			"Invalid all value"
//	@Failure		409	{string}	string			"An update is running"
//	@Failure		500	{string}	string			"Failed to remove images"
//	@Failure		401	{string}	string			"Missing or invalid API token"
//	@Security		BearerAuth
//	@Router			/v1/images/prune [post]
func (h *PruneHandler) Prune(c fiber.Ctx) error {
	all := false

	if value := c.Query("all"); value != "" {
		switch value {
		case "true", "1":
			all = true
		case "false", "0":
		default:
			return sendText(c, fiber.StatusBadRequest, "all must be true or false")
		}
	}

	if h.updateLock != nil {
		select {
		case token := <-h.updateLock:
			defer func() { h.updateLock <- token }()
		default:
			return sendText(c, fiber.StatusConflict, "an update is running; try again when it has finished")
		}
	}

	ctx, cancel := context.WithTimeout(c.Context(), PruneTimeout)
	defer cancel()

	report, err := h.store.PruneImages(ctx, all)
	if err != nil {
		h.log.Error().Err(err).Bool("all", all).Str("notify", "no").Msg("Failed to remove unused images for API")

		return sendText(c, fiber.StatusInternalServerError, "failed to remove unused images")
	}

	untagged := report.Untagged
	if untagged == nil {
		untagged = []string{}
	}

	return sendJSON(c, fiber.StatusOK, PruneResponse{
		All:            all,
		ImagesDeleted:  report.ImagesDeleted,
		Untagged:       untagged,
		SpaceReclaimed: report.SpaceReclaimed,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		APIVersion:     "v1",
	})
}

// sendJSON writes body as JSON with status.
func sendJSON(c fiber.Ctx, status int, body any) error {
	err := c.Status(status).JSON(body)
	if err != nil {
		return fmt.Errorf("failed to send JSON response: %w", err)
	}

	return nil
}

// sendText writes a plain-text error with status.
func sendText(c fiber.Ctx, status int, message string) error {
	err := c.Status(status).SendString(message)
	if err != nil {
		return fmt.Errorf("failed to send error response: %w", err)
	}

	return nil
}
