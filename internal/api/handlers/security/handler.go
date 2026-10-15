// Package security serves the /v1/security endpoints: each container's
// latest vulnerability scan, and on-demand scans of running images.
package security

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/rs/zerolog"

	"github.com/nicholas-fedor/watchtower/internal/security"
	"github.com/nicholas-fedor/watchtower/pkg/scanner"
)

// Path is the base path of the security endpoints.
const Path = "/v1/security"

// unavailableReason explains a missing scanner.
const unavailableReason = "Watchtower could not set up the image scanner. Its log says why."

// Response is the body of GET /v1/security.
type Response struct {
	// Available is false when no scanner could be set up.
	Available bool `json:"available"`
	// Reason says why scanning is unavailable.
	Reason string `json:"reason,omitempty"`
	// Scanner is the scanner backend, such as "trivy".
	Scanner string `json:"scanner,omitempty"`
	// ScannerImage is the image the scanner runs from.
	ScannerImage string `json:"scanner_image,omitempty"`
	// IgnoreUnfixed is true when findings without a published fix are left out.
	IgnoreUnfixed bool `json:"ignore_unfixed"`
	// ScanUpdates is true when the new image of each pending update is scanned.
	ScanUpdates bool `json:"scan_updates"`
	// Gate is the lowest severity of a new finding that holds an update.
	Gate scanner.Gate `json:"gate"`
	// Saved is true when results are kept across restarts.
	Saved bool `json:"saved"`
	// Job is the state of the latest on-demand scan.
	Job security.Job `json:"job"`
	// Containers holds each container's latest scan, without finding lists.
	Containers []security.Report `json:"containers"`
	// Timestamp is when the response was produced.
	Timestamp string `json:"timestamp"`
	// APIVersion is the API version of the response.
	APIVersion string `json:"api_version"`
}

// ScanRequest is the optional body of POST /v1/security/scan.
type ScanRequest struct {
	// Containers names the containers to scan. Empty scans every watched container.
	Containers []string `json:"containers"`
}

// ScanResponse is the body of POST /v1/security/scan.
type ScanResponse struct {
	// Job is the state of the scan that started.
	Job security.Job `json:"job"`
	// Timestamp is when the response was produced.
	Timestamp string `json:"timestamp"`
	// APIVersion is the API version of the response.
	APIVersion string `json:"api_version"`
}

// ReportResponse is the body of GET /v1/security/{name}.
type ReportResponse struct {
	// Container is the container's latest scan with every finding.
	Container security.Report `json:"container"`
	// Timestamp is when the response was produced.
	Timestamp string `json:"timestamp"`
	// APIVersion is the API version of the response.
	APIVersion string `json:"api_version"`
}

// Handler serves the security endpoints.
type Handler struct {
	log      *zerolog.Logger
	ctx      context.Context //nolint:containedctx // On-demand scans outlive the request that starts them.
	service  *security.Service
	listFunc func(ctx context.Context) ([]security.Target, error)

	Path string
}

// New creates a security handler.
//
// Parameters:
//   - log: Logger for requests. Nil disables logging.
//   - ctx: Process context; cancelling it stops on-demand scans.
//   - service: Scanner service, or nil when none could be set up.
//   - list: Lists the watched containers that a scan can cover.
//
// Returns:
//   - *Handler: Handler ready to register.
func New(
	log *zerolog.Logger,
	ctx context.Context,
	service *security.Service,
	list func(ctx context.Context) ([]security.Target, error),
) *Handler {
	if log == nil {
		nop := zerolog.Nop()
		log = &nop
	}

	return &Handler{
		log:      log,
		ctx:      ctx,
		service:  service,
		listFunc: list,
		Path:     Path,
	}
}

// Get responds with each container's latest scan.
//
//	@Summary		Image security overview
//	@Description	Returns the scanner setup and each container's latest vulnerability scan: counts by severity, how many findings have a fix, and how a waiting update changes them. Finding lists are
//
// left out; GET /v1/security/{name} has them.
//
//	@Tags			security
//	@Produce		json
//	@Success		200	{object}	Response	"Scanner state and per-container summaries"
//	@Failure		401	{string}	string		"Missing or invalid API token"
//	@Security		BearerAuth
//	@Router			/v1/security [get]
func (h *Handler) Get(c fiber.Ctx) error {
	h.log.Debug().
		Str("method", c.Method()).
		Str("path", c.Path()).
		Str("notify", "no").
		Msg("Received HTTP API security request")

	response := Response{
		Gate:       scanner.GateOff,
		Containers: []security.Report{},
		Timestamp:  now(),
		APIVersion: "v1",
	}

	if h.service == nil {
		response.Reason = unavailableReason

		return sendJSON(c, fiber.StatusOK, response)
	}

	response.Available = true
	response.Scanner = h.service.ScannerName()
	response.ScannerImage = h.service.ScannerImage()
	response.IgnoreUnfixed = h.service.IgnoreUnfixed()
	response.ScanUpdates = h.service.Enabled()
	response.Gate = h.service.Gate()
	response.Saved = h.service.Store().Persistent()
	response.Job = h.service.Job()
	response.Containers = h.service.Store().Summaries()

	return sendJSON(c, fiber.StatusOK, response)
}

// Report responds with one container's latest scan, including every finding.
//
//	@Summary		Container security report
//	@Description	Returns one container's latest vulnerability scan with each finding: its ID, severity, package, installed and fixed versions, and advisory link. When an update is waiting, also lists
//
// the findings it fixes and introduces.
//
//	@Tags			security
//	@Produce		json
//	@Param			name	path		string				true	"Container name"
//	@Success		200		{object}	ReportResponse		"The container's latest scan"
//	@Failure		401		{string}	string				"Missing or invalid API token"
//	@Failure		404		{object}	map[string]string	"The container has not been scanned"
//	@Security		BearerAuth
//	@Router			/v1/security/{name} [get]
func (h *Handler) Report(c fiber.Ctx) error {
	if h.service == nil {
		return sendError(c, fiber.StatusServiceUnavailable, unavailableReason)
	}

	name := c.Params("name")

	report, ok := h.service.Store().Get(name)
	if !ok {
		return sendError(c, fiber.StatusNotFound, name+" has not been scanned")
	}

	return sendJSON(c, fiber.StatusOK, ReportResponse{
		Container:  report,
		Timestamp:  now(),
		APIVersion: "v1",
	})
}

// Scan starts a scan of the named containers' running images, or of every
// watched container, against the latest vulnerability database.
//
//	@Summary		Scan running images
//	@Description	Starts scanning the running image of the named containers, or of every watched container when none are named. The scan runs in the background; GET /v1/security reports its progress
//
// and results. Only one scan runs at a time.
//
//	@Tags			security
//	@Accept			json
//	@Produce		json
//	@Param			request	body		ScanRequest			false	"Containers to scan"
//	@Success		202		{object}	ScanResponse		"The scan started"
//	@Failure		400		{object}	map[string]string	"The request body is not valid"
//	@Failure		401		{string}	string				"Missing or invalid API token"
//	@Failure		404		{object}	map[string]string	"No named container is watched"
//	@Failure		409		{object}	map[string]string	"A scan is already running"
//	@Failure		503		{object}	map[string]string	"No scanner is available"
//	@Security		BearerAuth
//	@Router			/v1/security/scan [post]
func (h *Handler) Scan(c fiber.Ctx) error {
	if h.service == nil {
		return sendError(c, fiber.StatusServiceUnavailable, unavailableReason)
	}

	var request ScanRequest

	if body := c.Body(); len(strings.TrimSpace(string(body))) > 0 {
		err := json.Unmarshal(body, &request)
		if err != nil {
			return sendError(c, fiber.StatusBadRequest, "request body must be a JSON object such as {\"containers\":[\"web\"]}")
		}
	}

	targets, err := h.listFunc(c.Context())
	if err != nil {
		h.log.Warn().Err(err).Str("notify", "no").Msg("Could not list containers for a security scan")

		return sendError(c, fiber.StatusInternalServerError, "could not list containers")
	}

	if len(request.Containers) > 0 {
		wanted := make([]string, 0, len(request.Containers))
		for _, name := range request.Containers {
			wanted = append(wanted, strings.TrimPrefix(name, "/"))
		}

		targets = slices.DeleteFunc(targets, func(target security.Target) bool {
			return !slices.Contains(wanted, strings.TrimPrefix(target.Name, "/"))
		})
	}

	job, err := h.service.Start(h.ctx, targets)

	switch {
	case errors.Is(err, security.ErrBusy):
		return sendError(c, fiber.StatusConflict, err.Error())
	case errors.Is(err, security.ErrNothingToScan):
		return sendError(c, fiber.StatusNotFound, "no watched container matches")
	case err != nil:
		return sendError(c, fiber.StatusInternalServerError, err.Error())
	}

	h.log.Info().
		Int("containers", job.Total).
		Str("ip", c.IP()).
		Str("notify", "no").
		Msg("Security scan started through the HTTP API")

	return sendJSON(c, fiber.StatusAccepted, ScanResponse{
		Job:        job,
		Timestamp:  now(),
		APIVersion: "v1",
	})
}

// now returns the current time as an RFC 3339 string.
func now() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// sendError writes a JSON error body with the given status.
func sendError(c fiber.Ctx, status int, message string) error {
	return sendJSON(c, status, fiber.Map{
		"error":       message,
		"api_version": "v1",
		"timestamp":   now(),
	})
}

// sendJSON writes body as a JSON response with the given status.
func sendJSON(c fiber.Ctx, status int, body any) error {
	err := c.Status(status).JSON(body)
	if err != nil {
		return fmt.Errorf("failed to send JSON response: %w", err)
	}

	return nil
}
