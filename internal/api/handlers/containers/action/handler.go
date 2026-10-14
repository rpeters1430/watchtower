package action

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/rs/zerolog"
)

// Request defines the payload for container lifecycle actions.
type Request struct {
	// Action specifies the operation: "start", "stop", "restart", or "set_tag".
	Action string `json:"action"`
	// Tag specifies the new image tag or full reference when Action is "set_tag".
	Tag string `json:"tag,omitempty"`
	// Image is an alias for Tag.
	Image string `json:"image,omitempty"`
}

// Response defines the JSON response returned by the container action handler.
type Response struct {
	Status    string `json:"status"`
	Container string `json:"container"`
	Action    string `json:"action"`
	Message   string `json:"message,omitempty"`
}

// Handler handles POST /v1/containers/:name/action.
type Handler struct {
	log      *zerolog.Logger
	executor Executor
	Path     string
}

// New creates a new container Action Handler.
func New(log *zerolog.Logger, executor Executor) *Handler {
	if log == nil {
		nop := zerolog.Nop()
		log = &nop
	}

	return &Handler{
		log:      log,
		executor: executor,
		Path:     "/v1/containers/:name/action",
	}
}

// Handle processes container lifecycle actions.
//
//	@Summary		Perform container lifecycle action
//	@Description	Performs start, stop, restart, or image tag change (set_tag) on a container.
//	@Tags			containers
//	@Accept			json
//	@Produce		json
//	@Param			name	path		string		true	"Container name"
//	@Param			request	body		Request		true	"Action request payload"
//	@Success		200		{object}	Response	"Action executed successfully"
//	@Failure		400		{string}	string		"Invalid request or action"
//	@Failure		404		{string}	string		"Container not found"
//	@Failure		500		{string}	string		"Failed to execute action"
//	@Security		BearerAuth
//	@Router			/v1/containers/{name}/action [post]
func (h *Handler) Handle(c fiber.Ctx) error {
	name := c.Params("name")
	if name == "" {
		return c.Status(fiber.StatusBadRequest).SendString("container name is required")
	}

	var req Request
	if err := json.Unmarshal(c.Body(), &req); err != nil {
		h.log.Debug().
			Err(err).
			Str("container", name).
			Msg("Failed to decode container action request")

		return c.Status(fiber.StatusBadRequest).SendString("invalid request body")
	}

	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action == "" {
		return c.Status(fiber.StatusBadRequest).SendString("action is required")
	}

	targetTag := req.Tag
	if targetTag == "" {
		targetTag = req.Image
	}

	if action == ActionSetTag && strings.TrimSpace(targetTag) == "" {
		return c.Status(fiber.StatusBadRequest).SendString("tag or image is required for set_tag action")
	}

	err := h.executor.Execute(c.Context(), name, action, targetTag)
	if err != nil {
		h.log.Error().
			Err(err).
			Str("container", name).
			Str("action", action).
			Msg("Container action execution failed")

		switch {
		case errors.Is(err, ErrContainerNotFound):
			return c.Status(fiber.StatusNotFound).SendString(err.Error())
		case errors.Is(err, ErrUnsupportedAction), errors.Is(err, ErrInvalidTag), errors.Is(err, ErrWatchtowerContainer):
			return c.Status(fiber.StatusBadRequest).SendString(err.Error())
		default:
			return c.Status(fiber.StatusInternalServerError).SendString(fmt.Sprintf("action failed: %v", err))
		}
	}

	return c.Status(fiber.StatusOK).JSON(Response{
		Status:    "success",
		Container: name,
		Action:    action,
		Message:   fmt.Sprintf("Action %s executed successfully on %s", action, name),
	})
}
