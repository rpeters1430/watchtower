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
	// Action specifies the operation: "start", "stop", "restart", "set_tag", or "upgrade_version".
	Action string `json:"action"`
	// Tag specifies the new image tag or full reference when Action is "set_tag" or "upgrade_version".
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
		return sendText(c, fiber.StatusBadRequest, "container name is required")
	}

	var req Request

	err := json.Unmarshal(c.Body(), &req)
	if err != nil {
		h.log.Debug().
			Err(err).
			Str("container", name).
			Msg("Failed to decode container action request")

		return sendText(c, fiber.StatusBadRequest, "invalid request body")
	}

	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action == "" {
		return sendText(c, fiber.StatusBadRequest, "action is required")
	}

	targetTag := req.Tag
	if targetTag == "" {
		targetTag = req.Image
	}

	if action == ActionSetTag && strings.TrimSpace(targetTag) == "" {
		return sendText(c, fiber.StatusBadRequest, "tag or image is required for set_tag action")
	}

	err = h.executor.Execute(c.Context(), name, action, targetTag)
	if err != nil {
		h.log.Error().
			Err(err).
			Str("container", name).
			Str("action", action).
			Msg("Container action execution failed")

		switch {
		case errors.Is(err, ErrContainerNotFound):
			return sendText(c, fiber.StatusNotFound, err.Error())
		case errors.Is(err, ErrUnsupportedAction), errors.Is(err, ErrInvalidTag), errors.Is(err, ErrWatchtowerContainer):
			return sendText(c, fiber.StatusBadRequest, err.Error())
		default:
			return sendText(c, fiber.StatusInternalServerError, fmt.Sprintf("action failed: %v", err))
		}
	}

	err = c.Status(fiber.StatusOK).JSON(Response{
		Status:    "success",
		Container: name,
		Action:    action,
		Message:   fmt.Sprintf("Action %s executed successfully on %s", action, name),
	})
	if err != nil {
		return fmt.Errorf("failed to send JSON response: %w", err)
	}

	return nil
}

// sendText writes a plain-text response with the given status.
func sendText(c fiber.Ctx, status int, body string) error {
	err := c.Status(status).SendString(body)
	if err != nil {
		return fmt.Errorf("failed to send response: %w", err)
	}

	return nil
}
