package settings

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/rs/zerolog"

	runtime "github.com/nicholas-fedor/watchtower/internal/settings"
	"github.com/nicholas-fedor/watchtower/pkg/types"
)

const (
	// SourceConfig marks a notification service set by flags or environment variables.
	SourceConfig = "config"
	// SourceSettings marks a notification service added at run time.
	SourceSettings = "settings"
)

// NotificationStore holds the notification services added at run time.
type NotificationStore interface {
	// NotificationServices returns the services added at run time.
	NotificationServices() []runtime.NotificationService
	// AddNotificationService saves and applies a new service.
	AddNotificationService(name, rawURL string) (runtime.NotificationService, error)
	// RemoveNotificationService deletes a saved service by ID.
	RemoveNotificationService(id string) error
	// Persistent reports whether changes survive a restart.
	Persistent() bool
}

// NotificationService describes one notification destination without its credentials.
type NotificationService struct {
	// ID identifies the service. It reveals nothing about the URL.
	ID string `json:"id"`
	// Name is the label given when the service was added, if any.
	Name string `json:"name,omitempty"`
	// Service is the Shoutrrr service, such as "ntfy" or "discord".
	Service string `json:"service"`
	// Host is the server the service sends to, when the URL names one.
	Host string `json:"host,omitempty"`
	// Source is "config" for services set by flags or environment variables,
	// which cannot be removed here, or "settings" for services added at run time.
	Source string `json:"source"`
}

// NotificationsResponse is the body returned by the notifications endpoints.
type NotificationsResponse struct {
	// Services lists every notification destination.
	Services []NotificationService `json:"services"`
	// Saved is true when added services are written to the data directory and survive a restart.
	Saved bool `json:"saved"`
	// Timestamp is when the response was produced.
	Timestamp string `json:"timestamp"`
	// APIVersion is the API version of the response.
	APIVersion string `json:"api_version"`
}

// AddNotificationRequest is the body of a request to add a notification service.
type AddNotificationRequest struct {
	// Name is an optional label for the service.
	Name string `json:"name"`
	// URL is the Shoutrrr service URL.
	URL string `json:"url"`
}

// NotificationsHandler serves /v1/settings/notifications.
type NotificationsHandler struct {
	log *zerolog.Logger

	store    NotificationStore
	notifier types.Notifier
	// Path is the HTTP route path for the endpoint.
	Path string
}

// NewNotifications creates a handler for the notification services.
//
// Parameters:
//   - log: Logger for request and change messages. Nil disables logging.
//   - store: Store for services added at run time.
//   - notifier: Process notifier, whose URLs include the configured services. May be nil.
//
// Returns:
//   - *NotificationsHandler: The handler.
func NewNotifications(log *zerolog.Logger, store NotificationStore, notifier types.Notifier) *NotificationsHandler {
	if log == nil {
		nop := zerolog.Nop()
		log = &nop
	}

	return &NotificationsHandler{
		log:      log,
		store:    store,
		notifier: notifier,
		Path:     "/v1/settings/notifications",
	}
}

// List responds with every notification destination.
//
//	@Summary		List notification services
//	@Description	Lists notification services without their URLs. Source is "config" for flags and environment variables, "settings" for services added here.
//	@Tags			settings
//	@Produce		json
//	@Success		200	{object}	NotificationsResponse	"Notification services"
//	@Failure		401	{string}	string					"Missing or invalid API token"
//	@Security		BearerAuth
//	@Router			/v1/settings/notifications [get]
func (h *NotificationsHandler) List(c fiber.Ctx) error {
	return h.send(c, fiber.StatusOK)
}

// Add saves a new notification service and starts sending to it.
//
//	@Summary		Add a notification service
//	@Description	Adds a Shoutrrr notification URL, such as ntfy://ntfy.sh/topic, in addition to any set by flags. It is saved in the data directory when one is mounted.
//	@Tags			settings
//	@Accept			json
//	@Produce		json
//	@Param			request	body		AddNotificationRequest	true	"Service to add"
//	@Success		201		{object}	NotificationsResponse	"Notification services after the change"
//	@Failure		400		{object}	map[string]interface{}	"Invalid URL"
//	@Failure		401		{string}	string					"Missing or invalid API token"
//	@Failure		409		{object}	map[string]interface{}	"The service is already set up"
//	@Failure		500		{object}	map[string]interface{}	"The change could not be saved"
//	@Security		BearerAuth
//	@Router			/v1/settings/notifications [post]
func (h *NotificationsHandler) Add(c fiber.Ctx) error {
	var req AddNotificationRequest

	err := json.Unmarshal(c.Body(), &req)
	if err != nil {
		return h.sendError(c, fiber.StatusBadRequest, "request body must be a JSON object with a url")
	}

	if slices.Contains(h.configuredURLs(), req.URL) {
		return h.sendError(c, fiber.StatusConflict, runtime.ErrNotificationExists.Error())
	}

	service, err := h.store.AddNotificationService(req.Name, req.URL)
	if err != nil {
		return h.sendError(c, statusFor(err), err.Error())
	}

	scheme, _ := runtime.NotificationSummary(service.URL)

	h.log.Info().
		Str("service", scheme).
		Str("notify", "no").
		Msg("Notification service added through the HTTP API")

	return h.send(c, fiber.StatusCreated)
}

// Remove deletes a notification service added at run time.
//
//	@Summary		Remove a notification service
//	@Description	Removes a notification service that was added through the HTTP API. Services set by flags or environment variables cannot be removed here.
//	@Tags			settings
//	@Produce		json
//	@Param			id	path		string					true	"Service ID"
//	@Success		200	{object}	NotificationsResponse	"Notification services after the change"
//	@Failure		401	{string}	string					"Missing or invalid API token"
//	@Failure		404	{object}	map[string]interface{}	"No service added at run time has this ID"
//	@Failure		500	{object}	map[string]interface{}	"The change could not be saved"
//	@Security		BearerAuth
//	@Router			/v1/settings/notifications/{id} [delete]
func (h *NotificationsHandler) Remove(c fiber.Ctx) error {
	err := h.store.RemoveNotificationService(c.Params("id"))
	if err != nil {
		return h.sendError(c, statusFor(err), err.Error())
	}

	h.log.Info().Str("notify", "no").Msg("Notification service removed through the HTTP API")

	return h.send(c, fiber.StatusOK)
}

// configuredURLs returns the notifier's URLs that were not added at run time.
func (h *NotificationsHandler) configuredURLs() []string {
	if h.notifier == nil {
		return nil
	}

	added := map[string]bool{}
	for _, service := range h.store.NotificationServices() {
		added[service.URL] = true
	}

	var urls []string

	for _, url := range h.notifier.GetURLs() {
		if !added[url] {
			urls = append(urls, url)
		}
	}

	return urls
}

func (h *NotificationsHandler) send(c fiber.Ctx, status int) error {
	configured := h.configuredURLs()
	saved := h.store.NotificationServices()
	services := make([]NotificationService, 0, len(configured)+len(saved))

	for index, url := range configured {
		service, host := runtime.NotificationSummary(url)
		services = append(services, NotificationService{
			ID:      fmt.Sprintf("config-%d", index+1),
			Service: service,
			Host:    host,
			Source:  SourceConfig,
		})
	}

	for _, added := range saved {
		service, host := runtime.NotificationSummary(added.URL)
		services = append(services, NotificationService{
			ID:      added.ID,
			Name:    added.Name,
			Service: service,
			Host:    host,
			Source:  SourceSettings,
		})
	}

	err := c.Status(status).JSON(NotificationsResponse{
		Services:   services,
		Saved:      h.store.Persistent(),
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		APIVersion: "v1",
	})
	if err != nil {
		return fmt.Errorf("failed to send JSON response: %w", err)
	}

	return nil
}

func (h *NotificationsHandler) sendError(c fiber.Ctx, status int, message string) error {
	err := c.Status(status).JSON(fiber.Map{
		"error":       message,
		"api_version": "v1",
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return fmt.Errorf("failed to send JSON response: %w", err)
	}

	return nil
}

// statusFor maps a store error to an HTTP status.
func statusFor(err error) int {
	switch {
	case errors.Is(err, runtime.ErrNotificationNotFound):
		return fiber.StatusNotFound
	case errors.Is(err, runtime.ErrNotificationExists):
		return fiber.StatusConflict
	case errors.Is(err, runtime.ErrInvalidValue):
		return fiber.StatusBadRequest
	default:
		return fiber.StatusInternalServerError
	}
}
