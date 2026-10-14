package settings

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// notificationIDBytes is the number of random bytes in a service ID.
const notificationIDBytes = 6

// maxNotificationNameLength bounds the label a service is shown with.
const maxNotificationNameLength = 80

var (
	// ErrNotificationNotFound is returned when no saved service has the given ID.
	ErrNotificationNotFound = errors.New("no notification service with that ID")
	// ErrNotificationExists is returned when the same URL is already saved.
	ErrNotificationExists = errors.New("this notification service is already set up")
)

// NotificationService is a notification destination added at run time.
type NotificationService struct {
	// ID identifies the service. It is random, so it reveals nothing about the URL.
	ID string `json:"id"`
	// Name is the label the service is shown with.
	Name string `json:"name,omitempty"`
	// URL is the Shoutrrr service URL. It usually carries credentials.
	URL string `json:"url"`
}

// newNotificationID returns a random identifier for a notification service.
func newNotificationID() string {
	id := make([]byte, notificationIDBytes)
	_, _ = rand.Read(id) // crypto/rand.Read never returns an error.

	return hex.EncodeToString(id)
}

// assignNotificationIDs gives every service without an ID a new one, for
// services saved before IDs were stored.
func assignNotificationIDs(services []NotificationService) {
	for i := range services {
		if services[i].ID == "" {
			services[i].ID = newNotificationID()
		}
	}
}

// NotificationSummary describes a notification URL without its credentials:
// the service and, when it is a real host name, the host.
//
// Parameters:
//   - rawURL: Shoutrrr service URL.
//
// Returns:
//   - service: The URL scheme, such as "ntfy".
//   - host: The host, or empty when the URL has none worth showing.
func NotificationSummary(rawURL string) (string, string) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" {
		return "unknown", ""
	}

	service := strings.ToLower(parsed.Scheme)
	host := parsed.Hostname()

	// Several services keep an ID or token in the host part, so only show
	// hosts that look like a server name.
	if !strings.Contains(host, ".") && host != "localhost" {
		host = ""
	}

	return service, host
}

// NotificationServices returns the services added at run time.
//
// Returns:
//   - []NotificationService: Saved services in the order they were added.
func (s *Store) NotificationServices() []NotificationService {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return slices.Clone(s.overrides.NotificationServices)
}

// OnNotificationChange registers the function that puts saved notification
// services into effect. It is called straight away with the saved URLs, and
// again before each change is saved; a change it rejects is not saved.
//
// Parameters:
//   - apply: Receives the full list of URLs added at run time.
//
// Returns:
//   - error: Non-nil if the saved URLs could not be applied. They stay saved.
func (s *Store) OnNotificationChange(apply func(urls []string) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.applyNotifications = apply

	if apply == nil || len(s.overrides.NotificationServices) == 0 {
		return nil
	}

	return apply(notificationURLs(s.overrides.NotificationServices))
}

// AddNotificationService saves a new notification destination and puts it
// into effect.
//
// Parameters:
//   - name: Label to show the service with. May be empty.
//   - rawURL: Shoutrrr service URL.
//
// Returns:
//   - NotificationService: The saved service.
//   - error: Non-nil if the URL is empty, already saved, rejected, or cannot be saved.
func (s *Store) AddNotificationService(name, rawURL string) (NotificationService, error) {
	service := NotificationService{
		ID:   newNotificationID(),
		Name: strings.TrimSpace(name),
		URL:  strings.TrimSpace(rawURL),
	}

	if service.URL == "" {
		return NotificationService{}, fmt.Errorf("%w: a notification URL is required", ErrInvalidValue)
	}

	if len(service.Name) > maxNotificationNameLength {
		return NotificationService{}, fmt.Errorf("%w: the name is longer than %d characters", ErrInvalidValue, maxNotificationNameLength)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if slices.ContainsFunc(s.overrides.NotificationServices, func(saved NotificationService) bool {
		return saved.URL == service.URL
	}) {
		return NotificationService{}, ErrNotificationExists
	}

	next := s.overrides
	next.NotificationServices = append(slices.Clone(s.overrides.NotificationServices), service)

	err := s.changeNotifications(next)
	if err != nil {
		return NotificationService{}, err
	}

	return service, nil
}

// RemoveNotificationService deletes a saved notification destination.
//
// Parameters:
//   - id: The service's ID.
//
// Returns:
//   - error: ErrNotificationNotFound when no saved service has the ID, or a
//     save problem.
func (s *Store) RemoveNotificationService(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	index := slices.IndexFunc(s.overrides.NotificationServices, func(saved NotificationService) bool {
		return saved.ID == id
	})
	if index < 0 {
		return ErrNotificationNotFound
	}

	next := s.overrides
	next.NotificationServices = slices.Delete(slices.Clone(s.overrides.NotificationServices), index, index+1)

	return s.changeNotifications(next)
}

// changeNotifications applies and saves a new set of notification services.
// The caller holds s.mu.
func (s *Store) changeNotifications(next overrides) error {
	if s.applyNotifications != nil {
		err := s.applyNotifications(notificationURLs(next.NotificationServices))
		if err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidValue, err)
		}
	}

	err := s.save(next)
	if err != nil {
		// Put the services that are still saved back into effect.
		if s.applyNotifications != nil {
			_ = s.applyNotifications(notificationURLs(s.overrides.NotificationServices))
		}

		return err
	}

	s.overrides = next

	return nil
}

func notificationURLs(services []NotificationService) []string {
	urls := make([]string, 0, len(services))
	for _, service := range services {
		urls = append(urls, service.URL)
	}

	return urls
}
