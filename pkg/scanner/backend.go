package scanner

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DefaultBackend is the scanner used when none is chosen.
const DefaultBackend = TrivyName

// ErrInvalidBackend indicates a scanner name is not a known backend.
var ErrInvalidBackend = errors.New("invalid scanner")

// Backends lists the scanner backends Watchtower can run, default first.
//
// Returns:
//   - []string: Backend names.
func Backends() []string {
	return []string{TrivyName, GrypeName}
}

// ParseBackend parses a scanner name, ignoring case. An empty value means
// DefaultBackend.
//
// Parameters:
//   - value: "trivy" or "grype".
//
// Returns:
//   - string: Backend name.
//   - error: Non-nil when the name is not recognized.
func ParseBackend(value string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))

	switch normalized {
	case "":
		return DefaultBackend, nil
	case TrivyName, GrypeName:
		return normalized, nil
	default:
		return DefaultBackend, fmt.Errorf("%w: %q (want trivy or grype)", ErrInvalidBackend, value)
	}
}

// Selection is one backend a Selector can switch to.
type Selection struct {
	// Reviewer scans images with the backend.
	Reviewer *Reviewer
	// Image is the backend's scanner image, shown to users.
	Image string
}

// Selector passes each call to the backend chosen at the time of the call,
// so the scanner can be switched while Watchtower runs. Each backend keeps
// its own reviewer, and so its own result cache: findings from one scanner
// are never served as another's.
type Selector struct {
	choose   func() string
	backends map[string]Selection
}

// NewSelector creates a Selector.
//
// Parameters:
//   - choose: Returns the backend name in force. A name with no backend
//     falls back to DefaultBackend.
//   - backends: Backends by name. Must include DefaultBackend.
//
// Returns:
//   - *Selector: Selector.
func NewSelector(choose func() string, backends map[string]Selection) *Selector {
	return &Selector{choose: choose, backends: backends}
}

// Name returns the name of the backend in force.
//
// Returns:
//   - string: Backend name, such as "trivy".
func (s *Selector) Name() string {
	return s.current().Reviewer.Name()
}

// Image returns the scanner image of the backend in force.
//
// Returns:
//   - string: Image reference.
func (s *Selector) Image() string {
	return s.current().Image
}

// ReviewUpdate scans the running and the new image with the backend in force.
//
// Parameters:
//   - ctx: Context for both scans.
//   - currentImage: Image ID of the running container.
//   - latestImage: Image ID the update switches to.
//
// Returns:
//   - *Review: Comparison and gate decision.
//   - error: Non-nil when the new image could not be scanned.
func (s *Selector) ReviewUpdate(ctx context.Context, currentImage, latestImage string) (*Review, error) {
	return s.current().Reviewer.ReviewUpdate(ctx, currentImage, latestImage)
}

// Rescan scans an image with the backend in force, ignoring cached results.
//
// Parameters:
//   - ctx: Context for the scan.
//   - image: Image ID or name.
//
// Returns:
//   - *Result: Scan result.
//   - error: Non-nil when the scan fails.
func (s *Selector) Rescan(ctx context.Context, image string) (*Result, error) {
	return s.current().Reviewer.Rescan(ctx, image)
}

// Expected estimates how long the backend in force would take to scan image.
//
// Parameters:
//   - image: Image ID or name.
//
// Returns:
//   - time.Duration: Expected scan time.
//   - bool: False when there is nothing to base an estimate on.
func (s *Selector) Expected(image string) (time.Duration, bool) {
	return s.current().Reviewer.Expected(image)
}

// current returns the backend in force.
func (s *Selector) current() Selection {
	if selected, ok := s.backends[s.choose()]; ok {
		return selected
	}

	return s.backends[DefaultBackend]
}
