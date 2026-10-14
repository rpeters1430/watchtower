package types

import (
	"context"

	"github.com/nicholas-fedor/watchtower/pkg/scanner"
)

// SecurityReviewer scans the running and new image of a pending update and
// decides whether the configured severity gate holds the update back.
type SecurityReviewer interface {
	ReviewUpdate(ctx context.Context, currentImage, latestImage string) (*scanner.Review, error)
}
