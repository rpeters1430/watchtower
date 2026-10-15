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

// SecurityRecorder is implemented by reviewers that keep what each update
// scan learned, so the HTTP API can show it. Reviewers without it are only
// used to hold updates and annotate notifications.
type SecurityRecorder interface {
	// RecordReview keeps a container's review. updated is true when the
	// update was applied, so the container now runs latestImageID.
	RecordReview(name, image, currentImageID, latestImageID string, review *scanner.Review, updated bool)
}
