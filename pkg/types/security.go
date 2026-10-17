package types

import (
	"context"
	"time"

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

// SecurityEstimator is implemented by reviewers that can say roughly how long
// reviewing an update takes, so progress views can show a time left.
type SecurityEstimator interface {
	// EstimateReview returns the expected duration of ReviewUpdate for the
	// two images, and false when there is nothing to base it on.
	EstimateReview(currentImage, latestImage string) (time.Duration, bool)
}
