package actions

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/nicholas-fedor/watchtower/internal/activity"
	"github.com/nicholas-fedor/watchtower/pkg/scanner"
	"github.com/nicholas-fedor/watchtower/pkg/session"
	"github.com/nicholas-fedor/watchtower/pkg/types"
)

// maxListedFindings caps how many finding IDs one log line names.
const maxListedFindings = 10

// ErrSecurityHold marks an update held back by the scan severity gate.
var ErrSecurityHold = errors.New("update held by scan gate")

// reviewSecurity scans the images of every pending update when scanning is
// on. An update whose new image introduces findings at or above the gate is
// held: the container is no longer stale and is reported as skipped with the
// findings that held it. A failed scan never holds an update.
//
// Scans are bounded by the reviewer's own timeout, not by ctx's deadline, so a
// slow scan cannot use up the time an update request has to restart its
// containers. See extendDeadline for how the caller gives that time back.
//
// Parameters:
//   - log: Process logger.
//   - ctx: Session context.
//   - containers: Filtered containers after the staleness check.
//   - progress: Session progress, used for each container's latest image.
//   - config: Update parameters carrying the reviewer.
//
// Returns:
//   - map[types.ContainerID]*scanner.Review: Completed reviews by container.
func reviewSecurity(
	log *zerolog.Logger,
	ctx context.Context,
	containers []types.Container,
	progress *session.Progress,
	config types.UpdateParams,
) map[types.ContainerID]*scanner.Review {
	reviewer := config.SecurityReviewer
	if reviewer == nil {
		return nil
	}

	ctx, cancel := withoutDeadline(ctx)
	defer cancel()

	reviews := make(map[types.ContainerID]*scanner.Review)
	tracker := activity.Default()

	// Images are scanned one at a time: every scan shares the scanner's
	// database, and the reviewer runs one scan at a time anyway.
	for _, c := range containers {
		if !c.IsStale() {
			continue
		}

		status, ok := (*progress)[c.ID()]
		if !ok {
			continue
		}

		current := string(c.ImageID())
		latest := string(status.LatestImageID())

		// A Git-built update has no new image until it is built.
		if latest == "" || latest == current {
			continue
		}

		clog := log.With().
			Str("container", c.Name()).
			Str("image", c.ImageName()).
			Logger()

		tracker.SetStep(c.Name(), c.ImageName(), activity.StepScanning)

		if estimator, ok := reviewer.(types.SecurityEstimator); ok {
			if expected, known := estimator.EstimateReview(current, latest); known {
				tracker.SetScanEstimate(c.Name(), expected)
			}
		}

		scanCtx := scanner.WithProgress(ctx, func(step string) {
			tracker.SetScanStep(c.Name(), step)
		})

		review, err := reviewer.ReviewUpdate(scanCtx, current, latest)
		tracker.SetScanResult(c.Name(), review, err)

		if err != nil {
			tracker.SetStep(c.Name(), "", activity.StepScanned)
			clog.Warn().
				Err(err).
				Msg("Could not scan the new image. Updating without a security review")

			continue
		}

		reviews[c.ID()] = review

		if review.Hold {
			tracker.SetStep(c.Name(), "", activity.StepHeld)
		} else {
			tracker.SetStep(c.Name(), "", activity.StepScanned)
		}

		counts := review.Latest.Counts()
		clog.Info().
			Int("fixed", len(review.Diff.Fixed)).
			Int("introduced", len(review.Diff.Introduced)).
			Int("critical", counts.Critical).
			Int("high", counts.High).
			Msg("Scanned new image")
	}

	held := make(map[types.ContainerID]error)

	for _, c := range containers {
		review, ok := reviews[c.ID()]
		if !ok || !review.Hold {
			continue
		}

		reason := holdReason(review)

		c.SetStale(false)
		held[c.ID()] = reason

		log.Warn().
			Str("container", c.Name()).
			Str("image", c.ImageName()).
			Str("gate", string(review.Gate)).
			Str("introduced", findingList(review.Diff.Introduced)).
			Msg("Holding update. The new image adds findings at or above the scan gate")
	}

	progress.UpdateSkipped(log, held)

	return reviews
}

// withoutDeadline returns a context that keeps parent's values and is canceled
// when parent is canceled, but outlives parent's deadline.
//
// Parameters:
//   - parent: Context to detach from its deadline.
//
// Returns:
//   - context.Context: Context without parent's deadline.
//   - context.CancelFunc: Releases the context. Always non-nil.
func withoutDeadline(parent context.Context) (context.Context, context.CancelFunc) {
	if _, ok := parent.Deadline(); !ok {
		return parent, func() {}
	}

	ctx, cancel := context.WithCancel(context.WithoutCancel(parent))

	return followCancel(parent, ctx, cancel)
}

// extendDeadline returns a context like parent whose deadline is extra later,
// so time spent scanning images is given back to the rest of the update. It is
// still canceled when parent is canceled for any reason other than its
// deadline.
//
// Parameters:
//   - parent: Context whose deadline to move.
//   - extra: How much later the deadline falls.
//
// Returns:
//   - context.Context: Context with the later deadline, or parent when it has
//     no deadline or extra is not positive.
//   - context.CancelFunc: Releases the context. Always non-nil.
func extendDeadline(parent context.Context, extra time.Duration) (context.Context, context.CancelFunc) {
	deadline, ok := parent.Deadline()
	if !ok || extra <= 0 {
		return parent, func() {}
	}

	ctx, cancel := context.WithDeadline(context.WithoutCancel(parent), deadline.Add(extra))

	return followCancel(parent, ctx, cancel)
}

// followCancel cancels ctx when parent is canceled, but not when parent only
// reached its deadline. Once parent's deadline has passed, a later
// cancellation of its own parent no longer reaches ctx; ctx's own deadline or
// the reviewer's timeout still bounds it.
//
// Parameters:
//   - parent: Context whose cancellation ctx follows.
//   - ctx: Context detached from parent.
//   - cancel: Cancels ctx.
//
// Returns:
//   - context.Context: ctx.
//   - context.CancelFunc: Stops following parent and cancels ctx.
func followCancel(
	parent, ctx context.Context,
	cancel context.CancelFunc,
) (context.Context, context.CancelFunc) {
	stop := context.AfterFunc(parent, func() {
		if !errors.Is(parent.Err(), context.DeadlineExceeded) {
			cancel()
		}
	})

	return ctx, func() {
		stop()
		cancel()
	}
}

// logSecurityFixes logs the findings each completed update fixed, so
// notifications list them alongside the update.
//
// Parameters:
//   - log: Process logger.
//   - progress: Session progress after restarts.
//   - reviews: Reviews from reviewSecurity.
func logSecurityFixes(
	log *zerolog.Logger,
	progress *session.Progress,
	reviews map[types.ContainerID]*scanner.Review,
) {
	for id, review := range reviews {
		status, ok := (*progress)[id]
		if !ok || status.State() != session.UpdatedStateString {
			continue
		}

		if len(review.Diff.Fixed) == 0 && len(review.Diff.Introduced) == 0 {
			continue
		}

		event := log.Info().
			Str("container", strings.TrimPrefix(status.Name(), "/")).
			Str("image", status.ImageName()).
			Int("fixed_count", len(review.Diff.Fixed))

		if len(review.Diff.Fixed) > 0 {
			event = event.Str("fixed", findingList(review.Diff.Fixed))
		}

		if len(review.Diff.Introduced) > 0 {
			event = event.
				Int("introduced_count", len(review.Diff.Introduced)).
				Str("introduced", findingList(review.Diff.Introduced))
		}

		event.Msg("Update changed known vulnerabilities")
	}
}

// recordSecurityReviews hands each review to the reviewer when it keeps
// them, with whether the update was applied, so the HTTP API can show what
// each container's running image contains.
//
// Parameters:
//   - progress: Session progress after restarts.
//   - reviews: Reviews from reviewSecurity.
//   - reviewer: Reviewer that produced them.
func recordSecurityReviews(
	progress *session.Progress,
	reviews map[types.ContainerID]*scanner.Review,
	reviewer types.SecurityReviewer,
) {
	recorder, ok := reviewer.(types.SecurityRecorder)
	if !ok {
		return
	}

	for id, review := range reviews {
		status, ok := (*progress)[id]
		if !ok {
			continue
		}

		recorder.RecordReview(
			strings.TrimPrefix(status.Name(), "/"),
			status.ImageName(),
			string(status.CurrentImageID()),
			string(status.LatestImageID()),
			review,
			status.State() == session.UpdatedStateString,
		)
	}
}

// holdReason describes why the gate held an update.
//
// Parameters:
//   - review: Review that holds the update.
//
// Returns:
//   - error: ErrSecurityHold with the findings at or above the gate.
func holdReason(review *scanner.Review) error {
	threshold, _ := review.Gate.Threshold()

	var blocking []scanner.Finding

	for _, finding := range review.Diff.Introduced {
		if finding.Severity >= threshold {
			blocking = append(blocking, finding)
		}
	}

	return fmt.Errorf(
		"%w: new image adds %d finding(s) at or above %s: %s",
		ErrSecurityHold,
		len(blocking),
		review.Gate,
		findingList(blocking),
	)
}

// findingList formats findings as "ID (severity)", worst first, naming at
// most maxListedFindings and counting the rest.
//
// Parameters:
//   - findings: Findings sorted worst first.
//
// Returns:
//   - string: Comma-separated list.
func findingList(findings []scanner.Finding) string {
	parts := make([]string, 0, min(len(findings), maxListedFindings)+1)

	for i, finding := range findings {
		if i == maxListedFindings {
			parts = append(parts, fmt.Sprintf("and %d more", len(findings)-maxListedFindings))

			break
		}

		parts = append(parts, fmt.Sprintf("%s (%s)", finding.ID, finding.Severity))
	}

	return strings.Join(parts, ", ")
}
