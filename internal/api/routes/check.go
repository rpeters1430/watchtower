package routes

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/timeout"

	"github.com/nicholas-fedor/watchtower/internal/api/config"
	"github.com/nicholas-fedor/watchtower/internal/api/handlers/check"
	"github.com/nicholas-fedor/watchtower/internal/api/handlers/update"
	"github.com/nicholas-fedor/watchtower/internal/metrics"
	"github.com/nicholas-fedor/watchtower/pkg/types"
)

func registerCheckRoute(app *fiber.App, auth fiber.Handler, opts config.Options) {
	if opts.Client == nil {
		return
	}

	checkTimeout := opts.CheckTimeout
	if checkTimeout <= 0 {
		checkTimeout = config.DefaultCheckTimeout
	}

	handler := check.New(opts.Logger,
		func(ctx context.Context, images, names []string, params types.UpdateParams) ([]check.ContainerCheck, error) {
			imageFilter := opts.FilterByImage(images, opts.Filter)
			containerFilter := update.ContainerFilter(names)
			combinedFilter := func(c types.FilterableContainer) bool {
				return imageFilter(c) && containerFilter(c.Name(), true)
			}

			results, err := check.CheckForUpdates(
				opts.Logger,
				ctx,
				opts.Client,
				combinedFilter,
				params,
				opts.GitClient,
			)
			if err != nil {
				return results, fmt.Errorf("check for updates: %w", err)
			}

			recordCheck(opts, results)

			return results, nil
		},
		checkTimeout,
		opts.Notifier,
		opts.NotificationSplitByContainer,
		opts.EventBroadcaster,
		func() types.UpdateParams {
			return config.BuildUpdateParams(opts)
		},
	)

	app.Post(
		handler.Path,
		auth,
		timeout.New(
			handler.Handle,
			timeout.Config{
				Timeout: checkTimeout,
			},
		),
	)

	if opts.DefaultMetrics != nil {
		latest := check.NewLatest(opts.Logger, func() []metrics.ContainerStatus {
			store := opts.DefaultMetrics()
			if store == nil {
				return nil
			}

			return store.GetStatuses()
		})

		app.Get(latest.Path, auth, latest.Handle)
	}
}

// recordCheck adds a completed check to the scan history so that checks
// started from the API or the web UI are visible alongside update scans.
func recordCheck(opts config.Options, results []check.ContainerCheck) {
	if opts.DefaultMetrics == nil {
		return
	}

	store := opts.DefaultMetrics()
	if store == nil {
		return
	}

	available, failed := 0, 0

	var containers []metrics.HistoryContainer

	statuses := make([]metrics.ContainerStatus, 0, len(results))

	for _, result := range results {
		statuses = append(statuses, checkStatus(result))

		item := metrics.HistoryContainer{
			Name:        strings.TrimPrefix(result.Name, "/"),
			Image:       result.Image,
			FromImageID: result.ImageID,
			FromVersion: result.CurrentImageVersion,
		}

		switch {
		case result.Error != "":
			failed++
			item.Outcome = metrics.HistoryOutcomeFailed
			item.Error = result.Error
		case result.UpdateAvailable:
			available++
			item.Outcome = metrics.HistoryOutcomeAvailable
			item.ToImageID = result.LatestImageID
			item.ToVersion = result.LatestImageVersion
		default:
			continue
		}

		containers = append(containers, item)
	}

	store.RecordCheck(len(results), available, failed, containers)
	store.RecordStatuses(statuses)
}

// checkStatus converts one check result into the container's latest status.
func checkStatus(result check.ContainerCheck) metrics.ContainerStatus {
	timestamp := result.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}

	return metrics.ContainerStatus{
		Name:                strings.TrimPrefix(result.Name, "/"),
		Image:               result.Image,
		ImageID:             result.ImageID,
		UpdateAvailable:     result.UpdateAvailable,
		LatestImageID:       result.LatestImageID,
		LatestDigest:        result.LatestDigest,
		CurrentImageVersion: result.CurrentImageVersion,
		LatestImageVersion:  result.LatestImageVersion,
		Changelog:           result.Changelog,
		OCISource:           result.OCISource,
		GitRepo:             result.GitRepo,
		GitRef:              result.GitRef,
		Error:               result.Error,
		Timestamp:           timestamp,
		CheckedBy:           metrics.StatusSourceCheck,
	}
}
