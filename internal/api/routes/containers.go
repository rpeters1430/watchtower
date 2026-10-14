package routes

import (
	"context"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/timeout"

	"github.com/nicholas-fedor/watchtower/internal/api/config"
	"github.com/nicholas-fedor/watchtower/internal/api/handlers/containers"
	"github.com/nicholas-fedor/watchtower/internal/api/handlers/containers/action"
	"github.com/nicholas-fedor/watchtower/internal/api/handlers/containers/details"
)

func registerContainersRoute(app *fiber.App, auth fiber.Handler, opts config.Options) {
	if opts.Client == nil {
		return
	}

	handler := containers.New(opts.Logger, func(ctx context.Context) ([]containers.Status, error) {
		return containers.ListContainerStatuses(ctx, opts.Client, opts.Filter)
	})
	app.Get(handler.Path, auth, config.TimeoutMiddleware(), handler.Handle)
}

func registerContainersDetailsRoute(app *fiber.App, auth fiber.Handler, opts config.Options) {
	if opts.Client == nil {
		return
	}

	handler := details.New(opts.Logger, func(ctx context.Context, name, image string) ([]details.ContainerDetails, error) {
		// Built per request so run-time settings changes show up.
		detailsParams := config.BuildUpdateParams(opts)

		return details.GetContainerDetails(ctx, opts.Client, opts.Filter, name, image, detailsParams)
	})
	app.Get(handler.Path, auth, config.TimeoutMiddleware(), handler.Handle)
}

func registerContainerActionRoute(app *fiber.App, auth fiber.Handler, opts config.Options) {
	if opts.Client == nil {
		return
	}

	actionTimeout := opts.UpdateTimeout
	if actionTimeout <= 0 {
		actionTimeout = config.DefaultUpdateTimeout
	}

	executor := action.NewExecutor(opts.Logger, opts.Client, actionTimeout)
	handler := action.New(opts.Logger, executor)

	app.Post(handler.Path, auth, timeout.New(handler.Handle, timeout.Config{
		Timeout: actionTimeout,
	}))
}

