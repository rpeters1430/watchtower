package routes

import (
	"context"
	"fmt"

	"github.com/gofiber/fiber/v3"

	"github.com/nicholas-fedor/watchtower/internal/api/config"
	securityhandler "github.com/nicholas-fedor/watchtower/internal/api/handlers/security"
	"github.com/nicholas-fedor/watchtower/internal/security"
	"github.com/nicholas-fedor/watchtower/pkg/types"
)

func registerSecurityRoute(ctx context.Context, app *fiber.App, auth fiber.Handler, opts config.Options) {
	if opts.Client == nil {
		return
	}

	handler := securityhandler.New(opts.Logger, ctx, opts.Security, func(ctx context.Context) ([]security.Target, error) {
		var (
			list []types.Container
			err  error
		)

		if opts.Filter != nil {
			list, err = opts.Client.ListContainers(ctx, opts.Filter)
		} else {
			list, err = opts.Client.ListContainers(ctx)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to list containers: %w", err)
		}

		targets := make([]security.Target, 0, len(list))
		for _, c := range list {
			targets = append(targets, security.Target{
				Name:    c.Name(),
				Image:   c.ImageName(),
				ImageID: string(c.ImageID()),
			})
		}

		return targets, nil
	})

	app.Get(handler.Path, auth, config.TimeoutMiddleware(), handler.Get)
	app.Post(handler.Path+"/scan", auth, config.TimeoutMiddleware(), handler.Scan)
	app.Get(handler.Path+"/:name", auth, config.TimeoutMiddleware(), handler.Report)
}
