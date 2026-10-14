package routes

import (
	"context"

	"github.com/gofiber/fiber/v3"

	apiconfig "github.com/nicholas-fedor/watchtower/internal/api/config"
	"github.com/nicholas-fedor/watchtower/internal/api/handlers/config"
)

func registerConfigRoute(app *fiber.App, auth fiber.Handler, opts apiconfig.Options) {
	handler := config.New(opts.Logger, func(_ context.Context) (config.ConfigData, error) {
		// Read the settings per request so run-time changes show up.
		params := opts.Settings.ApplyTo(opts.BaseParams)

		includeStopped := opts.IncludeStopped
		if opts.Settings != nil {
			includeStopped = opts.Settings.Effective().IncludeStopped
		}

		return config.ConfigData{
			MonitorOnly:       params.MonitorOnly,
			Cleanup:           params.Cleanup,
			NoPull:            params.NoPull,
			NoRestart:         params.NoRestart,
			RollingRestart:    params.RollingRestart,
			IncludeStopped:    includeStopped,
			IncludeRestarting: opts.IncludeRestarting,
			LifecycleHooks:    params.LifecycleHooks,
			LabelEnable:       opts.LabelEnable,
			FilterDesc:        opts.FilterDesc,
			Scope:             opts.Scope,
			GitEnable:         params.EnableGitMonitoring,
		}, nil
	})
	app.Get(handler.Path, auth, apiconfig.TimeoutMiddleware(), handler.Handle)
}
