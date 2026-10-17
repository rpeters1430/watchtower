package cmd

import (
	"github.com/rs/zerolog"

	scanConfig "github.com/nicholas-fedor/watchtower/internal/config/scan"
	"github.com/nicholas-fedor/watchtower/internal/security"
	"github.com/nicholas-fedor/watchtower/internal/settings"
	"github.com/nicholas-fedor/watchtower/pkg/scanner"
	"github.com/nicholas-fedor/watchtower/pkg/types"
)

// newSecurityService builds the image scanner. It is built whether or not
// update scanning is on, so the setting can be switched at run time and the
// HTTP API can scan running images on request.
//
// Parameters:
//   - log: Process logger.
//   - cfg: Scan settings from flags.
//   - dataDir: Directory for saved scan results, or empty for none.
//   - runtimeSettings: Run-time settings holding the scan switch and gate.
//
// Returns:
//   - *security.Service: Service, or nil when the Docker client for the
//     scanner cannot be created. A nil service means updates run without
//     scanning; it never stops Watchtower.
func newSecurityService(
	log *zerolog.Logger,
	cfg scanConfig.Scan,
	dataDir string,
	runtimeSettings *settings.Store,
) *security.Service {
	api, err := scanner.NewDockerAPI()
	if err != nil {
		log.Warn().
			Err(err).
			Msg("Could not create the Docker client for image scanning. Updates will run without scanning")

		return nil
	}

	// Both scanners are set up so the choice can change at run time. Neither
	// runs, or downloads anything, until it scans an image.
	runner := scanner.NewDockerRunner(log, api, cfg.DockerSocket)
	trivy := scanner.NewTrivy(log, runner, scanner.TrivyOptions{
		Image:         cfg.Image,
		CacheVolume:   cfg.CacheVolume,
		IgnoreUnfixed: cfg.IgnoreUnfixed,
	})
	grype := scanner.NewGrype(log, runner, scanner.GrypeOptions{
		Image:         cfg.GrypeImage,
		IgnoreUnfixed: cfg.IgnoreUnfixed,
	})

	selector := scanner.NewSelector(
		func() string { return runtimeSettings.Effective().Scanner },
		map[string]scanner.Selection{
			scanner.TrivyName: {
				Reviewer: scanner.NewReviewer(trivy, cfg.Gate, cfg.Timeout),
				Image:    cfg.Image,
			},
			scanner.GrypeName: {
				Reviewer: scanner.NewReviewer(grype, cfg.Gate, cfg.Timeout),
				Image:    grype.Image(),
			},
		},
	)

	values := runtimeSettings.Effective()
	if values.Scan {
		log.Info().
			Str("scanner", selector.Name()).
			Str("image", selector.Image()).
			Str("gate", string(values.ScanGate)).
			Msg("Image scanning enabled")
	}

	return security.NewService(
		log,
		selector,
		security.OpenStore(log, dataDir),
		security.Options{
			ScannerImage:  selector.Image,
			IgnoreUnfixed: cfg.IgnoreUnfixed,
			Enabled:       func() bool { return runtimeSettings.Effective().Scan },
			Gate:          func() scanner.Gate { return runtimeSettings.Effective().ScanGate },
		},
	)
}

// securityReviewer returns the service as a reviewer, or nil when there is
// none, so a nil service never becomes a non-nil interface.
//
// Parameters:
//   - service: Scanner service, possibly nil.
//
// Returns:
//   - types.SecurityReviewer: Reviewer, or nil.
func securityReviewer(service *security.Service) types.SecurityReviewer {
	if service == nil {
		return nil
	}

	return service
}
