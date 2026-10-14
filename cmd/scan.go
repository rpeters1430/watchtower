package cmd

import (
	"github.com/rs/zerolog"

	scanConfig "github.com/nicholas-fedor/watchtower/internal/config/scan"
	"github.com/nicholas-fedor/watchtower/pkg/scanner"
	"github.com/nicholas-fedor/watchtower/pkg/types"
)

// newSecurityReviewer builds the image scanner for pending updates.
//
// Parameters:
//   - log: Process logger.
//   - cfg: Scan settings.
//
// Returns:
//   - types.SecurityReviewer: Reviewer, or nil when scanning is off or the
//     Docker client for the scanner cannot be created. A nil reviewer means
//     updates run without scanning; it never stops Watchtower.
func newSecurityReviewer(log *zerolog.Logger, cfg scanConfig.Scan) types.SecurityReviewer {
	if !cfg.Enabled {
		return nil
	}

	api, err := scanner.NewDockerAPI()
	if err != nil {
		log.Warn().
			Err(err).
			Msg("Could not create the Docker client for image scanning. Updates will run without scanning")

		return nil
	}

	runner := scanner.NewDockerRunner(log, api, cfg.DockerSocket)
	trivy := scanner.NewTrivy(log, runner, scanner.TrivyOptions{
		Image:         cfg.Image,
		CacheVolume:   cfg.CacheVolume,
		IgnoreUnfixed: cfg.IgnoreUnfixed,
	})

	log.Info().
		Str("scanner", trivy.Name()).
		Str("image", cfg.Image).
		Str("gate", string(cfg.Gate)).
		Msg("Image scanning enabled")

	return scanner.NewReviewer(trivy, cfg.Gate, cfg.Timeout)
}
