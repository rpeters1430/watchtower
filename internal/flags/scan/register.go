// Package scan registers image vulnerability scanning flags.
package scan

import (
	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/watchtower/internal/flags/spec"
	"github.com/nicholas-fedor/watchtower/pkg/scanner"
)

// Specs returns scan domain flag metadata with static defaults.
//
// Returns:
//   - []spec.FlagSpec: Scan flag specifications.
func Specs() []spec.FlagSpec {
	return []spec.FlagSpec{
		{
			Name:    "scan",
			Kind:    spec.KindBool,
			Default: false,
			EnvKeys: []string{"WATCHTOWER_SCAN"},
			Help:    "Scan the new image of each pending update for known vulnerabilities with Trivy before updating",
		},
		{
			Name:    "scan-gate",
			Kind:    spec.KindString,
			Default: string(scanner.GateOff),
			EnvKeys: []string{"WATCHTOWER_SCAN_GATE"},
			Help:    "Hold an update when its new image adds findings at or above this severity (off, low, medium, high, critical)",
		},
		{
			Name:    "scan-image",
			Kind:    spec.KindString,
			Default: scanner.DefaultTrivyImage,
			EnvKeys: []string{"WATCHTOWER_SCAN_IMAGE"},
			Help:    "Trivy image used to scan images",
		},
		{
			Name:    "scan-timeout",
			Kind:    spec.KindDuration,
			Default: scanner.DefaultTimeout,
			EnvKeys: []string{"WATCHTOWER_SCAN_TIMEOUT"},
			Help:    "Timeout for scanning one image, including the first vulnerability database download",
		},
		{
			Name:    "scan-ignore-unfixed",
			Kind:    spec.KindBool,
			Default: false,
			EnvKeys: []string{"WATCHTOWER_SCAN_IGNORE_UNFIXED"},
			Help:    "Leave out vulnerabilities that have no published fix",
		},
		{
			Name:    "scan-cache-volume",
			Kind:    spec.KindString,
			Default: scanner.DefaultTrivyCacheVolume,
			EnvKeys: []string{"WATCHTOWER_SCAN_CACHE_VOLUME"},
			Help:    "Docker volume that keeps the vulnerability database between scans",
		},
		{
			Name:    "scan-docker-socket",
			Kind:    spec.KindString,
			Default: scanner.DefaultDockerSocket,
			EnvKeys: []string{"WATCHTOWER_SCAN_DOCKER_SOCKET"},
			Help:    "Host path of the Docker socket mounted into the scanner container",
		},
	}
}

// Register adds scan domain flags to the root command.
//
// Parameters:
//   - rootCmd: Root Cobra command.
func Register(rootCmd *cobra.Command) {
	spec.MustRegister(rootCmd.PersistentFlags(), Specs())
}
