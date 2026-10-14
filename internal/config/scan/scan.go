// Package scan holds image vulnerability scanning settings.
package scan

import (
	"time"

	"github.com/nicholas-fedor/watchtower/pkg/scanner"
)

// Scan holds image vulnerability scanning settings.
type Scan struct {
	// Enabled turns on scanning of pending updates.
	Enabled bool
	// Gate is the lowest severity of a newly introduced finding that holds an update.
	Gate scanner.Gate
	// Image is the Trivy image to run.
	Image string
	// Timeout bounds one image scan.
	Timeout time.Duration
	// IgnoreUnfixed leaves out vulnerabilities with no published fix.
	IgnoreUnfixed bool
	// CacheVolume keeps the vulnerability database between scans.
	CacheVolume string
	// DockerSocket is the host path of the Docker socket mounted into the scanner.
	DockerSocket string
}
