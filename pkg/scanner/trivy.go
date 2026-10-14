package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// TrivyName is the Trivy backend name.
const TrivyName = "trivy"

// trivyStatusFail marks a misconfiguration check that failed.
const trivyStatusFail = "FAIL"

// DefaultTrivyImage is the scanner image used when none is configured.
const DefaultTrivyImage = "aquasec/trivy:latest"

// DefaultTrivyCacheVolume is the named volume that keeps Trivy's
// vulnerability database between scans, so only the first scan downloads it.
const DefaultTrivyCacheVolume = "watchtower-trivy-cache"

// trivyCacheDir is where the cache volume is mounted inside the scanner.
const trivyCacheDir = "/root/.cache/trivy"

// TrivyOptions configures the Trivy backend.
type TrivyOptions struct {
	// Image is the Trivy image to run. Empty means DefaultTrivyImage.
	Image string
	// CacheVolume keeps the vulnerability database between scans. Empty
	// means DefaultTrivyCacheVolume.
	CacheVolume string
	// IgnoreUnfixed leaves out vulnerabilities with no published fix.
	IgnoreUnfixed bool
}

// Trivy scans images by running the Trivy CLI in a short-lived container.
type Trivy struct {
	runner  Runner
	options TrivyOptions
	logger  *zerolog.Logger
	now     func() time.Time
}

// NewTrivy creates a Trivy backend.
//
// Parameters:
//   - logger: Logger for scan progress.
//   - runner: Runs the scanner container.
//   - options: Trivy settings.
//
// Returns:
//   - *Trivy: Trivy backend.
func NewTrivy(logger *zerolog.Logger, runner Runner, options TrivyOptions) *Trivy {
	if options.Image == "" {
		options.Image = DefaultTrivyImage
	}

	if options.CacheVolume == "" {
		options.CacheVolume = DefaultTrivyCacheVolume
	}

	return &Trivy{
		runner:  runner,
		options: options,
		logger:  logger,
		now:     time.Now,
	}
}

// Name returns "trivy".
//
// Returns:
//   - string: Backend name.
func (t *Trivy) Name() string {
	return TrivyName
}

// Scan runs Trivy against one image and parses its JSON report.
//
// Parameters:
//   - ctx: Context bounding the whole scan, including any scanner image pull.
//   - ref: Image name or ID to scan.
//
// Returns:
//   - *Result: Parsed findings.
//   - error: Non-nil when the scanner could not run or its report is invalid.
func (t *Trivy) Scan(ctx context.Context, ref string) (*Result, error) {
	t.logger.Debug().
		Str("scanner", TrivyName).
		Str("image", ref).
		Msg("Scanning image")

	output, err := t.runner.Run(ctx, RunSpec{
		Image:   t.options.Image,
		Args:    t.args(ref),
		Volumes: map[string]string{t.options.CacheVolume: trivyCacheDir},
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrScanFailed, ref, err)
	}

	result, err := ParseTrivyReport(output)
	if err != nil {
		return nil, err
	}

	if result.Image == "" {
		result.Image = ref
	}

	result.ScannedAt = t.now()

	return result, nil
}

// args builds the Trivy command line for one image.
//
// Parameters:
//   - ref: Image name or ID to scan.
//
// Returns:
//   - []string: Arguments after the image entrypoint.
func (t *Trivy) args(ref string) []string {
	args := []string{
		"image",
		"--quiet",
		"--format", "json",
		"--cache-dir", trivyCacheDir,
		"--scanners", "vuln,secret",
		"--image-config-scanners", "misconfig",
	}

	if t.options.IgnoreUnfixed {
		args = append(args, "--ignore-unfixed")
	}

	return append(args, ref)
}

// trivyReport is the subset of Trivy's JSON report (schema version 2) that
// Watchtower reads.
type trivyReport struct {
	SchemaVersion int    `json:"SchemaVersion"`
	ArtifactName  string `json:"ArtifactName"`
	Metadata      struct {
		ImageID string `json:"ImageID"`
	} `json:"Metadata"`
	Trivy struct {
		Version string `json:"Version"`
	} `json:"Trivy"`
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target            string               `json:"Target"`
	Vulnerabilities   []trivyVulnerability `json:"Vulnerabilities"`
	Misconfigurations []trivyMisconfig     `json:"Misconfigurations"`
	Secrets           []trivySecret        `json:"Secrets"`
}

type trivyVulnerability struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
	Title            string `json:"Title"`
	PrimaryURL       string `json:"PrimaryURL"`
}

type trivyMisconfig struct {
	ID         string `json:"ID"`
	Title      string `json:"Title"`
	Severity   string `json:"Severity"`
	Resolution string `json:"Resolution"`
	PrimaryURL string `json:"PrimaryURL"`
	Status     string `json:"Status"`
}

type trivySecret struct {
	RuleID   string `json:"RuleID"`
	Title    string `json:"Title"`
	Severity string `json:"Severity"`
}

// ParseTrivyReport converts a Trivy JSON report into a Result. Passed
// misconfiguration checks are left out. ScannedAt is left for the caller.
//
// Parameters:
//   - data: Output of trivy image --format json.
//
// Returns:
//   - *Result: Findings sorted worst first.
//   - error: Non-nil when data is not a Trivy JSON report.
func ParseTrivyReport(data []byte) (*Result, error) {
	var report trivyReport

	err := json.Unmarshal(data, &report)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidReport, err)
	}

	if report.SchemaVersion == 0 {
		return nil, fmt.Errorf("%w: missing SchemaVersion", ErrInvalidReport)
	}

	result := &Result{
		Scanner:        TrivyName,
		ScannerVersion: report.Trivy.Version,
		Image:          report.ArtifactName,
		ImageID:        report.Metadata.ImageID,
		Findings:       []Finding{},
	}

	for _, target := range report.Results {
		for _, vuln := range target.Vulnerabilities {
			result.Findings = append(result.Findings, Finding{
				ID:               vuln.VulnerabilityID,
				Kind:             KindVulnerability,
				Severity:         parseSeverityLenient(vuln.Severity),
				Package:          vuln.PkgName,
				InstalledVersion: vuln.InstalledVersion,
				FixedVersion:     vuln.FixedVersion,
				Title:            vuln.Title,
				Target:           target.Target,
				URL:              vuln.PrimaryURL,
			})
		}

		for _, check := range target.Misconfigurations {
			if !strings.EqualFold(check.Status, trivyStatusFail) {
				continue
			}

			result.Findings = append(result.Findings, Finding{
				ID:         check.ID,
				Kind:       KindMisconfiguration,
				Severity:   parseSeverityLenient(check.Severity),
				Title:      check.Title,
				Resolution: check.Resolution,
				Target:     target.Target,
				URL:        check.PrimaryURL,
			})
		}

		for _, secret := range target.Secrets {
			result.Findings = append(result.Findings, Finding{
				ID:       secret.RuleID,
				Kind:     KindSecret,
				Severity: parseSeverityLenient(secret.Severity),
				Title:    secret.Title,
				Target:   target.Target,
			})
		}
	}

	result.Findings = dedupe(result.Findings)
	SortFindings(result.Findings)

	return result, nil
}
