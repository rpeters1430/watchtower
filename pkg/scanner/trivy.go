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
	// SkipSecrets leaves out the check for secrets in the image's files,
	// which reads every file of every layer and is often most of a scan.
	SkipSecrets bool
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
		Log: func(ctx context.Context, line string) {
			ReportProgress(ctx, TrivyStep(line))
		},
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
	scanners := "vuln,secret"
	if t.options.SkipSecrets {
		scanners = "vuln"
	}

	args := []string{
		"image",
		// Log lines on standard error say what the scan is doing; the
		// progress bars are only noise when nobody watches a terminal.
		"--no-progress",
		"--format", "json",
		"--cache-dir", trivyCacheDir,
		"--scanners", scanners,
		"--image-config-scanners", "misconfig",
	}

	if t.options.IgnoreUnfixed {
		args = append(args, "--ignore-unfixed")
	}

	return append(args, ref)
}

// trivySteps maps a fragment of a Trivy log message to the step it starts.
// Trivy logs each phase of a scan once, so these lines mark progress.
var trivySteps = []struct {
	fragment string
	step     string
}{
	{"need to update db", "Downloading the vulnerability database"},
	{"downloading vulnerability db", "Downloading the vulnerability database"},
	{"downloading java db", "Downloading the Java vulnerability database"},
	{"secret scanning is enabled", "Reading the image's layers and checking its files for secrets"},
	{"detected os", "Reading the image's operating system packages"},
	{"number of language-specific files", "Reading the image's application dependencies"},
	{"detecting vulnerabilities", "Matching packages against the vulnerability database"},
}

// TrivyStep turns one line of Trivy's log output into a progress step.
//
// Parameters:
//   - line: One line Trivy wrote to standard error, such as
//     "2026-10-15T10:00:00Z\tINFO\t[vulndb] Need to update DB".
//
// Returns:
//   - string: The step the line marks, a warning, or "" for a line that
//     says nothing new.
func TrivyStep(line string) string {
	level, message := splitTrivyLine(line)
	lower := strings.ToLower(message)

	for _, known := range trivySteps {
		if strings.Contains(lower, known.fragment) {
			return known.step
		}
	}

	switch level {
	case "WARN", "ERROR", "FATAL":
		return "Scanner warning: " + message
	default:
		return ""
	}
}

// splitTrivyLine separates a Trivy log line into its level and message,
// dropping the timestamp, the "[component]" prefix, and trailing fields.
//
// Parameters:
//   - line: One line of Trivy log output.
//
// Returns:
//   - string: Level such as "INFO", or "" when the line has none.
//   - string: Message.
func splitTrivyLine(line string) (string, string) {
	const minTabFields = 3

	var level, message string

	if fields := strings.Split(line, "\t"); len(fields) >= minTabFields {
		level, message = fields[1], fields[2]
	} else if fields := strings.Fields(line); len(fields) >= minTabFields && isTrivyLevel(fields[1]) {
		level, message = fields[1], strings.Join(fields[2:], " ")
	} else {
		message = line
	}

	message = strings.TrimSpace(message)
	if strings.HasPrefix(message, "[") {
		if end := strings.Index(message, "] "); end > 0 {
			message = message[end+2:]
		}
	}

	return strings.TrimSpace(level), message
}

// isTrivyLevel reports whether s is a Trivy log level.
func isTrivyLevel(s string) bool {
	switch s {
	case "DEBUG", "INFO", "WARN", "ERROR", "FATAL":
		return true
	default:
		return false
	}
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
