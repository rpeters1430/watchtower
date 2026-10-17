package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/rs/zerolog"
)

// GrypeName is the Grype backend name.
const GrypeName = "grype"

// DefaultGrypeImage is the Grype image used when none is configured.
const DefaultGrypeImage = "anchore/grype:latest"

// DefaultGrypeCacheVolume is the named volume that keeps Grype's
// vulnerability database between scans, so only the first scan downloads it.
const DefaultGrypeCacheVolume = "watchtower-grype-cache"

// grypeCacheDir is where the cache volume is mounted inside the scanner.
const grypeCacheDir = "/grype-cache"

// grypeFixed is the fix state of a vulnerability with a published fix.
const grypeFixed = "fixed"

// maxTitleLength caps a title cut from a Grype description, which has no
// one-line title of its own.
const maxTitleLength = 120

// GrypeOptions configures the Grype backend.
type GrypeOptions struct {
	// Image is the Grype image to run. Empty means DefaultGrypeImage.
	Image string
	// CacheVolume keeps the vulnerability database between scans. Empty
	// means DefaultGrypeCacheVolume.
	CacheVolume string
	// IgnoreUnfixed leaves out vulnerabilities with no published fix.
	IgnoreUnfixed bool
}

// Grype scans images by running the Grype CLI in a short-lived container.
// Grype reports vulnerabilities only; it has no secret or misconfiguration
// checks.
type Grype struct {
	runner  Runner
	options GrypeOptions
	logger  *zerolog.Logger
	now     func() time.Time
}

// NewGrype creates a Grype backend.
//
// Parameters:
//   - logger: Logger for scan progress.
//   - runner: Runs the scanner container.
//   - options: Grype settings.
//
// Returns:
//   - *Grype: Grype backend.
func NewGrype(logger *zerolog.Logger, runner Runner, options GrypeOptions) *Grype {
	if options.Image == "" {
		options.Image = DefaultGrypeImage
	}

	if options.CacheVolume == "" {
		options.CacheVolume = DefaultGrypeCacheVolume
	}

	return &Grype{
		runner:  runner,
		options: options,
		logger:  logger,
		now:     time.Now,
	}
}

// Name returns "grype".
//
// Returns:
//   - string: Backend name.
func (g *Grype) Name() string {
	return GrypeName
}

// Image returns the Grype image the backend runs.
//
// Returns:
//   - string: Image reference.
func (g *Grype) Image() string {
	return g.options.Image
}

// Scan runs Grype against one image and parses its JSON report.
//
// Parameters:
//   - ctx: Context bounding the whole scan, including any scanner image pull.
//   - ref: Image name or ID to scan.
//
// Returns:
//   - *Result: Parsed findings.
//   - error: Non-nil when the scanner could not run or its report is invalid.
func (g *Grype) Scan(ctx context.Context, ref string) (*Result, error) {
	g.logger.Debug().
		Str("scanner", GrypeName).
		Str("image", ref).
		Msg("Scanning image")

	output, err := g.runner.Run(ctx, RunSpec{
		Image: g.options.Image,
		Args:  g.args(ref),
		Env: []string{
			"GRYPE_DB_CACHE_DIR=" + grypeCacheDir,
			// Watchtower keeps the scanner image current itself.
			"GRYPE_CHECK_FOR_APP_UPDATE=false",
			// Info level logs each phase of the scan, which marks progress.
			"GRYPE_LOG_LEVEL=info",
		},
		Volumes: map[string]string{g.options.CacheVolume: grypeCacheDir},
		Log: func(ctx context.Context, line string) {
			ReportProgress(ctx, GrypeStep(line))
		},
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrScanFailed, ref, err)
	}

	result, err := ParseGrypeReport(output)
	if err != nil {
		return nil, err
	}

	result.Image = ref
	result.ScannedAt = g.now()

	return result, nil
}

// args builds the Grype command line for one image.
//
// Parameters:
//   - ref: Image name or ID to scan.
//
// Returns:
//   - []string: Arguments after the image entrypoint.
func (g *Grype) args(ref string) []string {
	args := []string{
		// Read the image from the mounted daemon, never from a registry.
		"--from", "docker",
		"--output", "json",
	}

	if g.options.IgnoreUnfixed {
		args = append(args, "--only-fixed")
	}

	return append(args, ref)
}

// grypeSteps maps a fragment of a Grype log message to the step it starts.
var grypeSteps = []struct {
	fragment string
	step     string
}{
	{"downloading new vulnerability db", "Downloading the vulnerability database"},
	{"installed new vulnerability db", "Loading the vulnerability database"},
	{"docker saved image", "Reading the image's layers"},
	{"using distro", "Reading the image's operating system packages"},
	{"gathered packages", "Matching packages against the vulnerability database"},
}

// GrypeStep turns one line of Grype's log output into a progress step.
//
// Parameters:
//   - line: One line Grype wrote to standard error, such as
//     "[0001]  INFO downloading new vulnerability DB".
//
// Returns:
//   - string: The step the line marks, a warning, or "" for a line that
//     says nothing new.
func GrypeStep(line string) string {
	level, message := splitGrypeLine(line)
	lower := strings.ToLower(message)

	for _, known := range grypeSteps {
		if strings.HasPrefix(lower, known.fragment) {
			return known.step
		}
	}

	switch level {
	case "WARN", "ERROR":
		return "Scanner warning: " + message
	default:
		return ""
	}
}

// splitGrypeLine separates a Grype log line into its level and message,
// dropping the "[0001]" elapsed-time prefix.
//
// Parameters:
//   - line: One line of Grype log output.
//
// Returns:
//   - string: Level such as "INFO", or "" when the line has none.
//   - string: Message.
func splitGrypeLine(line string) (string, string) {
	const minFields = 3

	fields := strings.Fields(line)
	if len(fields) < minFields || !strings.HasPrefix(fields[0], "[") {
		return "", strings.TrimSpace(line)
	}

	switch fields[1] {
	case "TRACE", "DEBUG", "INFO", "WARN", "ERROR":
		return fields[1], strings.Join(fields[2:], " ")
	default:
		return "", strings.TrimSpace(line)
	}
}

// grypeReport is the subset of Grype's JSON report that Watchtower reads.
type grypeReport struct {
	Matches    *[]grypeMatch `json:"matches"`
	Descriptor struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"descriptor"`
}

type grypeMatch struct {
	Vulnerability struct {
		ID          string   `json:"id"`
		DataSource  string   `json:"dataSource"`
		Severity    string   `json:"severity"`
		URLs        []string `json:"urls"`
		Description string   `json:"description"`
		Fix         struct {
			Versions []string `json:"versions"`
			State    string   `json:"state"`
		} `json:"fix"`
	} `json:"vulnerability"`
	RelatedVulnerabilities []struct {
		Description string `json:"description"`
	} `json:"relatedVulnerabilities"`
	Artifact struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		Locations []struct {
			Path string `json:"path"`
		} `json:"locations"`
	} `json:"artifact"`
}

// ParseGrypeReport converts a Grype JSON report into a Result. Image and
// ScannedAt are left for the caller: Grype reports the reference it was
// given, and a manifest digest rather than the daemon's image ID.
//
// Parameters:
//   - data: Output of grype --output json.
//
// Returns:
//   - *Result: Findings sorted worst first.
//   - error: Non-nil when data is not a Grype JSON report.
func ParseGrypeReport(data []byte) (*Result, error) {
	var report grypeReport

	err := json.Unmarshal(data, &report)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidReport, err)
	}

	if report.Matches == nil || report.Descriptor.Name != GrypeName {
		return nil, fmt.Errorf("%w: not a Grype report", ErrInvalidReport)
	}

	result := &Result{
		Scanner:        GrypeName,
		ScannerVersion: report.Descriptor.Version,
		Findings:       make([]Finding, 0, len(*report.Matches)),
	}

	for _, match := range *report.Matches {
		vuln := match.Vulnerability

		var fixed string
		if strings.EqualFold(vuln.Fix.State, grypeFixed) {
			fixed = strings.Join(vuln.Fix.Versions, ", ")
		}

		description := vuln.Description
		if description == "" && len(match.RelatedVulnerabilities) > 0 {
			description = match.RelatedVulnerabilities[0].Description
		}

		var target string
		if len(match.Artifact.Locations) > 0 {
			target = match.Artifact.Locations[0].Path
		}

		url := vuln.DataSource
		if url == "" && len(vuln.URLs) > 0 {
			url = vuln.URLs[0]
		}

		result.Findings = append(result.Findings, Finding{
			ID:               vuln.ID,
			Kind:             KindVulnerability,
			Severity:         grypeSeverity(vuln.Severity),
			Package:          match.Artifact.Name,
			InstalledVersion: match.Artifact.Version,
			FixedVersion:     fixed,
			Title:            firstSentence(description, maxTitleLength),
			Target:           target,
			URL:              url,
		})
	}

	result.Findings = dedupe(result.Findings)
	SortFindings(result.Findings)

	return result, nil
}

// grypeSeverity maps a Grype severity to a Severity. Grype's "Negligible"
// sits below low, so it counts as low rather than unknown.
//
// Parameters:
//   - name: Severity from a Grype report.
//
// Returns:
//   - Severity: Parsed severity.
func grypeSeverity(name string) Severity {
	if strings.EqualFold(strings.TrimSpace(name), "negligible") {
		return SeverityLow
	}

	return parseSeverityLenient(name)
}

// firstSentence returns the first sentence of text, cut to at most limit
// characters on a word boundary.
//
// Parameters:
//   - text: Description.
//   - limit: Maximum length in characters.
//
// Returns:
//   - string: Short title, or "" for empty text.
func firstSentence(text string, limit int) string {
	text = strings.Join(strings.Fields(text), " ")

	if end := strings.Index(text, ". "); end >= 0 {
		text = text[:end+1]
	}

	runes := []rune(text)
	if len(runes) <= limit {
		return text
	}

	cut := string(runes[:limit])
	if space := strings.LastIndexFunc(cut, unicode.IsSpace); space > 0 {
		cut = cut[:space]
	}

	return strings.TrimRightFunc(cut, func(r rune) bool { return unicode.IsPunct(r) || unicode.IsSpace(r) }) + "…"
}
