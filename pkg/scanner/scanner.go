package scanner

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Severity ranks a finding. The zero value is SeverityUnknown.
type Severity int

// Severities in ascending order of urgency.
const (
	SeverityUnknown Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// Finding kinds.
const (
	// KindVulnerability is a known vulnerability in an installed package.
	KindVulnerability = "vulnerability"
	// KindMisconfiguration is a failed check against the image configuration.
	KindMisconfiguration = "misconfiguration"
	// KindSecret is a credential found in an image layer.
	KindSecret = "secret"
)

var (
	// ErrInvalidSeverity indicates a severity name is not recognized.
	ErrInvalidSeverity = errors.New("invalid severity")
	// ErrScanFailed indicates the scanner ran but did not produce a report.
	ErrScanFailed = errors.New("image scan failed")
	// ErrInvalidReport indicates the scanner output could not be parsed.
	ErrInvalidReport = errors.New("invalid scanner report")
)

// severityNames maps each Severity to its lower-case name.
var severityNames = map[Severity]string{
	SeverityUnknown:  "unknown",
	SeverityLow:      "low",
	SeverityMedium:   "medium",
	SeverityHigh:     "high",
	SeverityCritical: "critical",
}

// String returns the lower-case severity name.
//
// Returns:
//   - string: Severity name, "unknown" for out-of-range values.
func (s Severity) String() string {
	name, ok := severityNames[s]
	if !ok {
		return severityNames[SeverityUnknown]
	}

	return name
}

// MarshalText encodes the severity as its lower-case name.
//
// Returns:
//   - []byte: Severity name.
//   - error: Always nil.
func (s Severity) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

// UnmarshalText decodes a severity name, ignoring case.
//
// Parameters:
//   - text: Severity name.
//
// Returns:
//   - error: Non-nil when the name is not recognized.
func (s *Severity) UnmarshalText(text []byte) error {
	parsed, err := ParseSeverity(string(text))
	if err != nil {
		return err
	}

	*s = parsed

	return nil
}

// ParseSeverity parses a severity name, ignoring case and surrounding space.
//
// Parameters:
//   - name: Severity name such as "HIGH" or "critical".
//
// Returns:
//   - Severity: Parsed severity.
//   - error: Non-nil when the name is not recognized.
func ParseSeverity(name string) (Severity, error) {
	normalized := strings.ToLower(strings.TrimSpace(name))

	for severity, candidate := range severityNames {
		if candidate == normalized {
			return severity, nil
		}
	}

	return SeverityUnknown, fmt.Errorf("%w: %q", ErrInvalidSeverity, name)
}

// parseSeverityLenient parses a scanner-reported severity, mapping anything
// unrecognized to SeverityUnknown instead of failing the whole report.
//
// Parameters:
//   - name: Severity name from a scanner report.
//
// Returns:
//   - Severity: Parsed severity, or SeverityUnknown.
func parseSeverityLenient(name string) Severity {
	severity, err := ParseSeverity(name)
	if err != nil {
		return SeverityUnknown
	}

	return severity
}

// Finding is one issue a scanner reported for an image.
type Finding struct {
	// ID is the vulnerability or check identifier, such as CVE-2024-1234.
	ID string `json:"id"`
	// Kind is KindVulnerability, KindMisconfiguration, or KindSecret.
	Kind string `json:"kind"`
	// Severity is the scanner's rating.
	Severity Severity `json:"severity"`
	// Package is the affected package, empty for non-package findings.
	Package string `json:"package,omitempty"`
	// InstalledVersion is the package version in the image.
	InstalledVersion string `json:"installed_version,omitempty"`
	// FixedVersion lists the package versions that fix the finding, empty
	// when no fix is published.
	FixedVersion string `json:"fixed_version,omitempty"`
	// Resolution describes how to fix a non-package finding, such as a
	// Dockerfile change for a misconfiguration.
	Resolution string `json:"resolution,omitempty"`
	// Title is a one-line description.
	Title string `json:"title,omitempty"`
	// Target is the layer, file, or OS the finding was reported against.
	Target string `json:"target,omitempty"`
	// URL links to the advisory or check documentation.
	URL string `json:"url,omitempty"`
}

// Key identifies a finding across scans of different images. The same
// vulnerability in two packages counts as two findings. A vulnerability's
// target is left out because it names the image and OS release, which change
// with every update; a secret or misconfiguration is tied to its file.
//
// Returns:
//   - string: Stable identity of the finding.
func (f Finding) Key() string {
	if f.Kind == KindVulnerability {
		return f.Kind + "|" + f.ID + "|" + f.Package
	}

	return f.Kind + "|" + f.ID + "|" + f.Target
}

// Fixable reports whether a fixed version is published.
//
// Returns:
//   - bool: True when FixedVersion is set.
func (f Finding) Fixable() bool {
	return f.FixedVersion != ""
}

// Counts holds the number of findings at each severity.
type Counts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
}

// Total returns the number of findings across all severities.
//
// Returns:
//   - int: Sum of all counts.
func (c Counts) Total() int {
	return c.Critical + c.High + c.Medium + c.Low + c.Unknown
}

// CountFindings tallies findings by severity.
//
// Parameters:
//   - findings: Findings to count.
//
// Returns:
//   - Counts: Number of findings at each severity.
func CountFindings(findings []Finding) Counts {
	var counts Counts

	for _, finding := range findings {
		switch finding.Severity {
		case SeverityCritical:
			counts.Critical++
		case SeverityHigh:
			counts.High++
		case SeverityMedium:
			counts.Medium++
		case SeverityLow:
			counts.Low++
		case SeverityUnknown:
			counts.Unknown++
		default:
			counts.Unknown++
		}
	}

	return counts
}

// Result is one scan of one image.
type Result struct {
	// Scanner is the backend name, such as "trivy".
	Scanner string `json:"scanner"`
	// ScannerVersion is the tool version when the report includes it.
	ScannerVersion string `json:"scanner_version,omitempty"`
	// Image is the reference that was scanned.
	Image string `json:"image"`
	// ImageID is the image ID the scanner resolved, when reported.
	ImageID string `json:"image_id,omitempty"`
	// ScannedAt is when the scan finished.
	ScannedAt time.Time `json:"scanned_at"`
	// Findings are sorted worst first.
	Findings []Finding `json:"findings"`
}

// Counts tallies the result's findings by severity.
//
// Returns:
//   - Counts: Number of findings at each severity.
func (r *Result) Counts() Counts {
	if r == nil {
		return Counts{}
	}

	return CountFindings(r.Findings)
}

// Highest returns the most severe finding's severity.
//
// Returns:
//   - Severity: Highest severity, or SeverityUnknown when there are no findings.
func (r *Result) Highest() Severity {
	highest := SeverityUnknown

	if r == nil {
		return highest
	}

	for _, finding := range r.Findings {
		highest = max(highest, finding.Severity)
	}

	return highest
}

// SortFindings orders findings worst first, then by ID and package so output
// is stable between runs.
//
// Parameters:
//   - findings: Findings to sort in place.
func SortFindings(findings []Finding) {
	slices.SortStableFunc(findings, func(left, right Finding) int {
		if left.Severity != right.Severity {
			return int(right.Severity) - int(left.Severity)
		}

		if byID := strings.Compare(left.ID, right.ID); byID != 0 {
			return byID
		}

		return strings.Compare(left.Package, right.Package)
	})
}

// Scanner scans one image and reports its findings.
type Scanner interface {
	// Name returns the backend name, such as "trivy".
	Name() string
	// Scan scans the image named by ref, which may be a name or an image ID.
	Scan(ctx context.Context, ref string) (*Result, error)
}
