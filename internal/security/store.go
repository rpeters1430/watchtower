// Package security keeps the latest vulnerability scan of each container and
// runs on-demand scans for the HTTP API and web UI.
package security

import (
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/nicholas-fedor/watchtower/internal/util"
	"github.com/nicholas-fedor/watchtower/pkg/scanner"
)

// FileName is the name of the scan results file inside the data directory.
const FileName = "security.json"

// retention is how long a container's report is kept after its last scan, so
// containers that were removed or renamed eventually drop out.
const retention = 30 * 24 * time.Hour

// maxFindings caps how many findings one report keeps, worst first, so a
// very old image cannot grow the results file without bound.
const maxFindings = 1000

// Update is the security comparison of an update waiting for a container.
type Update struct {
	// LatestImageID is the image the update switches to.
	LatestImageID string `json:"latest_image_id"`
	// Fixed are findings of the running image that the new image no longer has.
	Fixed []scanner.Finding `json:"fixed,omitempty"`
	// Introduced are findings the new image adds.
	Introduced []scanner.Finding `json:"introduced,omitempty"`
	// FixedCounts tallies Fixed by severity.
	FixedCounts scanner.Counts `json:"fixed_counts"`
	// IntroducedCounts tallies Introduced by severity.
	IntroducedCounts scanner.Counts `json:"introduced_counts"`
	// Held is true when the scan gate holds the update back.
	Held bool `json:"held"`
	// Gate is the severity gate the update was checked against.
	Gate scanner.Gate `json:"gate"`
}

// AppliedUpdate records the security diff of the most recently applied update.
type AppliedUpdate struct {
	// PreviousImageID is the image the container ran before the update.
	PreviousImageID string `json:"previous_image_id,omitempty"`
	// Fixed are findings of the previous image that the new image no longer has.
	Fixed []scanner.Finding `json:"fixed,omitempty"`
	// Introduced are findings the new image added.
	Introduced []scanner.Finding `json:"introduced,omitempty"`
	// FixedCounts tallies Fixed by severity.
	FixedCounts scanner.Counts `json:"fixed_counts"`
	// IntroducedCounts tallies Introduced by severity.
	IntroducedCounts scanner.Counts `json:"introduced_counts"`
	// AppliedAt is when the update was applied.
	AppliedAt time.Time `json:"applied_at"`
}

// Report is the latest scan of one container's running image.
type Report struct {
	// Name is the container name without a leading slash.
	Name string `json:"name"`
	// Image is the image name the container runs.
	Image string `json:"image"`
	// ImageID is the image ID that was scanned.
	ImageID string `json:"image_id"`
	// Scanner is the backend name, such as "trivy".
	Scanner string `json:"scanner,omitempty"`
	// ScannerVersion is the backend version when the report includes it.
	ScannerVersion string `json:"scanner_version,omitempty"`
	// ScannedAt is when the scan finished, or failed.
	ScannedAt time.Time `json:"scanned_at"`
	// Counts tallies the findings by severity.
	Counts scanner.Counts `json:"counts"`
	// Fixable is the number of findings with a published fix.
	Fixable int `json:"fixable"`
	// Error says why the running image could not be scanned.
	Error string `json:"error,omitempty"`
	// Findings are sorted worst first. Left out of summaries.
	Findings []scanner.Finding `json:"findings,omitempty"`
	// Truncated is true when Findings was cut to maxFindings.
	Truncated bool `json:"truncated,omitempty"`
	// Update compares the running image with a waiting update, when there is one.
	Update *Update `json:"update,omitempty"`
	// LastUpdate records what the most recent update of this container fixed and introduced.
	LastUpdate *AppliedUpdate `json:"last_update,omitempty"`
}

// Summary returns the report without its finding lists.
//
// Returns:
//   - Report: Copy of the report with Findings, Fixed, and Introduced left out.
func (r Report) Summary() Report {
	r.Findings = nil

	if r.Update != nil {
		update := *r.Update
		update.Fixed = nil
		update.Introduced = nil
		r.Update = &update
	}

	if r.LastUpdate != nil {
		last := *r.LastUpdate
		last.Fixed = nil
		last.Introduced = nil
		r.LastUpdate = &last
	}

	return r
}

// newReport builds a report from a scan of a container's running image.
//
// Parameters:
//   - name: Container name.
//   - image: Image name.
//   - imageID: Image ID that was scanned.
//   - result: Scan result, or nil when the scan failed.
//   - scanErr: Why the scan failed, or nil.
//   - now: Time used when the result carries none.
//
// Returns:
//   - Report: Report for the container.
func newReport(name, image, imageID string, result *scanner.Result, scanErr error, now time.Time) Report {
	if now.IsZero() {
		now = time.Now()
	}

	report := Report{
		Name:      strings.TrimPrefix(name, "/"),
		Image:     image,
		ImageID:   imageID,
		ScannedAt: now,
	}

	if scanErr != nil {
		report.Error = scanErr.Error()
	}

	if result == nil {
		return report
	}

	report.Scanner = result.Scanner
	report.ScannerVersion = result.ScannerVersion
	report.Counts = result.Counts()

	for _, finding := range result.Findings {
		if finding.Fixable() {
			report.Fixable++
		}
	}

	report.Findings = slices.Clone(result.Findings)
	if len(report.Findings) > maxFindings {
		report.Findings = report.Findings[:maxFindings]
		report.Truncated = true
	}

	return report
}

// newUpdate builds the comparison of a waiting update from its review.
//
// Parameters:
//   - latestImageID: Image the update switches to.
//   - review: Security review of the update.
//
// Returns:
//   - *Update: Comparison for the report.
func newUpdate(latestImageID string, review *scanner.Review) *Update {
	return &Update{
		LatestImageID:    latestImageID,
		Fixed:            capFindings(review.Diff.Fixed),
		Introduced:       capFindings(review.Diff.Introduced),
		FixedCounts:      scanner.CountFindings(review.Diff.Fixed),
		IntroducedCounts: scanner.CountFindings(review.Diff.Introduced),
		Held:             review.Hold,
		Gate:             review.Gate,
	}
}

// newAppliedUpdate builds the record of an applied update from its review.
//
// Parameters:
//   - previousImageID: Image the container ran before the update.
//   - review: Security review of the update.
//   - now: Time the update completed.
//
// Returns:
//   - *AppliedUpdate: Record of what the applied update fixed and introduced.
func newAppliedUpdate(previousImageID string, review *scanner.Review, now time.Time) *AppliedUpdate {
	if review == nil {
		return nil
	}

	return &AppliedUpdate{
		PreviousImageID:  previousImageID,
		Fixed:            capFindings(review.Diff.Fixed),
		Introduced:       capFindings(review.Diff.Introduced),
		FixedCounts:      scanner.CountFindings(review.Diff.Fixed),
		IntroducedCounts: scanner.CountFindings(review.Diff.Introduced),
		AppliedAt:        now,
	}
}

// capFindings copies at most maxFindings findings.
func capFindings(findings []scanner.Finding) []scanner.Finding {
	return slices.Clone(findings[:min(len(findings), maxFindings)])
}

// Store keeps the latest report of each container. It is safe for
// concurrent use.
type Store struct {
	log  *zerolog.Logger
	path string

	mu      sync.RWMutex
	reports map[string]Report
	saveMu  sync.Mutex
}

// OpenStore creates a store and loads saved reports from dataDir. An empty,
// missing, or unwritable dataDir yields a store that keeps reports in memory.
//
// Parameters:
//   - log: Logger for load and save problems. Nil disables logging.
//   - dataDir: Directory holding security.json, or empty for none.
//
// Returns:
//   - *Store: Store ready for use.
func OpenStore(log *zerolog.Logger, dataDir string) *Store {
	if log == nil {
		nop := zerolog.Nop()
		log = &nop
	}

	store := &Store{log: log, reports: make(map[string]Report)}

	if !util.UsableDir(dataDir) {
		return store
	}

	store.path = filepath.Join(dataDir, FileName)
	store.load()

	return store
}

// Record replaces a container's report, unless the stored one is newer, and
// saves the reports when a data directory is in use.
//
// Parameters:
//   - report: Report to keep.
func (s *Store) Record(report Report) {
	s.mu.Lock()

	if current, ok := s.reports[report.Name]; ok && current.ScannedAt.After(report.ScannedAt) {
		s.mu.Unlock()

		return
	}

	s.reports[report.Name] = report

	cutoff := report.ScannedAt.Add(-retention)

	maps.DeleteFunc(s.reports, func(_ string, kept Report) bool {
		return kept.ScannedAt.Before(cutoff)
	})

	var (
		data []byte
		err  error
	)

	if s.path != "" {
		data, err = json.Marshal(sorted(s.reports))
	}

	s.mu.Unlock()

	if s.path == "" {
		return
	}

	if err != nil {
		s.log.Error().Err(err).Msg("Could not encode scan results")

		return
	}

	s.saveMu.Lock()
	defer s.saveMu.Unlock()

	err = util.WriteFileAtomic(s.path, data)
	if err != nil {
		s.log.Error().Err(err).Str("path", s.path).Msg("Could not save scan results")
	}
}

// Get returns one container's full report.
//
// Parameters:
//   - name: Container name, with or without a leading slash.
//
// Returns:
//   - Report: The report.
//   - bool: False when the container has not been scanned.
func (s *Store) Get(name string) (Report, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	report, ok := s.reports[strings.TrimPrefix(name, "/")]

	return report, ok
}

// Summaries returns every report without its finding lists, sorted by name.
//
// Returns:
//   - []Report: Summaries, empty before the first scan.
func (s *Store) Summaries() []Report {
	s.mu.RLock()
	defer s.mu.RUnlock()

	reports := sorted(s.reports)
	for i := range reports {
		reports[i] = reports[i].Summary()
	}

	return reports
}

// Persistent reports whether results are saved across restarts.
//
// Returns:
//   - bool: True when a data directory is in use.
func (s *Store) Persistent() bool {
	return s.path != ""
}

// load reads saved reports.
func (s *Store) load() {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			s.log.Warn().Err(err).Str("path", s.path).Msg("Could not read saved scan results, starting empty")
		}

		return
	}

	var saved []Report

	err = json.Unmarshal(data, &saved)
	if err != nil {
		s.log.Warn().Err(err).Str("path", s.path).Msg("Saved scan results are not valid JSON, starting empty")

		return
	}

	for _, report := range saved {
		s.reports[report.Name] = report
	}
}

// sorted returns the reports sorted by container name.
func sorted(reports map[string]Report) []Report {
	result := slices.Collect(maps.Values(reports))
	slices.SortFunc(result, func(a, b Report) int {
		return strings.Compare(a.Name, b.Name)
	})

	if result == nil {
		result = []Report{}
	}

	return result
}
