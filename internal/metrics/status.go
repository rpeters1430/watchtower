package metrics

import (
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/nicholas-fedor/watchtower/internal/util"
	"github.com/nicholas-fedor/watchtower/pkg/session"
	"github.com/nicholas-fedor/watchtower/pkg/types"
)

const (
	// StatusSourceCheck marks a status recorded by an update availability check.
	StatusSourceCheck = "check"
	// StatusSourceScan marks a status recorded by an update scan.
	StatusSourceScan = "scan"
)

// statusRetention is how long a container's status is kept after it was last
// seen, so containers that were removed or renamed eventually drop out.
const statusRetention = 30 * 24 * time.Hour

// ContainerStatus is the latest known update state of one container, from
// whichever check or scan last looked at it. It is a subset of the
// per-container results of POST /v1/check, under the same JSON keys, so it
// leaves out fields only a registry check knows, such as the local digest.
type ContainerStatus struct {
	Name                string    `json:"name"`
	Image               string    `json:"image"`
	ImageID             string    `json:"image_id"`
	UpdateAvailable     bool      `json:"update_available"`
	LatestImageID       string    `json:"latest_image_id,omitempty"`
	LatestDigest        string    `json:"latest_digest,omitempty"`
	CurrentImageVersion string    `json:"current_image_version,omitempty"`
	LatestImageVersion  string    `json:"latest_image_version,omitempty"`
	Changelog           string    `json:"changelog,omitempty"`
	OCISource           string    `json:"oci_source,omitempty"`
	GitRepo             string    `json:"git_repo,omitempty"`
	GitRef              string    `json:"git_ref,omitempty"`
	Error               string    `json:"error,omitempty"`
	Timestamp           time.Time `json:"timestamp"`
	// CheckedBy is StatusSourceCheck or StatusSourceScan.
	CheckedBy string `json:"checked_by"`
}

// newScanStatuses describes each container a scan looked at. Skipped
// containers are left out, because the scan learned nothing new about them.
//
// Parameters:
//   - report: Scan report.
//   - now: Timestamp for every status.
//
// Returns:
//   - []ContainerStatus: One status per container the scan checked.
func newScanStatuses(report types.Report, now time.Time) []ContainerStatus {
	var statuses []ContainerStatus

	for _, item := range report.All() {
		if item == nil {
			continue
		}

		status := ContainerStatus{
			Name:                strings.TrimPrefix(item.Name(), "/"),
			Image:               item.ImageName(),
			ImageID:             string(item.CurrentImageID()),
			CurrentImageVersion: item.CurrentImageVersion(),
			Changelog:           item.Changelog(),
			OCISource:           item.Source(),
			GitRepo:             item.GitRepo(),
			GitRef:              item.GitRef(),
			Timestamp:           now,
			CheckedBy:           StatusSourceScan,
		}

		switch item.State() {
		case session.SkippedStateString, session.UnknownStateString:
			continue
		case session.UpdatedStateString:
			// The container now runs the image it was updated to.
			if latest := string(item.LatestImageID()); latest != "" {
				status.ImageID = latest
			}

			if version := item.LatestImageVersion(); version != "" {
				status.CurrentImageVersion = version
			}
		case session.StaleStateString:
			status.UpdateAvailable = true
			status.LatestImageID = string(item.LatestImageID())
			status.LatestImageVersion = item.LatestImageVersion()
		case session.FailedStateString:
			status.Error = item.Error()

			// A failure before the registry answered, such as a rate limit,
			// leaves the latest image equal to the current one: no update
			// was found. Otherwise the scan found one but could not apply it.
			if latest := string(item.LatestImageID()); latest != "" && latest != status.ImageID {
				status.UpdateAvailable = true
				status.LatestImageID = latest
				status.LatestImageVersion = item.LatestImageVersion()
			}
		}

		statuses = append(statuses, status)
	}

	return statuses
}

// RecordStatuses merges container statuses into the latest known state,
// replacing each named container's previous status, and saves the state when
// it is persisted.
//
// Parameters:
//   - statuses: Statuses from one check or scan.
func (m *Metrics) RecordStatuses(statuses []ContainerStatus) {
	if len(statuses) == 0 {
		return
	}

	m.statusMu.Lock()

	if m.statuses == nil {
		m.statuses = make(map[string]ContainerStatus, len(statuses))
	}

	latest := statuses[0].Timestamp

	for _, status := range statuses {
		// A check can overlap a scan and finish after it, so never let an
		// older result replace a newer one.
		if current, ok := m.statuses[status.Name]; ok && current.Timestamp.After(status.Timestamp) {
			continue
		}

		m.statuses[status.Name] = status

		if status.Timestamp.After(latest) {
			latest = status.Timestamp
		}
	}

	cutoff := latest.Add(-statusRetention)

	maps.DeleteFunc(m.statuses, func(_ string, status ContainerStatus) bool {
		return status.Timestamp.Before(cutoff)
	})

	path := m.statusPath
	log := m.statusLog

	var data []byte

	var err error

	if path != "" {
		data, err = json.Marshal(sortedStatuses(m.statuses))
	}

	m.statusMu.Unlock()

	if path == "" {
		return
	}

	if err != nil {
		log.Error().Err(err).Msg("Could not encode container statuses")

		return
	}

	m.statusSaveMu.Lock()
	defer m.statusSaveMu.Unlock()

	err = util.WriteFileAtomic(path, data)
	if err != nil {
		log.Error().Err(err).Str("path", path).Msg("Could not save container statuses")
	}
}

// GetStatuses returns the latest known status of every container, sorted by
// name.
//
// Returns:
//   - []ContainerStatus: Statuses, empty before the first check or scan.
func (m *Metrics) GetStatuses() []ContainerStatus {
	m.statusMu.RLock()
	defer m.statusMu.RUnlock()

	return sortedStatuses(m.statuses)
}

// PersistStatuses loads previously saved container statuses from path and
// saves them there after every change, so they survive restarts.
// Call it once at startup, before scans begin.
//
// Parameters:
//   - log: Logger for load and save problems. Nil disables logging.
//   - path: File to keep the statuses in.
func (m *Metrics) PersistStatuses(log *zerolog.Logger, path string) {
	if log == nil {
		nop := zerolog.Nop()
		log = &nop
	}

	m.statusMu.Lock()
	defer m.statusMu.Unlock()

	m.statusLog = log
	m.statusPath = path

	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			log.Warn().Err(err).Str("path", path).Msg("Could not read saved container statuses, starting empty")
		}

		return
	}

	var saved []ContainerStatus

	err = json.Unmarshal(data, &saved)
	if err != nil {
		log.Warn().Err(err).Str("path", path).Msg("Saved container statuses are not valid JSON, starting empty")

		return
	}

	if m.statuses == nil {
		m.statuses = make(map[string]ContainerStatus, len(saved))
	}

	for _, status := range saved {
		// Statuses recorded before the file was loaded are newer than anything saved.
		if current, ok := m.statuses[status.Name]; ok && current.Timestamp.After(status.Timestamp) {
			continue
		}

		m.statuses[status.Name] = status
	}
}

func sortedStatuses(statuses map[string]ContainerStatus) []ContainerStatus {
	result := slices.Collect(maps.Values(statuses))
	slices.SortFunc(result, func(a, b ContainerStatus) int {
		return strings.Compare(a.Name, b.Name)
	})

	if result == nil {
		result = []ContainerStatus{}
	}

	return result
}
