package metrics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"

	"github.com/nicholas-fedor/watchtower/internal/util"
	"github.com/nicholas-fedor/watchtower/pkg/types"
)

var metrics *Metrics

var metricsOnce sync.Once

// Metric holds data points from a Watchtower scan.
type Metric struct {
	Scanned   int `json:"scanned"`
	Updated   int `json:"updated"`
	Failed    int `json:"failed"`
	Restarted int `json:"restarted"`
	Skipped   int `json:"skipped"`
	// Containers names the containers the scan changed or failed on.
	Containers []HistoryContainer `json:"containers,omitempty"`
	// Statuses is the update state of each container the scan looked at.
	Statuses []ContainerStatus `json:"-"`
	// ScanFailed reports that the scan ended in an error. The counts are then
	// those the scan reached before it failed.
	ScanFailed bool `json:"scan_failed,omitempty"`
	// RecordedAt is the timestamp when the scan completed.
	RecordedAt time.Time `json:"recorded_at,omitempty"`
}

// Metrics handles processing and exposing scan metrics.
type Metrics struct {
	channel            chan *Metric               // Channel for queuing metrics.
	scanned            prometheus.Gauge           // Gauge for scanned containers.
	updated            prometheus.Gauge           // Gauge for updated containers.
	failed             prometheus.Gauge           // Gauge for failed containers.
	restarted          prometheus.Gauge           // Gauge for restarted containers.
	skipped            prometheus.Gauge           // Gauge for skipped containers.
	restartedTotal     prometheus.Counter         // Counter for total restarted containers.
	total              prometheus.Counter         // Counter for total scans.
	skippedScans       prometheus.Counter         // Counter for skipped scans.
	failedScans        prometheus.Counter         // Counter for failed scans.
	dropped            prometheus.Counter         // Counter for dropped metrics.
	imageBytes         prometheus.Gauge           // Gauge for Docker image usage bytes.
	imageReclaimable   prometheus.Gauge           // Gauge for reclaimable Docker image bytes.
	diskSpaceMaxBytes  prometheus.Gauge           // Gauge for the configured image-usage maximum.
	diskSpaceWarnBytes prometheus.Gauge           // Gauge for the configured image-usage warning threshold.
	stopCh             chan struct{}              // Channel for shutdown signaling.
	shutdownOnce       sync.Once                  // Ensures shutdown is called only once.
	lastMetric         *Metric                    // Last scan metric for status endpoint.
	lastMetricMu       sync.RWMutex               // Protects lastMetric.
	history            []HistoryEntry             // Ring buffer of scan history.
	historyIdx         int                        // Current write position in the ring buffer.
	historyMu          sync.RWMutex               // Protects history and historyIdx.
	historyPath        string                     // File history is saved to, empty for memory only.
	historySaveMu      sync.Mutex                 // Serializes writes of the history file.
	historyLog         *zerolog.Logger            // Logger for history file problems.
	statuses           map[string]ContainerStatus // Latest known status per container name.
	statusMu           sync.RWMutex               // Protects statuses, statusPath, and statusLog.
	statusPath         string                     // File statuses are saved to, empty for memory only.
	statusSaveMu       sync.Mutex                 // Serializes writes of the status file.
	statusLog          *zerolog.Logger            // Logger for status file problems.
	//nolint:containedctx
	ctx    context.Context    // Context for cancellation.
	cancel context.CancelFunc // Cancel function for the context.
}

// NewWithRegistry creates a new Metrics handler with a custom Prometheus registry.
//
// Parameters:
//   - registry: Prometheus registerer to use for metric registration.
//
// Returns:
//   - (*Metrics, error): Metrics handler with Prometheus metrics and goroutine, or an error if registration fails.
func NewWithRegistry(registry prometheus.Registerer) (*Metrics, error) {
	// channelBufferSize sets the metrics channel capacity.
	const channelBufferSize = 10

	// Create context for cancellation

	ctx, cancel := context.WithCancel(context.Background())

	// Initialize metrics with Prometheus gauges and counters.
	metrics := &Metrics{
		scanned: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "watchtower_containers_scanned",
			Help: "Number of containers scanned for changes by watchtower during the last scan",
		}),
		updated: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "watchtower_containers_updated",
			Help: "Number of containers updated by watchtower during the last scan",
		}),
		failed: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "watchtower_containers_failed",
			Help: "Number of containers where update failed during the last scan",
		}),
		restarted: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "watchtower_containers_restarted",
			Help: "Number of containers restarted due to linked dependencies during the last scan",
		}),
		skipped: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "watchtower_containers_skipped",
			Help: "Number of containers skipped during the last scan",
		}),
		restartedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "watchtower_containers_restarted_total",
			Help: "Total number of containers restarted due to linked dependencies",
		}),
		total: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "watchtower_scans_total",
			Help: "Number of scans since the watchtower started",
		}),
		skippedScans: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "watchtower_scans_skipped_total",
			Help: "Number of skipped scans since watchtower started",
		}),
		failedScans: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "watchtower_scans_failed_total",
			Help: "Number of scans that ended in an error since watchtower started",
		}),
		dropped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "watchtower_metrics_dropped_total",
			Help: "Number of metrics dropped due to full channel",
		}),
		imageBytes: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "watchtower_docker_images_bytes",
			Help: "Docker image storage usage in bytes reported by the last disk-space check",
		}),
		imageReclaimable: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "watchtower_docker_images_reclaimable_bytes",
			Help: "Reclaimable Docker image storage in bytes reported by the last disk-space check",
		}),
		diskSpaceMaxBytes: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "watchtower_disk_space_max_bytes",
			Help: "Configured Docker image-usage maximum in bytes (0 if unset)",
		}),
		diskSpaceWarnBytes: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "watchtower_disk_space_warn_bytes",
			Help: "Configured Docker image-usage warning threshold in bytes (0 if unset)",
		}),
		channel: make(chan *Metric, channelBufferSize),
		stopCh:  make(chan struct{}),
		ctx:     ctx,
		cancel:  cancel,
	}

	// Register the metrics with the provided registry.
	// If a metric is already registered, return an error to avoid duplicate collectors.
	collectors := []prometheus.Collector{
		metrics.scanned,
		metrics.updated,
		metrics.failed,
		metrics.restarted,
		metrics.skipped,
		metrics.restartedTotal,
		metrics.total,
		metrics.skippedScans,
		metrics.failedScans,
		metrics.dropped,
		metrics.imageBytes,
		metrics.imageReclaimable,
		metrics.diskSpaceMaxBytes,
		metrics.diskSpaceWarnBytes,
	}

	for _, c := range collectors {
		err := registry.Register(c)
		if err != nil {
			alreadyRegisteredError := &prometheus.AlreadyRegisteredError{}
			if errors.As(err, &alreadyRegisteredError) {
				continue
			}

			return nil, fmt.Errorf("failed to register metric: %w", err)
		}
	}

	// Start goroutine to process metrics.
	go metrics.HandleUpdate()

	return metrics, nil
}

// NewMetric creates a Metric from a scan report.
//
// Parameters:
//   - report: Scan report from types.Report.
//
// Returns:
//   - *Metric: New metric instance.
func NewMetric(report types.Report) *Metric {
	if report == nil {
		panic("NewMetric: report is nil")
	}

	var containers []HistoryContainer

	for _, group := range []struct {
		outcome string
		reports []types.ContainerReport
	}{
		{HistoryOutcomeUpdated, report.Updated()},
		{HistoryOutcomeFailed, report.Failed()},
		{HistoryOutcomeRestarted, report.Restarted()},
		{HistoryOutcomeAvailable, report.Stale()},
	} {
		for _, item := range group.reports {
			if item == nil {
				continue
			}

			containers = append(containers, NewHistoryContainer(group.outcome, item))
		}
	}

	now := time.Now().UTC()

	return &Metric{
		Scanned:    len(report.Scanned()),
		Updated:    len(report.Updated()), // Only count actually updated containers.
		Failed:     len(report.Failed()),
		Restarted:  len(report.Restarted()),
		Skipped:    len(report.Skipped()),
		Containers: containers,
		Statuses:   newScanStatuses(report, now),
		RecordedAt: now,
	}
}

// QueueIsEmpty checks if the metrics channel is empty.
//
// Returns:
//   - bool: True if empty, false otherwise.
func (m *Metrics) QueueIsEmpty() bool {
	return len(m.channel) == 0
}

// Register attempts to enqueue a metric for processing.
// If the channel is full, the metric is dropped and the dropped counter is incremented.
//
// Parameters:
//   - metric: Metric to register.
func (m *Metrics) Register(metric *Metric) {
	select {
	case m.channel <- metric:
		// Metric sent successfully
	default:
		// Channel is full, drop the metric
		m.dropped.Inc()
	}
}

// Default initializes or returns the singleton Metrics handler.
// It panics on registration failure, such as duplicate registration against the default registry.
//
// Returns:
//   - *Metrics: Metrics handler with Prometheus metrics and goroutine.
func Default() *Metrics {
	metricsOnce.Do(func() {
		var err error

		metrics, err = NewWithRegistry(prometheus.DefaultRegisterer)
		if err != nil {
			panic(err)
		}
	})

	return metrics
}

// RegisterScan enqueues a scan metric using the default handler.
//
// Parameters:
//   - metric: Metric to register.
func (m *Metrics) RegisterScan(metric *Metric) {
	m.Register(metric)
}

// RecordImageDiskUsage updates Docker image-usage gauges on the default handler.
//
// It is a no-op when metrics have not been initialized.
//
// Parameters:
//   - totalSize: Bytes used by Docker images.
//   - reclaimable: Bytes that unused images could free.
//   - maxBytes: Configured block threshold in bytes, or 0 if unset.
//   - warnBytes: Configured warning threshold in bytes, or 0 if unset.
func RecordImageDiskUsage(totalSize, reclaimable, maxBytes, warnBytes int64) {
	if metrics == nil {
		return
	}

	metrics.SetImageDiskUsage(totalSize, reclaimable, maxBytes, warnBytes)
}

// SetImageDiskUsage updates Docker image-usage gauges.
//
// Parameters:
//   - totalSize: Bytes used by Docker images.
//   - reclaimable: Bytes that unused images could free.
//   - maxBytes: Configured block threshold in bytes, or 0 if unset.
//   - warnBytes: Configured warning threshold in bytes, or 0 if unset.
func (m *Metrics) SetImageDiskUsage(totalSize, reclaimable, maxBytes, warnBytes int64) {
	if m == nil || m.imageBytes == nil {
		return
	}

	m.imageBytes.Set(float64(totalSize))
	m.imageReclaimable.Set(float64(reclaimable))
	m.diskSpaceMaxBytes.Set(float64(maxBytes))
	m.diskSpaceWarnBytes.Set(float64(warnBytes))
}

// Shutdown gracefully stops the metrics processing goroutine.
// It closes the stopCh channel and cancels the context to signal the goroutine to exit.
// This method is idempotent and can be called multiple times safely.
func (m *Metrics) Shutdown() {
	m.shutdownOnce.Do(func() {
		close(m.stopCh)
		m.cancel()
	})
}

// GetLastScan returns a copy of the most recent scan metric, or nil if no scan
// has completed yet. The returned copy is safe to modify by the caller without
// affecting the internal metrics state.
//
// Returns:
//   - *Metric: Copy of the last scan metric, or nil.
func (m *Metrics) GetLastScan() *Metric {
	m.lastMetricMu.RLock()
	defer m.lastMetricMu.RUnlock()

	if m.lastMetric == nil {
		return nil
	}

	metricCopy := *m.lastMetric

	return &metricCopy
}

// historyBufferSize defines the maximum number of scan history entries
// retained in the in-memory ring buffer.
const historyBufferSize = 500

const (
	// HistoryKindScan marks an entry recorded by an update scan.
	HistoryKindScan = "scan"
	// HistoryKindCheck marks an entry recorded by an update availability check,
	// which changes no containers.
	HistoryKindCheck = "check"
)

const (
	// HistoryOutcomeUpdated marks a container a scan moved to a newer image.
	HistoryOutcomeUpdated = "updated"
	// HistoryOutcomeFailed marks a container a scan or check failed on.
	HistoryOutcomeFailed = "failed"
	// HistoryOutcomeRestarted marks a container restarted because a container
	// it depends on was updated.
	HistoryOutcomeRestarted = "restarted"
	// HistoryOutcomeAvailable marks a container a check or scan found a newer
	// image for without applying it, for example in monitor-only mode.
	HistoryOutcomeAvailable = "available"
)

// HistoryContainer records what happened to one container in a scan or check.
// Only containers that were changed, failed, or have an update waiting are
// recorded, so up-to-date containers do not fill the history.
type HistoryContainer struct {
	Name    string `json:"name"`
	Image   string `json:"image,omitempty"`
	Outcome string `json:"outcome"`
	// FromImageID and ToImageID are the image before and after the change.
	FromImageID string `json:"from_image_id,omitempty"`
	ToImageID   string `json:"to_image_id,omitempty"`
	// FromVersion and ToVersion are the images' OCI version annotations, when set.
	FromVersion string `json:"from_version,omitempty"`
	ToVersion   string `json:"to_version,omitempty"`
	Error       string `json:"error,omitempty"`
}

// NewHistoryContainer records one container's part in a scan.
//
// Parameters:
//   - outcome: One of the HistoryOutcome* values.
//   - report: The container's scan report.
//
// Returns:
//   - HistoryContainer: The container's history record.
func NewHistoryContainer(outcome string, report types.ContainerReport) HistoryContainer {
	return HistoryContainer{
		Name:        strings.TrimPrefix(report.Name(), "/"),
		Image:       report.ImageName(),
		Outcome:     outcome,
		FromImageID: string(report.CurrentImageID()),
		ToImageID:   string(report.LatestImageID()),
		FromVersion: report.CurrentImageVersion(),
		ToVersion:   report.LatestImageVersion(),
		Error:       report.Error(),
	}
}

// HistoryEntry represents a single scan or check record in the history ring buffer.
type HistoryEntry struct {
	Timestamp time.Time `json:"timestamp"`
	// Kind is HistoryKindScan or HistoryKindCheck.
	Kind      string `json:"kind"`
	Scanned   int    `json:"scanned"`
	Updated   int    `json:"updated"`
	Failed    int    `json:"failed"`
	Restarted int    `json:"restarted"`
	Skipped   int    `json:"skipped"`
	// UpdatesAvailable counts containers a check found a newer image for.
	UpdatesAvailable int `json:"updates_available,omitempty"`
	// Containers lists the containers that were updated, failed, restarted,
	// or (for a check) have an update waiting.
	Containers []HistoryContainer `json:"containers,omitempty"`
	// ScanFailed reports that the scan ended in an error.
	ScanFailed bool `json:"scan_failed,omitempty"`
}

// RecordHistory stores a scan result in the ring buffer.
// When the buffer is full, the oldest entry is overwritten.
func (m *Metrics) RecordHistory(metric *Metric) {
	m.appendHistory(HistoryEntry{
		Timestamp:  time.Now().UTC(),
		Kind:       HistoryKindScan,
		Scanned:    metric.Scanned,
		Updated:    metric.Updated,
		Failed:     metric.Failed,
		Restarted:  metric.Restarted,
		Skipped:    metric.Skipped,
		Containers: slices.Clone(metric.Containers),
		ScanFailed: metric.ScanFailed,
	})
}

// RecordCheck stores the outcome of an update availability check in the ring
// buffer. Checks change no containers, so they do not touch the scan gauges.
//
// Parameters:
//   - checked: Number of containers checked.
//   - available: Number of containers with a newer image available.
//   - failed: Number of containers that could not be checked.
//   - containers: The containers with an update available or that failed.
func (m *Metrics) RecordCheck(checked, available, failed int, containers []HistoryContainer) {
	m.appendHistory(HistoryEntry{
		Timestamp:        time.Now().UTC(),
		Kind:             HistoryKindCheck,
		Scanned:          checked,
		Failed:           failed,
		UpdatesAvailable: available,
		Containers:       slices.Clone(containers),
	})
}

// PersistHistory loads previously saved history from path and saves the
// history there after every new entry, so it survives restarts.
// Call it once at startup, before scans begin.
//
// Parameters:
//   - log: Logger for load and save problems. Nil disables logging.
//   - path: File to keep the history in.
func (m *Metrics) PersistHistory(log *zerolog.Logger, path string) {
	if log == nil {
		nop := zerolog.Nop()
		log = &nop
	}

	m.historyMu.Lock()
	defer m.historyMu.Unlock()

	m.historyLog = log
	m.historyPath = path

	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			log.Warn().Err(err).Str("path", path).Msg("Could not read saved scan history, starting empty")
		}

		return
	}

	var saved []HistoryEntry

	err = json.Unmarshal(data, &saved)
	if err != nil {
		log.Warn().Err(err).Str("path", path).Msg("Saved scan history is not valid JSON, starting empty")

		return
	}

	slices.SortFunc(saved, func(a, b HistoryEntry) int {
		return a.Timestamp.Compare(b.Timestamp)
	})

	if len(saved) > historyBufferSize {
		saved = saved[len(saved)-historyBufferSize:]
	}

	// Entries recorded before the file was loaded are newer than anything saved.
	saved = append(saved, m.history...)
	if len(saved) > historyBufferSize {
		saved = saved[len(saved)-historyBufferSize:]
	}

	m.history = saved
	m.historyIdx = 0
}

// GetHistory returns a copy of the history entries, optionally filtered
// by since/until timestamps and limited to the most recent N entries.
// The returned slice is sorted by timestamp in ascending order.
func (m *Metrics) GetHistory(since, until *time.Time, limit int) []HistoryEntry {
	m.historyMu.RLock()
	defer m.historyMu.RUnlock()

	result := make([]HistoryEntry, 0, len(m.history))

	for _, entry := range m.history {
		if since != nil && entry.Timestamp.Before(*since) {
			continue
		}

		if until != nil && entry.Timestamp.After(*until) {
			continue
		}

		result = append(result, entry)
	}

	slices.SortFunc(result, func(a, b HistoryEntry) int {
		return a.Timestamp.Compare(b.Timestamp)
	})

	if limit > 0 && limit < len(result) {
		result = result[len(result)-limit:]
	}

	return result
}

// HandleUpdate processes metrics from the channel.
func (m *Metrics) HandleUpdate() {
	for {
		select {
		case change, ok := <-m.channel:
			if !ok {
				// Channel closed: exit handler.
				return
			}

			if change == nil {
				// Update was skipped and rescheduled
				m.total.Inc()
				m.skippedScans.Inc()
				m.scanned.Set(0)
				m.updated.Set(0)
				m.failed.Set(0)
				m.restarted.Set(0)
				m.skipped.Set(0)

				continue
			}
			// Update metrics with scan results. A failed scan still counts as a
			// scan, with the counts it reached.
			m.total.Inc()

			if change.ScanFailed {
				m.failedScans.Inc()
			}

			m.scanned.Set(float64(change.Scanned))
			m.updated.Set(float64(change.Updated))
			m.failed.Set(float64(change.Failed))
			m.restarted.Set(float64(change.Restarted))
			m.skipped.Set(float64(change.Skipped))
			m.restartedTotal.Add(float64(change.Restarted))

			m.lastMetricMu.Lock()
			m.lastMetric = change
			m.lastMetricMu.Unlock()

			m.RecordHistory(change)
			m.RecordStatuses(change.Statuses)
		case <-m.stopCh:
			return
		case <-m.ctx.Done():
			return
		}
	}
}

// appendHistory writes an entry to the ring buffer, overwriting the oldest
// entry once the buffer is full, and saves the history when it is persisted.
func (m *Metrics) appendHistory(entry HistoryEntry) {
	m.historyMu.Lock()

	if len(m.history) < historyBufferSize {
		m.history = append(m.history, entry)
	} else {
		m.history[m.historyIdx] = entry
		m.historyIdx = (m.historyIdx + 1) % historyBufferSize
	}

	path := m.historyPath
	if path == "" {
		m.historyMu.Unlock()

		return
	}

	m.historySaveMu.Lock()
	snapshot := slices.Clone(m.history)
	log := m.historyLog
	m.historyMu.Unlock()

	defer m.historySaveMu.Unlock()

	slices.SortFunc(snapshot, func(a, b HistoryEntry) int {
		return a.Timestamp.Compare(b.Timestamp)
	})

	data, err := json.Marshal(snapshot)
	if err != nil {
		log.Error().Err(err).Msg("Could not encode scan history")

		return
	}

	err = util.WriteFileAtomic(path, data)
	if err != nil {
		log.Error().Err(err).Str("path", path).Msg("Could not save scan history")
	}
}
