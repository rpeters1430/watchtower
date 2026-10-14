// Package activity records what a running update scan is doing right now, so
// the HTTP API and the web UI can show progress while it happens: which image
// is downloading and how far it has got, and which container is being stopped
// or started.
//
// Scans are serialized by the update lock, so the tracker holds at most one
// scan. Everything is in memory and cleared when the scan ends.
package activity

import (
	"slices"
	"strings"
	"sync"
	"time"
)

// Steps a container goes through during an update.
const (
	// StepPulling means the container's new image is downloading.
	StepPulling = "pulling"
	// StepStopping means the old container is being stopped and removed.
	StepStopping = "stopping"
	// StepStarting means the replacement container is being created and started.
	StepStarting = "starting"
	// StepUpdated means the container was recreated on its new image.
	StepUpdated = "updated"
	// StepFailed means the update of this container failed.
	StepFailed = "failed"
)

// Phases of an image pull.
const (
	// PhaseStarting means the pull was requested but no layer has been reported yet.
	PhaseStarting = "starting"
	// PhaseDownloading means at least one layer is still waiting or downloading.
	PhaseDownloading = "downloading"
	// PhaseExtracting means every layer is downloaded and some are still being unpacked.
	PhaseExtracting = "extracting"
	// PhaseFinishing means every layer is in place and Docker is finishing the pull.
	PhaseFinishing = "finishing"
	// PhaseDone means the pull completed.
	PhaseDone = "done"
	// PhaseFailed means the pull failed.
	PhaseFailed = "failed"
)

// Layer states, in the order a layer moves through them.
const (
	layerQueued = iota
	layerDownloading
	layerDownloaded
	layerExtracting
	layerDone
)

// Snapshot is the state of the running scan.
type Snapshot struct {
	// Running is true while an update scan is in progress.
	Running bool `json:"running"`
	// StartedAt is when the running scan began, in RFC 3339. Empty when idle.
	StartedAt string `json:"started_at,omitempty"`
	// Containers lists the containers the scan has started working on, in order.
	Containers []Container `json:"containers"`
	// LastScan is how the most recent scan ended. Omitted while a scan runs
	// and before the first one finishes.
	LastScan *FinishedScan `json:"last_scan,omitempty"`
}

// FinishedScan is the final state of a scan that has ended, kept so a client
// polling every few seconds still learns the outcome of steps it missed.
type FinishedScan struct {
	// FinishedAt is when the scan ended, in RFC 3339.
	FinishedAt string `json:"finished_at"`
	// Containers is the final step of each container the scan worked on.
	Containers []Container `json:"containers"`
}

// Container is what the scan is doing to one container.
type Container struct {
	// Name is the container name.
	Name string `json:"name"`
	// Image is the image reference the container is updated to.
	Image string `json:"image"`
	// Step is one of the Step constants.
	Step string `json:"step"`
	// Since is when the container entered this step, in RFC 3339.
	Since string `json:"since"`
	// Pull is the download progress of the container's image while Step is pulling.
	Pull *Pull `json:"pull,omitempty"`
}

// Pull is the progress of one image pull.
type Pull struct {
	// Phase is one of the Phase constants.
	Phase string `json:"phase"`
	// Layers is the number of layers Docker has reported so far.
	Layers int `json:"layers"`
	// LayersDownloaded counts layers that have finished downloading.
	LayersDownloaded int `json:"layers_downloaded"`
	// LayersDone counts layers that are downloaded and unpacked.
	LayersDone int `json:"layers_done"`
	// DownloadedBytes is the number of bytes downloaded across reported layers.
	DownloadedBytes int64 `json:"downloaded_bytes"`
	// TotalBytes is the download size of the layers reported so far. It can
	// grow while the pull runs, because Docker reports sizes as layers start.
	TotalBytes int64 `json:"total_bytes"`
}

// Tracker records the progress of update scans. It is safe for concurrent use.
type Tracker struct {
	mu sync.Mutex

	scans      int
	startedAt  time.Time
	order      []string
	containers map[string]*containerState
	pulls      map[string]*PullProgress
	last       *FinishedScan
	now        func() time.Time
}

type containerState struct {
	image string
	step  string
	since time.Time
}

type layerState struct {
	state   int
	current int64
	total   int64
}

//nolint:gochecknoglobals // one tracker per process, like the metrics store
var defaultTracker = New()

// Default returns the process-wide tracker.
func Default() *Tracker {
	return defaultTracker
}

// New returns an empty tracker.
func New() *Tracker {
	return &Tracker{
		containers: map[string]*containerState{},
		pulls:      map[string]*PullProgress{},
		now:        time.Now,
	}
}

// BeginScan marks the start of an update scan.
func (t *Tracker) BeginScan() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.scans == 0 {
		t.startedAt = t.now()
		t.reset()
	}

	t.scans++
}

// EndScan marks the end of an update scan and forgets what it did.
func (t *Tracker) EndScan() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.scans == 0 {
		return
	}

	t.scans--
	if t.scans == 0 {
		t.last = &FinishedScan{
			FinishedAt: t.now().UTC().Format(time.RFC3339),
			Containers: t.containersLocked(false),
		}
		t.startedAt = time.Time{}
		t.reset()
	}
}

// SetStep records that a container has entered a step. It does nothing when
// no scan is running, so container actions outside a scan are not reported.
//
// Parameters:
//   - name: Container name.
//   - image: Image reference the container is updated to.
//   - step: One of the Step constants.
func (t *Tracker) SetStep(name, image, step string) {
	name = strings.TrimPrefix(name, "/")
	if name == "" {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.scans == 0 {
		return
	}

	entry, ok := t.containers[name]
	if !ok {
		entry = &containerState{}
		t.containers[name] = entry
		t.order = append(t.order, name)
	}

	if image != "" {
		entry.image = image
	}

	if entry.step != step {
		entry.step = step
		entry.since = t.now()
	}
}

// StartPull begins tracking a pull of image and returns the handle that
// receives its progress messages. Outside a scan the pull is still tracked by
// the handle, for logging, but does not appear in snapshots.
//
// Parameters:
//   - image: Image reference being pulled.
//
// Returns:
//   - *PullProgress: Handle for progress messages. Never nil.
func (t *Tracker) StartPull(image string) *PullProgress {
	progress := &PullProgress{layers: map[string]*layerState{}}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.scans > 0 && image != "" {
		t.pulls[image] = progress
	}

	return progress
}

// Snapshot returns the state of the running scan.
func (t *Tracker) Snapshot() Snapshot {
	t.mu.Lock()
	defer t.mu.Unlock()

	snapshot := Snapshot{
		Running:    t.scans > 0,
		Containers: make([]Container, 0, len(t.order)),
	}

	if snapshot.Running {
		snapshot.StartedAt = t.startedAt.UTC().Format(time.RFC3339)
		snapshot.Containers = t.containersLocked(true)
	} else if t.last != nil {
		last := *t.last
		last.Containers = slices.Clone(last.Containers)
		snapshot.LastScan = &last
	}

	return snapshot
}

// containersLocked lists the tracked containers in order, with pull progress
// when withPulls is set. The caller holds t.mu.
func (t *Tracker) containersLocked(withPulls bool) []Container {
	containers := make([]Container, 0, len(t.order))

	for _, name := range t.order {
		entry := t.containers[name]
		container := Container{
			Name:  name,
			Image: entry.image,
			Step:  entry.step,
			Since: entry.since.UTC().Format(time.RFC3339),
		}

		if withPulls && entry.step == StepPulling {
			if pull, ok := t.pulls[entry.image]; ok {
				summary := pull.Summary()
				container.Pull = &summary
			}
		}

		containers = append(containers, container)
	}

	return containers
}

// reset forgets all containers and pulls. The caller holds t.mu.
func (t *Tracker) reset() {
	t.order = nil
	t.containers = map[string]*containerState{}
	t.pulls = map[string]*PullProgress{}
}

// PullProgress receives the progress messages of one image pull.
// It is safe for concurrent use.
type PullProgress struct {
	mu     sync.Mutex
	failed bool
	done   bool
	layers map[string]*layerState
	order  []string
}

// Observe records one progress message from the Docker pull stream.
//
// Parameters:
//   - id: Layer ID the message is about. Messages without one are ignored.
//   - status: Docker's status text, such as "Downloading" or "Pull complete".
//   - current: Bytes done for a download, from the message's progress detail.
//   - total: Total bytes for a download, from the message's progress detail.
func (p *PullProgress) Observe(id, status string, current, total int64) {
	if p == nil || id == "" {
		return
	}

	state, known := layerStateFor(status)
	if !known {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.layers == nil {
		p.layers = map[string]*layerState{}
	}

	layer, ok := p.layers[id]
	if !ok {
		layer = &layerState{}
		p.layers[id] = layer
		p.order = append(p.order, id)
	}

	// Progress messages can arrive out of order; never move a layer backwards.
	if state > layer.state {
		layer.state = state
	}

	if status == "Downloading" && total > 0 {
		layer.total = total
		layer.current = min(current, total)
	}

	if layer.state >= layerDownloaded && layer.total > 0 {
		layer.current = layer.total
	}
}

// Finish records that the pull ended, successfully when err is nil.
func (p *PullProgress) Finish(err error) {
	if p == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.done = true
	p.failed = err != nil
}

// Summary condenses the per-layer state into overall progress.
func (p *PullProgress) Summary() Pull {
	if p == nil {
		return Pull{Phase: PhaseStarting}
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	summary := Pull{Layers: len(p.order)}

	waiting, unpacking := 0, 0

	for _, id := range p.order {
		layer := p.layers[id]
		summary.DownloadedBytes += layer.current
		summary.TotalBytes += layer.total

		switch layer.state {
		case layerQueued, layerDownloading:
			waiting++
		case layerDownloaded, layerExtracting:
			summary.LayersDownloaded++
			unpacking++
		case layerDone:
			summary.LayersDownloaded++
			summary.LayersDone++
		}
	}

	switch {
	case p.failed:
		summary.Phase = PhaseFailed
	case p.done:
		summary.Phase = PhaseDone
	case summary.Layers == 0:
		summary.Phase = PhaseStarting
	case waiting > 0:
		summary.Phase = PhaseDownloading
	case unpacking > 0:
		summary.Phase = PhaseExtracting
	default:
		summary.Phase = PhaseFinishing
	}

	return summary
}

// layerStateFor maps Docker's pull status text to a layer state.
func layerStateFor(status string) (int, bool) {
	switch status {
	case "Pulling fs layer", "Waiting", "Retrying":
		return layerQueued, true
	case "Downloading", "Verifying Checksum":
		return layerDownloading, true
	case "Download complete":
		return layerDownloaded, true
	case "Extracting":
		return layerExtracting, true
	case "Pull complete", "Already exists":
		return layerDone, true
	}

	// Docker prefixes retries with a countdown, e.g. "Retrying in 5 seconds".
	if strings.HasPrefix(status, "Retrying") {
		return layerQueued, true
	}

	return 0, false
}
