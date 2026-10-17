package security

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/nicholas-fedor/watchtower/pkg/scanner"
)

// maxActivity caps how many steps a job's activity list keeps.
const maxActivity = 40

// minRemaining is the least time an estimate leaves for a scan that has
// already run longer than expected.
const minRemaining = 5 * time.Second

var (
	// ErrBusy is returned when a scan is requested while one is running.
	ErrBusy = errors.New("a security scan is already running")
	// ErrNothingToScan is returned when a scan request matches no container.
	ErrNothingToScan = errors.New("no container to scan")
	// errCurrentUnscanned explains a report whose running image could not be scanned.
	errCurrentUnscanned = errors.New("the running image could not be scanned")
)

// ImageScanner scans images and reviews pending updates. *scanner.Reviewer
// implements it.
type ImageScanner interface {
	// Name returns the backend name, such as "trivy".
	Name() string
	// ReviewUpdate scans the running and the new image and compares them.
	ReviewUpdate(ctx context.Context, currentImage, latestImage string) (*scanner.Review, error)
	// Rescan scans an image against the latest vulnerability database.
	Rescan(ctx context.Context, image string) (*scanner.Result, error)
	// Expected estimates how long scanning an image would take now. It
	// returns false when it has nothing to base the estimate on.
	Expected(image string) (time.Duration, bool)
}

// Target is one container to scan.
type Target struct {
	// Name is the container name.
	Name string
	// Image is the image name the container runs.
	Image string
	// ImageID is the image ID the container runs.
	ImageID string
}

// Job is the state of the latest on-demand scan.
type Job struct {
	// Running is true while the scan is in progress.
	Running bool `json:"running"`
	// StartedAt is when the scan started, omitted before the first one.
	StartedAt *time.Time `json:"started_at,omitempty"`
	// FinishedAt is when the scan finished, omitted while it runs.
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	// Total is the number of containers the scan covers.
	Total int `json:"total"`
	// Done is the number of containers scanned so far.
	Done int `json:"done"`
	// Failed is the number of containers whose image could not be scanned.
	Failed int `json:"failed"`
	// Current names the containers being scanned right now.
	Current []string `json:"current,omitempty"`
	// Waiting names the containers still queued, in the order they will be
	// scanned. Images are scanned one at a time.
	Waiting []string `json:"waiting,omitempty"`
	// Images is the number of distinct images the scan covers.
	Images int `json:"images"`
	// ImagesDone is the number of those images scanned so far.
	ImagesDone int `json:"images_done"`
	// CurrentStartedAt is when the image being scanned right now started.
	CurrentStartedAt *time.Time `json:"current_started_at,omitempty"`
	// EstimatedFinishAt is when the scan is expected to finish, based on how
	// long earlier scans of the same images took, or on the average so far.
	// Omitted until there is anything to base it on.
	EstimatedFinishAt *time.Time `json:"estimated_finish_at,omitempty"`
	// Step says what the scan is doing right now, such as downloading the
	// vulnerability database.
	Step string `json:"step,omitempty"`
	// StepStartedAt is when the current step began.
	StepStartedAt *time.Time `json:"step_started_at,omitempty"`
	// Activity lists the scan's steps so far, oldest first, up to the most
	// recent maxActivity.
	Activity []Activity `json:"activity,omitempty"`
}

// Activity is one step of an on-demand scan.
type Activity struct {
	// At is when the step began.
	At time.Time `json:"at"`
	// Containers names the containers the step is about, if any.
	Containers []string `json:"containers,omitempty"`
	// Message says what happened, in a sentence.
	Message string `json:"message"`
	// Problem is true when the step is a failure.
	Problem bool `json:"problem,omitempty"`
}

// Options configures a Service.
type Options struct {
	// ScannerImage returns the image of the scanner in force, shown to
	// users. Nil means none is shown.
	ScannerImage func() string
	// IgnoreUnfixed is true when findings without a fix are left out.
	IgnoreUnfixed bool
	// Enabled reports whether pending updates are scanned. Nil means off.
	Enabled func() bool
	// Gate returns the severity gate in force. Nil means scanner.GateOff.
	Gate func() scanner.Gate
}

// Service scans images, applies the run-time severity gate to pending
// updates, and keeps each container's latest report.
type Service struct {
	log     *zerolog.Logger
	scanner ImageScanner
	store   *Store
	options Options
	now     func() time.Time

	mu  sync.Mutex
	job Job
	// plan holds what the running job needs to estimate its finish.
	plan plan
}

// plan is the running job's queue and timings, for its estimate.
type plan struct {
	// queue holds the image IDs not started yet, in scan order.
	queue []string
	// current is the image ID being scanned.
	current string
	// previous maps an image ID to how long its last scan took.
	previous map[string]time.Duration
	// taken lists how long each image of this job took.
	taken []time.Duration
}

// NewService creates a Service.
//
// Parameters:
//   - log: Logger for scan progress. Nil disables logging.
//   - imageScanner: Backend that scans images.
//   - store: Store for each container's latest report.
//   - options: Scanner details and run-time settings.
//
// Returns:
//   - *Service: Service ready for use.
func NewService(log *zerolog.Logger, imageScanner ImageScanner, store *Store, options Options) *Service {
	if log == nil {
		nop := zerolog.Nop()
		log = &nop
	}

	return &Service{
		log:     log,
		scanner: imageScanner,
		store:   store,
		options: options,
		now:     time.Now,
	}
}

// ScannerName returns the scanner backend's name.
//
// Returns:
//   - string: Backend name, such as "trivy".
func (s *Service) ScannerName() string {
	return s.scanner.Name()
}

// ScannerImage returns the scanner container image.
//
// Returns:
//   - string: Image reference.
func (s *Service) ScannerImage() string {
	if s.options.ScannerImage == nil {
		return ""
	}

	return s.options.ScannerImage()
}

// IgnoreUnfixed reports whether findings without a fix are left out.
//
// Returns:
//   - bool: True when unfixed findings are left out.
func (s *Service) IgnoreUnfixed() bool {
	return s.options.IgnoreUnfixed
}

// Enabled reports whether pending updates are scanned.
//
// Returns:
//   - bool: True when update scanning is on.
func (s *Service) Enabled() bool {
	return s.options.Enabled != nil && s.options.Enabled()
}

// Gate returns the severity gate in force.
//
// Returns:
//   - scanner.Gate: Gate, GateOff when none is set.
func (s *Service) Gate() scanner.Gate {
	if s.options.Gate == nil {
		return scanner.GateOff
	}

	return s.options.Gate()
}

// Store returns the store holding each container's latest report.
//
// Returns:
//   - *Store: Report store.
func (s *Service) Store() *Store {
	return s.store
}

// ReviewUpdate scans both images of a pending update and checks the new one
// against the gate in force at the time of the call.
//
// Parameters:
//   - ctx: Context for both scans.
//   - currentImage: Image ID of the running container.
//   - latestImage: Image ID the update switches to.
//
// Returns:
//   - *scanner.Review: Comparison and gate decision.
//   - error: Non-nil when the new image could not be scanned.
func (s *Service) ReviewUpdate(ctx context.Context, currentImage, latestImage string) (*scanner.Review, error) {
	review, err := s.scanner.ReviewUpdate(ctx, currentImage, latestImage)
	if err != nil {
		return nil, err //nolint:wrapcheck // The reviewer's error already names the image and scanner.
	}

	gated := *review
	gated.Gate = s.Gate()
	gated.Hold = review.Diff.Blocks(gated.Gate)

	return &gated, nil
}

// EstimateReview works out how long ReviewUpdate should take for an
// update: the scanner's own estimate for each image, or else how long the
// image's last on-request scan took, or else the average of those scans.
//
// Parameters:
//   - currentImage: Image ID of the running container.
//   - latestImage: Image ID the update switches to.
//
// Returns:
//   - time.Duration: Expected time for both scans.
//   - bool: False when there is nothing to base an estimate on.
func (s *Service) EstimateReview(currentImage, latestImage string) (time.Duration, bool) {
	var (
		previous map[string]time.Duration
		average  time.Duration
		total    time.Duration
	)

	for _, imageID := range []string{latestImage, currentImage} {
		if took, ok := s.scanner.Expected(imageID); ok {
			total += took

			continue
		}

		if previous == nil {
			previous = s.previousScans()
			average = mean(slices.Collect(maps.Values(previous)))
		}

		took, ok := previous[imageID]
		if !ok {
			took = average
		}

		if took == 0 {
			return 0, false
		}

		total += took
	}

	return total, true
}

// RecordReview keeps what an update scan learned about a container. An
// updated container now runs the new image, so its report is the new
// image's scan. Otherwise the report is the running image's scan, with the
// waiting update's comparison attached.
//
// Parameters:
//   - name: Container name.
//   - image: Image name.
//   - currentImageID: Image the container ran when it was scanned.
//   - latestImageID: Image the update switches to.
//   - review: Review of the update.
//   - updated: True when the update was applied.
func (s *Service) RecordReview(
	name, image, currentImageID, latestImageID string,
	review *scanner.Review,
	updated bool,
) {
	if review == nil {
		return
	}

	now := s.now()

	if updated {
		report := newReport(name, image, latestImageID, review.Latest, nil, now)
		report.LastUpdate = newAppliedUpdate(currentImageID, review, now)
		s.store.Record(report)

		return
	}

	var scanErr error
	if review.Current == nil {
		scanErr = errCurrentUnscanned
	}

	report := newReport(name, image, currentImageID, review.Current, scanErr, now)
	report.Update = newUpdate(latestImageID, review)

	if previous, ok := s.store.Get(name); ok && previous.LastUpdate != nil {
		report.LastUpdate = previous.LastUpdate
	}

	s.store.Record(report)
}

// Job returns the state of the latest on-demand scan.
//
// Returns:
//   - Job: Copy of the job state.
func (s *Service) Job() Job {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.snapshot()
}

// Start scans the running image of each target in the background, against
// the latest vulnerability database. Containers sharing an image share one
// scan.
//
// Parameters:
//   - ctx: Long-lived context; cancelling it stops the scan.
//   - targets: Containers to scan.
//
// Returns:
//   - Job: The job state at the start.
//   - error: ErrBusy when a scan is running, ErrNothingToScan when no
//     target has an image ID.
func (s *Service) Start(ctx context.Context, targets []Target) (Job, error) {
	byImage := make(map[string][]Target)
	order := make([]string, 0, len(targets))
	total := 0

	for _, target := range targets {
		if target.ImageID == "" {
			continue
		}

		target.Name = strings.TrimPrefix(target.Name, "/")

		if _, seen := byImage[target.ImageID]; !seen {
			order = append(order, target.ImageID)
		}

		byImage[target.ImageID] = append(byImage[target.ImageID], target)
		total++
	}

	if total == 0 {
		return Job{}, ErrNothingToScan
	}

	s.mu.Lock()

	if s.job.Running {
		s.mu.Unlock()

		return Job{}, ErrBusy
	}

	previous := s.previousScans()

	waiting := make([]string, 0, total)

	for _, imageID := range order {
		for _, target := range byImage[imageID] {
			waiting = append(waiting, target.Name)
		}
	}

	started := s.now().UTC()
	s.job = Job{Running: true, StartedAt: &started, Total: total, Images: len(order), Waiting: waiting}
	s.plan = plan{queue: slices.Clone(order), previous: previous}
	s.step(nil, startMessage(total, len(order)), false)
	job := s.snapshot()

	s.mu.Unlock()

	s.log.Info().Int("containers", total).Int("images", len(order)).Msg("Starting security scan")

	go s.run(ctx, order, byImage)

	return job, nil
}

// previousScans maps each image ID to how long its last successful
// on-request scan took, from the stored reports.
//
// Returns:
//   - map[string]time.Duration: Scan durations by image ID.
func (s *Service) previousScans() map[string]time.Duration {
	previous := make(map[string]time.Duration)

	for _, report := range s.store.Summaries() {
		if report.ScanSeconds > 0 && report.Error == "" {
			previous[report.ImageID] = time.Duration(report.ScanSeconds * float64(time.Second))
		}
	}

	return previous
}

// snapshot copies the job state and adds the current estimate. Callers
// hold s.mu.
//
// Returns:
//   - Job: Copy of the job state.
func (s *Service) snapshot() Job {
	job := s.job
	job.Current = slices.Clone(s.job.Current)
	job.Waiting = slices.Clone(s.job.Waiting)
	job.Activity = slices.Clone(s.job.Activity)

	if job.Running {
		job.EstimatedFinishAt = s.estimate()
	}

	return job
}

// estimate works out when the running job should finish: each remaining
// image takes as long as its last scan did, or else the average of this
// job's scans, or else the average of earlier scans. Callers hold s.mu.
//
// Returns:
//   - *time.Time: Expected finish, or nil when there is nothing to go on.
func (s *Service) estimate() *time.Time {
	average := mean(s.plan.taken)
	if average == 0 {
		average = mean(slices.Collect(maps.Values(s.plan.previous)))
	}

	guess := func(imageID string) time.Duration {
		if took, ok := s.plan.previous[imageID]; ok {
			return took
		}

		return average
	}

	now := s.now()

	var remaining time.Duration

	for _, imageID := range s.plan.queue {
		took := guess(imageID)
		if took == 0 {
			return nil
		}

		remaining += took
	}

	if s.plan.current != "" && s.job.CurrentStartedAt != nil {
		took := guess(s.plan.current)
		if took == 0 {
			return nil
		}

		remaining += max(took-now.Sub(*s.job.CurrentStartedAt), minRemaining)
	}

	finish := now.Add(remaining).UTC().Truncate(time.Second)

	return &finish
}

// mean returns the average of durations, or 0 for none.
func mean(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}

	var sum time.Duration
	for _, d := range durations {
		sum += d
	}

	return sum / time.Duration(len(durations))
}

// step records what the running job is doing. A step repeating the current
// one is dropped. Callers hold s.mu.
//
// Parameters:
//   - names: Containers the step is about, or nil.
//   - message: What is happening.
//   - problem: True when the step is a failure.
func (s *Service) step(names []string, message string, problem bool) {
	if message == "" || (s.job.Step == message && !problem) {
		return
	}

	startedAt := s.now().UTC()

	if !problem {
		s.job.Step = message
		s.job.StepStartedAt = &startedAt
	}

	s.job.Activity = append(s.job.Activity, Activity{
		At:         startedAt,
		Containers: slices.Clone(names),
		Message:    message,
		Problem:    problem,
	})

	if extra := len(s.job.Activity) - maxActivity; extra > 0 {
		s.job.Activity = slices.Delete(s.job.Activity, 0, extra)
	}
}

// run scans each image in turn and records a report for every container
// using it. Images go one at a time: the reviewer serializes scans anyway,
// so this keeps the job's current image and estimate accurate.
func (s *Service) run(ctx context.Context, order []string, byImage map[string][]Target) {
	for _, imageID := range order {
		s.scanImage(ctx, imageID, byImage[imageID])
	}

	finished := s.now().UTC()

	s.mu.Lock()
	s.job.Running = false
	s.job.Current = nil
	s.job.Waiting = nil
	s.job.CurrentStartedAt = nil
	s.job.Step = ""
	s.job.StepStartedAt = nil
	s.job.FinishedAt = &finished
	s.plan = plan{}
	job := s.job
	s.mu.Unlock()

	s.log.Info().Int("containers", job.Total).Int("failed", job.Failed).Msg("Security scan finished")
}

// scanImage scans one image and records a report for each container using it.
//
// Parameters:
//   - ctx: Context for the scan.
//   - imageID: Image to scan.
//   - targets: Containers running the image.
func (s *Service) scanImage(ctx context.Context, imageID string, targets []Target) {
	names := make([]string, 0, len(targets))
	for _, target := range targets {
		names = append(names, target.Name)
	}

	began := s.now()
	beganUTC := began.UTC()

	s.mu.Lock()
	s.job.Current = names
	s.job.CurrentStartedAt = &beganUTC
	s.job.Waiting = slices.DeleteFunc(s.job.Waiting, func(name string) bool {
		return slices.Contains(names, name)
	})
	s.plan.queue = slices.DeleteFunc(s.plan.queue, func(id string) bool { return id == imageID })
	s.plan.current = imageID
	s.step(names, "Scanning "+strings.Join(names, ", "), false)
	s.mu.Unlock()

	progress := scanner.WithProgress(ctx, func(step string) {
		s.mu.Lock()
		defer s.mu.Unlock()

		s.step(names, step, false)
	})

	result, err := s.scanner.Rescan(progress, imageID)
	if err != nil {
		s.log.Warn().Err(err).Strs("containers", names).Msg("Could not scan image")
	}

	now := s.now()
	took := now.Sub(began)

	for _, target := range targets {
		report := newReport(target.Name, target.Image, imageID, result, err, now)

		if err == nil {
			report.ScanSeconds = took.Seconds()
		}

		// A waiting update is still waiting while the container runs the same image.
		if previous, ok := s.store.Get(target.Name); ok {
			if previous.Update != nil && previous.ImageID == imageID {
				report.Update = previous.Update
			}

			if previous.LastUpdate != nil {
				report.LastUpdate = previous.LastUpdate
			}
		}

		s.store.Record(report)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.job.Current = nil
	s.job.CurrentStartedAt = nil
	s.plan.current = ""
	s.job.Done += len(targets)
	s.job.ImagesDone++

	if err != nil {
		s.job.Failed += len(targets)
		s.step(names, "Couldn't scan "+strings.Join(names, ", ")+": "+err.Error(), true)

		return
	}

	// A scan cut short by an error says nothing about how long a full one takes.
	s.plan.taken = append(s.plan.taken, took)
	s.step(names, "Finished "+strings.Join(names, ", ")+" in "+roundDuration(took)+": "+findingsMessage(result), false)
}

// roundDuration formats d to whole seconds, such as "1m12s".
func roundDuration(d time.Duration) string {
	return d.Round(time.Second).String()
}

// startMessage describes a scan as it starts.
//
// Parameters:
//   - containers: Number of containers covered.
//   - images: Number of distinct images among them.
//
// Returns:
//   - string: Sentence for the activity list.
func startMessage(containers, images int) string {
	message := "Started scanning " + plural(containers, "container")
	if images != containers {
		message += " (" + plural(images, "image") + ")"
	}

	return message
}

// findingsMessage summarises a scan result for the activity list.
//
// Parameters:
//   - result: Scan result, possibly nil.
//
// Returns:
//   - string: Number of findings, worst severities first.
func findingsMessage(result *scanner.Result) string {
	if result == nil || len(result.Findings) == 0 {
		return "no findings"
	}

	counts := result.Counts()
	parts := make([]string, 0, 5) //nolint:mnd // One per severity.

	for _, level := range []struct {
		n    int
		name string
	}{
		{counts.Critical, "critical"},
		{counts.High, "high"},
		{counts.Medium, "medium"},
		{counts.Low, "low"},
		{counts.Unknown, "unknown"},
	} {
		if level.n > 0 {
			parts = append(parts, strconv.Itoa(level.n)+" "+level.name)
		}
	}

	return plural(len(result.Findings), "finding") + " (" + strings.Join(parts, ", ") + ")"
}

// plural formats n with noun, adding "s" unless n is 1.
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}

	return strconv.Itoa(n) + " " + noun + "s"
}
