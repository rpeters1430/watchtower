package security

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"

	"github.com/nicholas-fedor/watchtower/pkg/scanner"
)

// maxActivity caps how many steps a job's activity list keeps.
const maxActivity = 40

// maxConcurrentScans bounds on-demand image scans running at once. The
// reviewer runs one scan at a time anyway, so taking images one by one keeps
// the job's list of images being scanned accurate.
const maxConcurrentScans = 1

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
	// ScannerImage is the scanner container image, shown to users.
	ScannerImage string
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
	return s.options.ScannerImage
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

	job := s.job
	job.Current = slices.Clone(s.job.Current)
	job.Activity = slices.Clone(s.job.Activity)

	return job
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

	at := s.now().UTC()

	if !problem {
		s.job.Step = message
		s.job.StepStartedAt = &at
	}

	s.job.Activity = append(s.job.Activity, Activity{
		At:         at,
		Containers: slices.Clone(names),
		Message:    message,
		Problem:    problem,
	})

	if extra := len(s.job.Activity) - maxActivity; extra > 0 {
		s.job.Activity = slices.Delete(s.job.Activity, 0, extra)
	}
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

	started := s.now().UTC()
	s.job = Job{Running: true, StartedAt: &started, Total: total}
	s.step(nil, startMessage(total, len(order)), false)
	job := s.job
	job.Activity = slices.Clone(s.job.Activity)

	s.mu.Unlock()

	s.log.Info().Int("containers", total).Int("images", len(order)).Msg("Starting security scan")

	go s.run(ctx, order, byImage)

	return job, nil
}

// run scans each image and records a report for every container using it.
func (s *Service) run(ctx context.Context, order []string, byImage map[string][]Target) {
	var group errgroup.Group

	group.SetLimit(maxConcurrentScans)

	for _, imageID := range order {
		targets := byImage[imageID]

		group.Go(func() error {
			names := make([]string, 0, len(targets))
			for _, target := range targets {
				names = append(names, target.Name)
			}

			s.mu.Lock()
			s.job.Current = append(s.job.Current, names...)
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

			for _, target := range targets {
				report := newReport(target.Name, target.Image, imageID, result, err, now)

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
			s.job.Current = slices.DeleteFunc(s.job.Current, func(name string) bool {
				return slices.Contains(names, name)
			})
			s.job.Done += len(targets)

			if err != nil {
				s.job.Failed += len(targets)
				s.step(names, "Couldn't scan "+strings.Join(names, ", ")+": "+err.Error(), true)
			} else {
				s.step(names, "Finished "+strings.Join(names, ", ")+": "+findingsMessage(result), false)
			}
			s.mu.Unlock()

			return nil
		})
	}

	_ = group.Wait()

	finished := s.now().UTC()

	s.mu.Lock()
	s.job.Running = false
	s.job.Current = nil
	s.job.Step = ""
	s.job.StepStartedAt = nil
	s.job.FinishedAt = &finished
	job := s.job
	s.mu.Unlock()

	s.log.Info().Int("containers", job.Total).Int("failed", job.Failed).Msg("Security scan finished")
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
