package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/rs/zerolog"

	dockerContainer "github.com/moby/moby/api/types/container"
	dockerClient "github.com/moby/moby/client"
)

// DefaultDockerSocket is the Docker socket mounted into scanner containers so
// they can read images from the local daemon.
const DefaultDockerSocket = "/var/run/docker.sock"

// maxReportBytes caps how much scanner output is read, so a runaway scanner
// cannot exhaust Watchtower's memory.
const maxReportBytes = 64 << 20

// maxStderrBytes caps the scanner error output kept for error messages.
const maxStderrBytes = 4 << 10

// cleanupTimeout bounds removing a scanner container after its run.
const cleanupTimeout = 30 * time.Second

// ImageRefreshInterval is how often a scanner image that is already present
// is pulled again, so a tag such as "latest" picks up new scanner releases.
// An image pinned by digest is never pulled again.
const ImageRefreshInterval = 24 * time.Hour

// Labels set on every scanner container. The enable label keeps Watchtower
// from treating its own scanner containers as update candidates.
const (
	enableLabel  = "com.centurylinklabs.watchtower.enable"
	scannerLabel = "com.centurylinklabs.watchtower.scanner"
)

var (
	// ErrScannerExited indicates the scanner container exited with a non-zero code.
	ErrScannerExited = errors.New("scanner exited with an error")
	// ErrScannerWait indicates the daemon reported an error while waiting for the scanner.
	ErrScannerWait = errors.New("waiting for scanner container failed")
	// ErrReportTooLarge indicates the scanner output exceeded maxReportBytes.
	ErrReportTooLarge = errors.New("scanner report too large")
)

// RunSpec describes one scanner container run.
type RunSpec struct {
	// Image is the scanner image.
	Image string
	// Args are passed to the image entrypoint.
	Args []string
	// Env holds "KEY=value" environment variables for the scanner.
	Env []string
	// Volumes maps named volumes to mount points inside the container.
	Volumes map[string]string
	// Log, when set and the context carries a ProgressFunc, receives each
	// line the scanner writes to standard error while it runs.
	Log func(ctx context.Context, line string)
}

// Runner runs a scanner to completion and returns its standard output.
type Runner interface {
	Run(ctx context.Context, spec RunSpec) ([]byte, error)
}

// dockerAPI is the subset of the Docker client the runner uses.
type dockerAPI interface {
	ImageInspect(
		ctx context.Context,
		imageID string,
		opts ...dockerClient.ImageInspectOption,
	) (dockerClient.ImageInspectResult, error)
	ImagePull(
		ctx context.Context,
		ref string,
		options dockerClient.ImagePullOptions,
	) (dockerClient.ImagePullResponse, error)
	ImageRemove(
		ctx context.Context,
		imageID string,
		options dockerClient.ImageRemoveOptions,
	) (dockerClient.ImageRemoveResult, error)
	ContainerCreate(
		ctx context.Context,
		options dockerClient.ContainerCreateOptions,
	) (dockerClient.ContainerCreateResult, error)
	ContainerStart(
		ctx context.Context,
		containerID string,
		options dockerClient.ContainerStartOptions,
	) (dockerClient.ContainerStartResult, error)
	ContainerWait(
		ctx context.Context,
		containerID string,
		options dockerClient.ContainerWaitOptions,
	) dockerClient.ContainerWaitResult
	ContainerLogs(
		ctx context.Context,
		containerID string,
		options dockerClient.ContainerLogsOptions,
	) (dockerClient.ContainerLogsResult, error)
	ContainerRemove(
		ctx context.Context,
		containerID string,
		options dockerClient.ContainerRemoveOptions,
	) (dockerClient.ContainerRemoveResult, error)
}

// DockerRunner runs scanners as short-lived containers on the same Docker
// daemon Watchtower manages, with the daemon socket mounted so the scanner
// can read local images without pulling them again.
type DockerRunner struct {
	api    dockerAPI
	socket string
	logger *zerolog.Logger
	now    func() time.Time

	mu sync.Mutex
	// pulled records when each scanner image was last pulled or checked.
	pulled map[string]time.Time
}

// NewDockerRunner creates a runner on a Docker client.
//
// Parameters:
//   - logger: Logger for container lifecycle messages.
//   - api: Docker client.
//   - socket: Host path of the Docker socket to mount. Empty means DefaultDockerSocket.
//
// Returns:
//   - *DockerRunner: Runner.
func NewDockerRunner(logger *zerolog.Logger, api dockerAPI, socket string) *DockerRunner {
	if socket == "" {
		socket = DefaultDockerSocket
	}

	return &DockerRunner{
		api:    api,
		socket: socket,
		logger: logger,
		now:    time.Now,
		pulled: make(map[string]time.Time),
	}
}

// Run pulls the scanner image if it is missing, runs it, waits for it to
// exit, and returns its standard output. The container is always removed.
//
// Parameters:
//   - ctx: Context bounding the run; cancellation stops waiting and removes the container.
//   - spec: Scanner image, arguments, and volumes.
//
// Returns:
//   - []byte: Standard output.
//   - error: Non-nil when the image, container, or scanner fails.
func (r *DockerRunner) Run(ctx context.Context, spec RunSpec) ([]byte, error) {
	err := r.ensureImage(ctx, spec.Image)
	if err != nil {
		return nil, err
	}

	binds := []string{r.socket + ":" + DefaultDockerSocket}
	for volume, target := range spec.Volumes {
		binds = append(binds, volume+":"+target)
	}

	created, err := r.api.ContainerCreate(ctx, dockerClient.ContainerCreateOptions{
		Config: &dockerContainer.Config{
			Image: spec.Image,
			Cmd:   spec.Args,
			Env:   spec.Env,
			Labels: map[string]string{
				enableLabel:  "false",
				scannerLabel: "true",
			},
		},
		HostConfig: &dockerContainer.HostConfig{
			Binds: binds,
			// Read the report back through the logs API, which needs a
			// driver that supports reading regardless of the daemon default.
			LogConfig: dockerContainer.LogConfig{Type: "json-file"},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("creating scanner container: %w", err)
	}

	defer r.remove(context.WithoutCancel(ctx), created.ID)

	ReportProgress(ctx, "Starting the scanner")

	_, err = r.api.ContainerStart(ctx, created.ID, dockerClient.ContainerStartOptions{})
	if err != nil {
		return nil, fmt.Errorf("starting scanner container: %w", err)
	}

	stopFollowing := r.follow(ctx, created.ID, spec.Log)
	exitCode, err := r.wait(ctx, created.ID)

	stopFollowing()

	if err != nil {
		return nil, err
	}

	stdout, stderr, err := r.logs(ctx, created.ID)
	if err != nil {
		return nil, err
	}

	if exitCode != 0 {
		return nil, fmt.Errorf(
			"%w: exit code %d: %s",
			ErrScannerExited,
			exitCode,
			strings.TrimSpace(tail(stderr, maxStderrBytes)),
		)
	}

	return stdout, nil
}

// ensureImage pulls the scanner image when the daemon does not have it, and
// pulls it again once ImageRefreshInterval has passed since the last pull, so
// a tag such as "latest" stays on the newest scanner release. When a refresh
// fails, the image already present is used.
//
// Parameters:
//   - ctx: Context for the inspect and pull.
//   - image: Scanner image reference.
//
// Returns:
//   - error: Non-nil when the image is missing and cannot be pulled.
func (r *DockerRunner) ensureImage(ctx context.Context, image string) error {
	inspected, err := r.api.ImageInspect(ctx, image)
	present := err == nil

	if present && !r.refreshDue(image) {
		return nil
	}

	if present {
		r.logger.Debug().Str("image", image).Msg("Checking for a newer scanner image")
		ReportProgress(ctx, "Checking for a newer version of the scanner image "+image)
	} else {
		r.logger.Info().Str("image", image).Msg("Pulling scanner image")
		ReportProgress(ctx, "Downloading the scanner image "+image)
	}

	err = r.pull(ctx, image)

	// A failed refresh is retried after the next interval, not on every scan.
	r.markPulled(image)

	if err != nil {
		if !present {
			return err
		}

		r.logger.Warn().
			Err(err).
			Str("image", image).
			Msg("Could not check for a newer scanner image, using the one already present")

		return nil
	}

	if present {
		r.removeSuperseded(ctx, image, inspected.ID)
	}

	return nil
}

// pull pulls the scanner image and waits for the pull to finish.
//
// Parameters:
//   - ctx: Context for the pull.
//   - image: Scanner image reference.
//
// Returns:
//   - error: Non-nil when the pull fails.
func (r *DockerRunner) pull(ctx context.Context, image string) error {
	response, err := r.api.ImagePull(ctx, image, dockerClient.ImagePullOptions{})
	if err != nil {
		return fmt.Errorf("pulling scanner image %s: %w", image, err)
	}

	defer response.Close()

	err = response.Wait(ctx)
	if err != nil {
		return fmt.Errorf("pulling scanner image %s: %w", image, err)
	}

	return nil
}

// refreshDue reports whether a present scanner image should be pulled again.
//
// Parameters:
//   - image: Scanner image reference.
//
// Returns:
//   - bool: True when the image is referenced by tag and was not pulled
//     within ImageRefreshInterval by this runner.
func (r *DockerRunner) refreshDue(image string) bool {
	// A digest names one image for good, so there is nothing newer to fetch.
	if strings.Contains(image, "@") {
		return false
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	last, ok := r.pulled[image]

	return !ok || r.now().Sub(last) >= ImageRefreshInterval
}

// markPulled records that image was just pulled or checked.
//
// Parameters:
//   - image: Scanner image reference.
func (r *DockerRunner) markPulled(image string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.pulled[image] = r.now()
}

// removeSuperseded removes the scanner image a refresh replaced, so each
// scanner release does not leave an untagged image behind. A failure only
// leaves the old image in place.
//
// Parameters:
//   - ctx: Context for the inspect and removal.
//   - image: Scanner image reference.
//   - previousID: Image ID the reference named before the pull.
func (r *DockerRunner) removeSuperseded(ctx context.Context, image, previousID string) {
	current, err := r.api.ImageInspect(ctx, image)
	if err != nil || previousID == "" || current.ID == previousID {
		return
	}

	r.logger.Info().
		Str("image", image).
		Str("previous_id", previousID).
		Str("image_id", current.ID).
		Msg("Updated scanner image")
	ReportProgress(ctx, "Updated the scanner image "+image)

	_, err = r.api.ImageRemove(ctx, previousID, dockerClient.ImageRemoveOptions{PruneChildren: true})
	if err != nil {
		r.logger.Debug().Err(err).Str("image_id", previousID).Msg("Could not remove the previous scanner image")
	}
}

// wait blocks until the container exits or ctx ends.
//
// Parameters:
//   - ctx: Context bounding the wait.
//   - containerID: Scanner container ID.
//
// Returns:
//   - int64: Container exit code.
//   - error: Non-nil when waiting fails or ctx ends first.
func (r *DockerRunner) wait(ctx context.Context, containerID string) (int64, error) {
	waited := r.api.ContainerWait(ctx, containerID, dockerClient.ContainerWaitOptions{
		Condition: dockerContainer.WaitConditionNotRunning,
	})

	select {
	case response := <-waited.Result:
		if response.Error != nil && response.Error.Message != "" {
			return 0, fmt.Errorf("%w: %s", ErrScannerWait, response.Error.Message)
		}

		return response.StatusCode, nil
	case err := <-waited.Error:
		return 0, fmt.Errorf("waiting for scanner container: %w", err)
	case <-ctx.Done():
		return 0, fmt.Errorf("waiting for scanner container: %w", ctx.Err())
	}
}

// follow passes each line the running scanner writes to standard error to
// onLine, so a long scan can say what it is doing. It does nothing unless the
// context carries a ProgressFunc. A failure to follow only loses progress
// steps; the report is still read after the scanner exits.
//
// Parameters:
//   - ctx: Context bounding the scan.
//   - containerID: Scanner container ID.
//   - onLine: Receives each line, or nil for none.
//
// Returns:
//   - func(): Stops following and waits for the reader to finish.
func (r *DockerRunner) follow(
	ctx context.Context,
	containerID string,
	onLine func(ctx context.Context, line string),
) func() {
	if onLine == nil || !hasProgress(ctx) {
		return func() {}
	}

	followCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})

	go func() {
		defer close(done)

		reader, err := r.api.ContainerLogs(followCtx, containerID, dockerClient.ContainerLogsOptions{
			ShowStderr: true,
			Follow:     true,
		})
		if err != nil {
			r.logger.Debug().Err(err).Msg("Could not follow scanner output")

			return
		}

		defer reader.Close()

		lines := &lineWriter{fn: func(line string) { onLine(ctx, line) }}
		_, _ = stdcopy.StdCopy(io.Discard, lines, io.LimitReader(reader, maxReportBytes))
	}()

	return func() {
		cancel()
		<-done
	}
}

// logs reads the container's standard output and error.
//
// Parameters:
//   - ctx: Context for the logs request.
//   - containerID: Scanner container ID.
//
// Returns:
//   - []byte: Standard output.
//   - string: Standard error.
//   - error: Non-nil when the logs cannot be read or exceed maxReportBytes.
func (r *DockerRunner) logs(ctx context.Context, containerID string) ([]byte, string, error) {
	reader, err := r.api.ContainerLogs(ctx, containerID, dockerClient.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
	})
	if err != nil {
		return nil, "", fmt.Errorf("reading scanner output: %w", err)
	}

	defer reader.Close()

	var stdout, stderr bytes.Buffer

	_, err = stdcopy.StdCopy(&stdout, &stderr, io.LimitReader(reader, maxReportBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("reading scanner output: %w", err)
	}

	if stdout.Len()+stderr.Len() > maxReportBytes {
		return nil, "", ErrReportTooLarge
	}

	return stdout.Bytes(), stderr.String(), nil
}

// remove force-removes the scanner container. Callers pass a context
// detached from the scan's cancellation so cleanup still happens after a
// timeout.
//
// Parameters:
//   - ctx: Context without the scan's deadline.
//   - containerID: Scanner container ID.
func (r *DockerRunner) remove(ctx context.Context, containerID string) {
	ctx, cancel := context.WithTimeout(ctx, cleanupTimeout)
	defer cancel()

	_, err := r.api.ContainerRemove(ctx, containerID, dockerClient.ContainerRemoveOptions{
		Force:         true,
		RemoveVolumes: false,
	})
	if err != nil {
		r.logger.Warn().
			Err(err).
			Str("container_id", containerID).
			Msg("Failed to remove scanner container")
	}
}

// tail returns at most limit bytes from the end of s.
//
// Parameters:
//   - s: Text to trim.
//   - limit: Maximum length in bytes.
//
// Returns:
//   - string: The end of s.
func tail(s string, limit int) string {
	if len(s) <= limit {
		return s
	}

	return s[len(s)-limit:]
}

// NewDockerAPI creates a Docker client from the same DOCKER_HOST,
// DOCKER_TLS_VERIFY, DOCKER_CERT_PATH, and DOCKER_API_VERSION settings
// Watchtower's own client uses.
//
// Returns:
//   - *dockerClient.Client: Docker client with API version negotiation.
//   - error: Non-nil when the environment settings are invalid.
func NewDockerAPI() (*dockerClient.Client, error) {
	cli, err := dockerClient.New(dockerClient.FromEnv)
	if err != nil {
		return nil, fmt.Errorf("creating Docker client for scanner: %w", err)
	}

	return cli, nil
}
