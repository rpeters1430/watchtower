package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
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
	// Volumes maps named volumes to mount points inside the container.
	Volumes map[string]string
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

	return &DockerRunner{api: api, socket: socket, logger: logger}
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

	_, err = r.api.ContainerStart(ctx, created.ID, dockerClient.ContainerStartOptions{})
	if err != nil {
		return nil, fmt.Errorf("starting scanner container: %w", err)
	}

	exitCode, err := r.wait(ctx, created.ID)
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

// ensureImage pulls the scanner image when the daemon does not have it.
//
// Parameters:
//   - ctx: Context for the inspect and pull.
//   - image: Scanner image reference.
//
// Returns:
//   - error: Non-nil when the image is missing and cannot be pulled.
func (r *DockerRunner) ensureImage(ctx context.Context, image string) error {
	_, err := r.api.ImageInspect(ctx, image)
	if err == nil {
		return nil
	}

	r.logger.Info().Str("image", image).Msg("Pulling scanner image")

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
