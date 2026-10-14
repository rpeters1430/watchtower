package action

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/distribution/reference"
	"github.com/rs/zerolog"

	dockerContainer "github.com/moby/moby/api/types/container"

	"github.com/nicholas-fedor/watchtower/pkg/container"
	"github.com/nicholas-fedor/watchtower/pkg/types"
)

// Supported container lifecycle action names.
const (
	ActionStart   = "start"
	ActionStop    = "stop"
	ActionRestart = "restart"
	ActionSetTag  = "set_tag"
)

var (
	// ErrContainerNotFound indicates that the requested container was not found.
	ErrContainerNotFound = errors.New("container not found")
	// ErrUnsupportedAction indicates an invalid or unsupported action was requested.
	ErrUnsupportedAction = errors.New("unsupported action")
	// ErrWatchtowerContainer indicates mutation actions cannot be executed on Watchtower itself via this endpoint.
	ErrWatchtowerContainer = errors.New("cannot perform action on Watchtower container")
	// ErrInvalidTag indicates that the provided image tag or reference could not be parsed.
	ErrInvalidTag = errors.New("invalid tag or image reference")
)

// Executor defines the interface for running lifecycle operations on a container.
type Executor interface {
	Execute(ctx context.Context, containerName, action, newImageOrTag string) error
}

// defaultActionTimeout is the stop timeout used when none is configured.
const defaultActionTimeout = 30 * time.Second

// containerExecutor is the concrete implementation of Executor.
type containerExecutor struct {
	client  container.Client
	log     *zerolog.Logger
	timeout time.Duration
}

// NewExecutor creates a new container action Executor.
func NewExecutor(log *zerolog.Logger, client container.Client, timeout time.Duration) Executor {
	if log == nil {
		nop := zerolog.Nop()
		log = &nop
	}

	if timeout <= 0 {
		timeout = defaultActionTimeout
	}

	return &containerExecutor{
		client:  client,
		log:     log,
		timeout: timeout,
	}
}

// Execute performs the requested lifecycle action on the target container.
func (e *containerExecutor) Execute(ctx context.Context, containerName, action, newImageOrTag string) error {
	allContainers, err := e.client.ListContainers(ctx)
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	var target types.Container

	for _, c := range allContainers {
		if c.Name() == containerName || strings.TrimPrefix(c.Name(), "/") == strings.TrimPrefix(containerName, "/") {
			target = c

			break
		}
	}

	if target == nil {
		return fmt.Errorf("%w: %s", ErrContainerNotFound, containerName)
	}

	if target.IsWatchtower() {
		return fmt.Errorf("%w: %s", ErrWatchtowerContainer, containerName)
	}

	switch action {
	case ActionStart:
		return e.start(ctx, target)
	case ActionStop:
		return e.stop(ctx, target)
	case ActionRestart:
		return e.restart(ctx, target)
	case ActionSetTag:
		return e.setTag(ctx, target, newImageOrTag)
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedAction, action)
	}
}

func (e *containerExecutor) start(ctx context.Context, target types.Container) error {
	e.log.Info().
		Str("container", target.Name()).
		Str("id", target.ID().ShortID()).
		Msg("Starting container via API")

	err := e.client.StartContainerByID(ctx, target.ID())
	if err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}

	return nil
}

func (e *containerExecutor) stop(ctx context.Context, target types.Container) error {
	e.log.Info().
		Str("container", target.Name()).
		Str("id", target.ID().ShortID()).
		Msg("Stopping container via API")

	err := e.client.StopContainer(ctx, target, e.timeout)
	if err != nil {
		return fmt.Errorf("failed to stop container: %w", err)
	}

	return nil
}

func (e *containerExecutor) restart(ctx context.Context, target types.Container) error {
	e.log.Info().
		Str("container", target.Name()).
		Str("id", target.ID().ShortID()).
		Msg("Restarting container via API")

	err := e.client.RestartContainer(ctx, target, e.timeout)
	if err != nil {
		return fmt.Errorf("failed to restart container: %w", err)
	}

	return nil
}

// targetContainerWrapper wraps a types.Container and overrides its creation config image.
type targetContainerWrapper struct {
	types.Container

	newImage string
}

// GetCreateConfig returns the source container's Config with the Image field updated.
func (w *targetContainerWrapper) GetCreateConfig() *dockerContainer.Config {
	cfg := w.Container.GetCreateConfig()
	if cfg == nil {
		return &dockerContainer.Config{Image: w.newImage}
	}

	cloned := *cfg
	cloned.Image = w.newImage

	return &cloned
}

// ImageName returns the updated image name.
func (w *targetContainerWrapper) ImageName() string {
	return w.newImage
}

// ResolveNewImage resolves a user-supplied tag or full image reference against the current image.
func ResolveNewImage(currentImage, newImageOrTag string) (string, error) {
	trimmed := strings.TrimSpace(newImageOrTag)
	if trimmed == "" {
		return "", fmt.Errorf("%w: empty tag", ErrInvalidTag)
	}

	// If the user specified a full image name containing '/' or a new repo
	if strings.Contains(trimmed, "/") {
		parsed, err := reference.ParseNormalizedNamed(trimmed)
		if err != nil {
			return "", fmt.Errorf("%w: %w", ErrInvalidTag, err)
		}

		tagged, ok := parsed.(reference.NamedTagged)
		if !ok {
			// Add default tag if missing
			tagged, err = reference.WithTag(parsed, "latest")
			if err != nil {
				return "", fmt.Errorf("%w: %w", ErrInvalidTag, err)
			}
		}

		return tagged.String(), nil
	}

	// If the user supplied only a tag (or repo:tag without slash)
	if strings.Contains(trimmed, ":") {
		// e.g. "alpine:3.19"
		parsed, err := reference.ParseNormalizedNamed(trimmed)
		if err != nil {
			return "", fmt.Errorf("%w: %w", ErrInvalidTag, err)
		}

		return parsed.String(), nil
	}

	// Just a tag (e.g. "latest", "v1.2.3")
	currParsed, err := reference.ParseNormalizedNamed(currentImage)
	if err != nil {
		return "", fmt.Errorf("failed to parse current container image %s: %w", currentImage, err)
	}

	baseName := reference.TrimNamed(currParsed)

	tagged, err := reference.WithTag(baseName, trimmed)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidTag, err)
	}

	return tagged.String(), nil
}

func (e *containerExecutor) setTag(ctx context.Context, target types.Container, newImageOrTag string) error {
	resolvedImage, err := ResolveNewImage(target.ImageName(), newImageOrTag)
	if err != nil {
		return err
	}

	e.log.Info().
		Str("container", target.Name()).
		Str("current_image", target.ImageName()).
		Str("new_image", resolvedImage).
		Msg("Setting new container image tag via API")

	// 1. Pull the new image first before taking down the existing container.
	err = e.client.PullImageByName(ctx, resolvedImage)
	if err != nil {
		return fmt.Errorf("failed to pull image %s: %w", resolvedImage, err)
	}

	wasRunning := target.IsRunning()

	// 2. Stop and remove the existing container.
	err = e.client.StopAndRemoveContainer(ctx, target, e.timeout)
	if err != nil {
		return fmt.Errorf("failed to stop and remove previous container: %w", err)
	}

	// 3. Create the replacement container with the new image.
	wrapper := &targetContainerWrapper{
		Container: target,
		newImage:  resolvedImage,
	}

	newID, err := e.client.CreateContainer(ctx, wrapper)
	if err != nil {
		return fmt.Errorf("failed to create container with new image %s: %w", resolvedImage, err)
	}

	// 4. Start the new container if the previous container was running.
	if wasRunning {
		err = e.client.StartContainerByID(ctx, newID)
		if err != nil {
			return fmt.Errorf("failed to start recreated container %s: %w", newID.ShortID(), err)
		}
	}

	e.log.Info().
		Str("container", target.Name()).
		Str("new_id", newID.ShortID()).
		Str("image", resolvedImage).
		Msg("Successfully updated container image tag and recreated container")

	return nil
}
