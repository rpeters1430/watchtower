package scanner

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"iter"
	"testing"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/jsonstream"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dockerContainer "github.com/moby/moby/api/types/container"
	dockerClient "github.com/moby/moby/client"
)

var errFake = errors.New("fake docker error")

// frame encodes one multiplexed log frame as the Docker logs API sends it.
func frame(stream stdcopy.StdType, payload string) []byte {
	const headerLen = 8

	buf := make([]byte, headerLen+len(payload))
	buf[0] = byte(stream)
	binary.BigEndian.PutUint32(buf[4:headerLen], uint32(len(payload)))
	copy(buf[headerLen:], payload)

	return buf
}

type fakePull struct {
	io.ReadCloser

	err error
}

func (p fakePull) JSONMessages(context.Context) iter.Seq2[jsonstream.Message, error] {
	return func(func(jsonstream.Message, error) bool) {}
}

func (p fakePull) Wait(context.Context) error { return p.err }

type fakeDocker struct {
	hasImage  bool
	pulled    []string
	pullErr   error
	createErr error
	created   dockerClient.ContainerCreateOptions
	startErr  error
	exitCode  int64
	block     bool
	logs      []byte
	removed   []string
}

func (f *fakeDocker) ImageInspect(
	context.Context,
	string,
	...dockerClient.ImageInspectOption,
) (dockerClient.ImageInspectResult, error) {
	if f.hasImage {
		return dockerClient.ImageInspectResult{}, nil
	}

	return dockerClient.ImageInspectResult{}, errFake
}

func (f *fakeDocker) ImagePull(
	_ context.Context,
	ref string,
	_ dockerClient.ImagePullOptions,
) (dockerClient.ImagePullResponse, error) {
	f.pulled = append(f.pulled, ref)

	return fakePull{ReadCloser: io.NopCloser(bytes.NewReader(nil)), err: f.pullErr}, nil
}

func (f *fakeDocker) ContainerCreate(
	_ context.Context,
	options dockerClient.ContainerCreateOptions,
) (dockerClient.ContainerCreateResult, error) {
	f.created = options
	if f.createErr != nil {
		return dockerClient.ContainerCreateResult{}, f.createErr
	}

	return dockerClient.ContainerCreateResult{ID: "scanner-1"}, nil
}

func (f *fakeDocker) ContainerStart(
	context.Context,
	string,
	dockerClient.ContainerStartOptions,
) (dockerClient.ContainerStartResult, error) {
	return dockerClient.ContainerStartResult{}, f.startErr
}

func (f *fakeDocker) ContainerWait(
	context.Context,
	string,
	dockerClient.ContainerWaitOptions,
) dockerClient.ContainerWaitResult {
	result := make(chan dockerContainer.WaitResponse, 1)
	if !f.block {
		result <- dockerContainer.WaitResponse{StatusCode: f.exitCode}
	}

	return dockerClient.ContainerWaitResult{Result: result, Error: make(chan error)}
}

func (f *fakeDocker) ContainerLogs(
	context.Context,
	string,
	dockerClient.ContainerLogsOptions,
) (dockerClient.ContainerLogsResult, error) {
	return io.NopCloser(bytes.NewReader(f.logs)), nil
}

func (f *fakeDocker) ContainerRemove(
	_ context.Context,
	containerID string,
	_ dockerClient.ContainerRemoveOptions,
) (dockerClient.ContainerRemoveResult, error) {
	f.removed = append(f.removed, containerID)

	return dockerClient.ContainerRemoveResult{}, nil
}

func newTestRunner(api *fakeDocker) *DockerRunner {
	logger := zerolog.Nop()

	return NewDockerRunner(&logger, api, "")
}

func TestDockerRunnerRun(t *testing.T) {
	t.Parallel()

	api := &fakeDocker{
		logs: append(frame(stdcopy.Stdout, `{"SchemaVersion":2}`), frame(stdcopy.Stderr, "progress")...),
	}

	out, err := newTestRunner(api).Run(t.Context(), RunSpec{
		Image:   "aquasec/trivy:latest",
		Args:    []string{"image", "nginx"},
		Volumes: map[string]string{"cache": "/root/.cache/trivy"},
	})
	require.NoError(t, err)
	assert.JSONEq(t, `{"SchemaVersion":2}`, string(out))

	assert.Equal(t, []string{"aquasec/trivy:latest"}, api.pulled)
	assert.Equal(t, "aquasec/trivy:latest", api.created.Config.Image)
	assert.Equal(t, []string{"image", "nginx"}, api.created.Config.Cmd)
	assert.Equal(t, "false", api.created.Config.Labels[enableLabel])
	assert.ElementsMatch(
		t,
		[]string{"/var/run/docker.sock:/var/run/docker.sock", "cache:/root/.cache/trivy"},
		api.created.HostConfig.Binds,
	)
	assert.Equal(t, []string{"scanner-1"}, api.removed)
}

func TestDockerRunnerSkipsPullWhenPresent(t *testing.T) {
	t.Parallel()

	api := &fakeDocker{hasImage: true, logs: frame(stdcopy.Stdout, "{}")}

	_, err := newTestRunner(api).Run(t.Context(), RunSpec{Image: "trivy"})
	require.NoError(t, err)
	assert.Empty(t, api.pulled)
}

func TestDockerRunnerErrors(t *testing.T) {
	t.Parallel()

	t.Run("pull fails", func(t *testing.T) {
		t.Parallel()

		api := &fakeDocker{pullErr: errFake}
		_, err := newTestRunner(api).Run(t.Context(), RunSpec{Image: "trivy"})
		require.ErrorIs(t, err, errFake)
		assert.Empty(t, api.removed)
	})

	t.Run("create fails", func(t *testing.T) {
		t.Parallel()

		api := &fakeDocker{hasImage: true, createErr: errFake}
		_, err := newTestRunner(api).Run(t.Context(), RunSpec{Image: "trivy"})
		require.ErrorIs(t, err, errFake)
	})

	t.Run("start fails and container is removed", func(t *testing.T) {
		t.Parallel()

		api := &fakeDocker{hasImage: true, startErr: errFake}
		_, err := newTestRunner(api).Run(t.Context(), RunSpec{Image: "trivy"})
		require.ErrorIs(t, err, errFake)
		assert.Equal(t, []string{"scanner-1"}, api.removed)
	})

	t.Run("non-zero exit carries stderr", func(t *testing.T) {
		t.Parallel()

		api := &fakeDocker{
			hasImage: true,
			exitCode: 1,
			logs:     frame(stdcopy.Stderr, "FATAL unable to find the specified image"),
		}
		_, err := newTestRunner(api).Run(t.Context(), RunSpec{Image: "trivy"})
		require.ErrorIs(t, err, ErrScannerExited)
		assert.Contains(t, err.Error(), "unable to find the specified image")
		assert.Equal(t, []string{"scanner-1"}, api.removed)
	})

	t.Run("timeout removes container", func(t *testing.T) {
		t.Parallel()

		api := &fakeDocker{hasImage: true, block: true}

		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
		defer cancel()

		_, err := newTestRunner(api).Run(ctx, RunSpec{Image: "trivy"})
		require.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Equal(t, []string{"scanner-1"}, api.removed)
	})
}

func TestTail(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "abc", tail("abc", 5))
	assert.Equal(t, "cde", tail("abcde", 3))
}
