package scanner

import (
	"context"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeRunner struct {
	spec   RunSpec
	output []byte
	err    error
}

func (f *fakeRunner) Run(_ context.Context, spec RunSpec) ([]byte, error) {
	f.spec = spec

	return f.output, f.err
}

func TestTrivyScan(t *testing.T) {
	t.Parallel()

	logger := zerolog.Nop()
	runner := &fakeRunner{output: readFixture(t, "trivy-current.json")}
	trivy := NewTrivy(&logger, runner, TrivyOptions{})

	scannedAt := time.Date(2026, 10, 14, 21, 0, 0, 0, time.UTC)
	trivy.now = func() time.Time { return scannedAt }

	result, err := trivy.Scan(t.Context(), "sha256:abc")
	require.NoError(t, err)

	assert.Equal(t, TrivyName, trivy.Name())
	assert.Equal(t, scannedAt, result.ScannedAt)
	assert.Len(t, result.Findings, 4)

	assert.Equal(t, DefaultTrivyImage, runner.spec.Image)
	assert.Equal(t, map[string]string{DefaultTrivyCacheVolume: trivyCacheDir}, runner.spec.Volumes)
	assert.Equal(t, "sha256:abc", runner.spec.Args[len(runner.spec.Args)-1])
	assert.Contains(t, runner.spec.Args, "json")
	assert.NotContains(t, runner.spec.Args, "--ignore-unfixed")
}

func TestTrivyScanOptions(t *testing.T) {
	t.Parallel()

	logger := zerolog.Nop()
	runner := &fakeRunner{output: []byte(`{"SchemaVersion":2}`)}
	trivy := NewTrivy(&logger, runner, TrivyOptions{
		Image:         "mirror.local/trivy:0.67.0",
		CacheVolume:   "my-cache",
		IgnoreUnfixed: true,
	})

	result, err := trivy.Scan(t.Context(), "nginx:latest")
	require.NoError(t, err)

	// A report without ArtifactName falls back to the scanned reference.
	assert.Equal(t, "nginx:latest", result.Image)
	assert.Equal(t, "mirror.local/trivy:0.67.0", runner.spec.Image)
	assert.Contains(t, runner.spec.Volumes, "my-cache")
	assert.Contains(t, runner.spec.Args, "--ignore-unfixed")
}

func TestTrivyScanErrors(t *testing.T) {
	t.Parallel()

	logger := zerolog.Nop()

	_, err := NewTrivy(&logger, &fakeRunner{err: errFake}, TrivyOptions{}).Scan(t.Context(), "nginx")
	require.ErrorIs(t, err, ErrScanFailed)
	require.ErrorIs(t, err, errFake)

	_, err = NewTrivy(&logger, &fakeRunner{output: []byte("oops")}, TrivyOptions{}).Scan(t.Context(), "nginx")
	require.ErrorIs(t, err, ErrInvalidReport)
}
