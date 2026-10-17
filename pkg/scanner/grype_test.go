package scanner

import (
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGrypeScan(t *testing.T) {
	t.Parallel()

	logger := zerolog.Nop()
	runner := &fakeRunner{output: readFixture(t, "grype-report.json")}
	grype := NewGrype(&logger, runner, GrypeOptions{})

	scannedAt := time.Date(2026, 10, 17, 6, 0, 0, 0, time.UTC)
	grype.now = func() time.Time { return scannedAt }

	result, err := grype.Scan(t.Context(), "sha256:abc")
	require.NoError(t, err)

	assert.Equal(t, GrypeName, grype.Name())
	assert.Equal(t, GrypeName, result.Scanner)
	assert.Equal(t, "0.120.1", result.ScannerVersion)
	assert.Equal(t, "sha256:abc", result.Image)
	assert.Equal(t, scannedAt, result.ScannedAt)

	assert.Equal(t, DefaultGrypeImage, runner.spec.Image)
	assert.Equal(t, map[string]string{DefaultGrypeCacheVolume: grypeCacheDir}, runner.spec.Volumes)
	assert.Contains(t, runner.spec.Env, "GRYPE_DB_CACHE_DIR="+grypeCacheDir)
	assert.Equal(t, []string{"--from", "docker", "--output", "json", "sha256:abc"}, runner.spec.Args)
}

func TestGrypeScanOptions(t *testing.T) {
	t.Parallel()

	logger := zerolog.Nop()
	runner := &fakeRunner{output: []byte(`{"matches":[],"descriptor":{"name":"grype","version":"0.120.1"}}`)}
	grype := NewGrype(&logger, runner, GrypeOptions{
		Image:         "mirror.local/grype:v0.120.1",
		CacheVolume:   "my-cache",
		IgnoreUnfixed: true,
	})

	result, err := grype.Scan(t.Context(), "nginx:latest")
	require.NoError(t, err)

	assert.Empty(t, result.Findings)
	assert.NotNil(t, result.Findings)
	assert.Equal(t, "mirror.local/grype:v0.120.1", grype.Image())
	assert.Equal(t, "mirror.local/grype:v0.120.1", runner.spec.Image)
	assert.Contains(t, runner.spec.Volumes, "my-cache")
	assert.Contains(t, runner.spec.Args, "--only-fixed")
}

func TestGrypeScanErrors(t *testing.T) {
	t.Parallel()

	logger := zerolog.Nop()

	_, err := NewGrype(&logger, &fakeRunner{err: errFake}, GrypeOptions{}).Scan(t.Context(), "nginx")
	require.ErrorIs(t, err, ErrScanFailed)
	require.ErrorIs(t, err, errFake)

	_, err = NewGrype(&logger, &fakeRunner{output: []byte("oops")}, GrypeOptions{}).Scan(t.Context(), "nginx")
	require.ErrorIs(t, err, ErrInvalidReport)

	// A Trivy report is not mistaken for an empty Grype one.
	_, err = NewGrype(&logger, &fakeRunner{output: readFixture(t, "trivy-current.json")}, GrypeOptions{}).
		Scan(t.Context(), "nginx")
	require.ErrorIs(t, err, ErrInvalidReport)
}

func TestParseGrypeReport(t *testing.T) {
	t.Parallel()

	result, err := ParseGrypeReport(readFixture(t, "grype-report.json"))
	require.NoError(t, err)

	// The repeated busybox match is dropped.
	require.Len(t, result.Findings, 7)
	assert.Equal(t, Counts{High: 1, Medium: 3, Low: 3}, result.Counts())

	worst := result.Findings[0]
	assert.Equal(t, "CVE-2026-40200", worst.ID)
	assert.Equal(t, KindVulnerability, worst.Kind)
	assert.Equal(t, SeverityHigh, worst.Severity)
	assert.Equal(t, "musl", worst.Package)
	assert.Equal(t, "1.2.4-r3", worst.FixedVersion)
	assert.True(t, worst.Fixable())
	assert.Equal(t, "/lib/apk/db/installed", worst.Target)
	assert.NotEmpty(t, worst.URL)
	assert.NotEmpty(t, worst.Title)
	assert.LessOrEqual(t, len([]rune(worst.Title)), maxTitleLength+1)

	var negligible Finding

	for _, finding := range result.Findings {
		if finding.ID == "GHSA-test-negl-igib" {
			negligible = finding
		}

		if finding.ID != worst.ID {
			assert.False(t, finding.Fixable(), "%s has no published fix", finding.ID)
		}
	}

	assert.Equal(t, SeverityLow, negligible.Severity, "negligible counts as low")
	assert.Equal(t, "A related advisory describes the problem.", negligible.Title)
}

func TestGrypeStep(t *testing.T) {
	t.Parallel()

	tests := []struct {
		line string
		want string
	}{
		{"[0001]  INFO downloading new vulnerability DB", "Downloading the vulnerability database"},
		{"[0105]  INFO installed new vulnerability DB built=2026-10-16T06:29:51Z version=v6.1.10", "Loading the vulnerability database"},
		{"[0000]  INFO docker saved image from=stereoscope image=sha256:abc", "Reading the image's layers"},
		{"[0001]  INFO using distro: alpine 3.18.12", "Reading the image's operating system packages"},
		{"[0001]  INFO gathered packages packages=15 time=1.7s", "Matching packages against the vulnerability database"},
		{"[0000]  WARN unable to check for vulnerability database update", "Scanner warning: unable to check for vulnerability database update"},
		{"[0002]  INFO task completed elapsed=151.7µs from=syft task=environment-cataloger", ""},
		{`15 packages from EOL distro "alpine 3.18.12"`, ""},
		{"", ""},
	}

	for _, test := range tests {
		assert.Equal(t, test.want, GrypeStep(test.line), test.line)
	}
}

func TestFirstSentence(t *testing.T) {
	t.Parallel()

	assert.Empty(t, firstSentence("", 10))
	assert.Equal(t, "Short one.", firstSentence("Short one. Then more.", 40))
	assert.Equal(t, "Words that…", firstSentence("Words that run, past the limit", 12))
}
