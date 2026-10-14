package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)

	return data
}

func parseFixture(t *testing.T, name string) *Result {
	t.Helper()

	result, err := ParseTrivyReport(readFixture(t, name))
	require.NoError(t, err)

	return result
}

func TestParseSeverity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   string
		want Severity
	}{
		{"CRITICAL", SeverityCritical},
		{" high ", SeverityHigh},
		{"Medium", SeverityMedium},
		{"low", SeverityLow},
		{"UNKNOWN", SeverityUnknown},
	}

	for _, tt := range tests {
		got, err := ParseSeverity(tt.in)
		require.NoError(t, err, tt.in)
		assert.Equal(t, tt.want, got, tt.in)
	}

	_, err := ParseSeverity("severe")
	require.ErrorIs(t, err, ErrInvalidSeverity)
}

func TestSeverityJSON(t *testing.T) {
	t.Parallel()

	data, err := json.Marshal(Finding{ID: "CVE-1", Severity: SeverityHigh})
	require.NoError(t, err)
	assert.Contains(t, string(data), `"severity":"high"`)

	var decoded Finding
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, SeverityHigh, decoded.Severity)

	assert.Equal(t, "unknown", Severity(42).String())
}

func TestParseTrivyReport(t *testing.T) {
	t.Parallel()

	result := parseFixture(t, "trivy-current.json")

	assert.Equal(t, TrivyName, result.Scanner)
	assert.Equal(t, "0.67.0", result.ScannerVersion)
	assert.Equal(t, "nginx:1.27", result.Image)
	assert.Equal(
		t,
		"sha256:1111111111111111111111111111111111111111111111111111111111111111",
		result.ImageID,
	)

	// The duplicate CVE-2024-0001 row is collapsed and the passed DS026
	// check is left out.
	require.Len(t, result.Findings, 4)

	ids := make([]string, 0, len(result.Findings))
	for _, finding := range result.Findings {
		ids = append(ids, finding.ID)
	}

	assert.Equal(t, []string{"CVE-2024-0001", "CVE-2024-0003", "DS002", "CVE-2024-0002"}, ids)

	critical := result.Findings[0]
	assert.Equal(t, KindVulnerability, critical.Kind)
	assert.Equal(t, "libssl3", critical.Package)
	assert.Equal(t, "3.0.14-1", critical.InstalledVersion)
	assert.Equal(t, "3.0.15-1", critical.FixedVersion)
	assert.True(t, critical.Fixable())
	assert.Equal(t, "https://avd.aquasec.com/nvd/cve-2024-0001", critical.URL)

	misconfig := result.Findings[2]
	assert.Equal(t, KindMisconfiguration, misconfig.Kind)
	assert.Equal(t, "Dockerfile", misconfig.Target)
	assert.Contains(t, misconfig.Resolution, "USER")

	assert.False(t, result.Findings[3].Fixable())

	assert.Equal(t, Counts{Critical: 1, High: 2, Medium: 1}, result.Counts())
	assert.Equal(t, 4, result.Counts().Total())
	assert.Equal(t, SeverityCritical, result.Highest())
}

func TestParseTrivyReportSecrets(t *testing.T) {
	t.Parallel()

	result := parseFixture(t, "trivy-next.json")

	assert.Empty(t, result.ScannerVersion)

	secret := result.Findings[0]
	assert.Equal(t, KindSecret, secret.Kind)
	assert.Equal(t, "aws-access-key-id", secret.ID)
	assert.Equal(t, SeverityCritical, secret.Severity)
	assert.Equal(t, "/app/.env", secret.Target)
}

func TestParseTrivyReportInvalid(t *testing.T) {
	t.Parallel()

	_, err := ParseTrivyReport([]byte("not json"))
	require.ErrorIs(t, err, ErrInvalidReport)

	_, err = ParseTrivyReport([]byte(`{"Results":[]}`))
	require.ErrorIs(t, err, ErrInvalidReport)

	result, err := ParseTrivyReport([]byte(`{"SchemaVersion":2}`))
	require.NoError(t, err)
	assert.Empty(t, result.Findings)
	assert.NotNil(t, result.Findings)
}

func TestParseTrivyReportUnknownSeverity(t *testing.T) {
	t.Parallel()

	result, err := ParseTrivyReport([]byte(`{"SchemaVersion":2,"Results":[{"Vulnerabilities":[
		{"VulnerabilityID":"CVE-1","PkgName":"a","Severity":"NEGLIGIBLE"}]}]}`))
	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, SeverityUnknown, result.Findings[0].Severity)
}

func TestNilResult(t *testing.T) {
	t.Parallel()

	var result *Result

	assert.Equal(t, Counts{}, result.Counts())
	assert.Equal(t, SeverityUnknown, result.Highest())
}
