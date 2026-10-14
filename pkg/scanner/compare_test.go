package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func findingIDs(findings []Finding) []string {
	ids := make([]string, 0, len(findings))
	for _, finding := range findings {
		ids = append(ids, finding.ID)
	}

	return ids
}

func TestCompare(t *testing.T) {
	t.Parallel()

	current := parseFixture(t, "trivy-current.json")
	next := parseFixture(t, "trivy-next.json")

	diff := Compare(current, next)

	assert.Equal(t, []string{"CVE-2024-0001", "CVE-2024-0003"}, findingIDs(diff.Fixed))
	assert.Equal(t, []string{"aws-access-key-id", "CVE-2024-0004"}, findingIDs(diff.Introduced))
	// The vulnerability target changes with the OS release (debian 12.7 to
	// 12.8) but CVE-2024-0002 still counts as the same finding.
	assert.Equal(t, []string{"DS002", "CVE-2024-0002"}, findingIDs(diff.Remaining))
}

func TestCompareNil(t *testing.T) {
	t.Parallel()

	next := parseFixture(t, "trivy-next.json")

	diff := Compare(nil, next)
	assert.Empty(t, diff.Fixed)
	assert.Len(t, diff.Introduced, len(next.Findings))
	assert.Empty(t, diff.Remaining)

	diff = Compare(next, nil)
	assert.Len(t, diff.Fixed, len(next.Findings))
	assert.Empty(t, diff.Introduced)

	diff = Compare(nil, nil)
	assert.Empty(t, diff.Fixed)
	assert.Empty(t, diff.Introduced)
	assert.Empty(t, diff.Remaining)
}

func TestCompareSamePackageDifferentCVE(t *testing.T) {
	t.Parallel()

	current := &Result{Findings: []Finding{
		{ID: "CVE-1", Kind: KindVulnerability, Package: "openssl"},
		{ID: "CVE-1", Kind: KindVulnerability, Package: "libssl3"},
	}}
	next := &Result{Findings: []Finding{
		{ID: "CVE-1", Kind: KindVulnerability, Package: "libssl3"},
	}}

	diff := Compare(current, next)
	require.Len(t, diff.Fixed, 1)
	assert.Equal(t, "openssl", diff.Fixed[0].Package)
}

func TestDiffBlocks(t *testing.T) {
	t.Parallel()

	current := parseFixture(t, "trivy-current.json")
	next := parseFixture(t, "trivy-next.json")
	diff := Compare(current, next)

	// The new image introduces a critical secret and a high CVE.
	assert.False(t, diff.Blocks(GateOff))
	assert.True(t, diff.Blocks(GateCritical))
	assert.True(t, diff.Blocks(GateHigh))
	assert.True(t, diff.Blocks(GateLow))

	// Going back to the older image would bring back its critical CVE, so a
	// critical gate holds that too.
	reverse := Compare(next, current)
	assert.True(t, reverse.Blocks(GateCritical))

	// Shared findings never block, however severe.
	same := Compare(current, current)
	assert.False(t, same.Blocks(GateLow))

	assert.False(t, Diff{}.Blocks(Gate("bogus")))
}

func TestParseGate(t *testing.T) {
	t.Parallel()

	for in, want := range map[string]Gate{
		"":         GateOff,
		"off":      GateOff,
		"Critical": GateCritical,
		"HIGH":     GateHigh,
		"medium":   GateMedium,
		"low":      GateLow,
	} {
		got, err := ParseGate(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}

	padded, err := ParseGate("  high ")
	require.NoError(t, err)
	assert.Equal(t, GateHigh, padded)

	_, err = ParseGate("unknown")
	require.ErrorIs(t, err, ErrInvalidGate)
}
