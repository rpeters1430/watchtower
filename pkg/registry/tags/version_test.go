package tags

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsVersioned(t *testing.T) {
	assert.False(t, IsVersioned("latest"))
	assert.False(t, IsVersioned("edge"))
	assert.False(t, IsVersioned("dev"))
	assert.False(t, IsVersioned("master"))
	assert.False(t, IsVersioned(""))

	assert.True(t, IsVersioned("15.2"))
	assert.True(t, IsVersioned("15.2-alpine"))
	assert.True(t, IsVersioned("v1.2.3"))
	assert.True(t, IsVersioned("3.11-slim"))
	assert.True(t, IsVersioned("20.10.0-alpine3.18"))
}

func TestParseTag(t *testing.T) {
	pt, ok := ParseTag("v1.2.3")
	require.True(t, ok)
	assert.Equal(t, "v", pt.Prefix)
	assert.Equal(t, []int{1, 2, 3}, pt.Numbers)
	assert.Equal(t, "", pt.Suffix)

	pt, ok = ParseTag("15.2-alpine")
	require.True(t, ok)
	assert.Equal(t, "", pt.Prefix)
	assert.Equal(t, []int{15, 2}, pt.Numbers)
	assert.Equal(t, "-alpine", pt.Suffix)

	pt, ok = ParseTag("node:20.10.0-alpine3.18")
	// If only tag component is passed:
	pt, ok = ParseTag("20.10.0-alpine3.18")
	require.True(t, ok)
	assert.Equal(t, "", pt.Prefix)
	assert.Equal(t, []int{20, 10, 0}, pt.Numbers)
	assert.Equal(t, "-alpine3.18", pt.Suffix)
}

func TestFindNewerVersions(t *testing.T) {
	t.Run("alpine variants", func(t *testing.T) {
		tags := []string{
			"14.9-alpine",
			"15.1-alpine",
			"15.2-alpine",
			"15.3-alpine",
			"16.0-alpine",
			"16.1-alpine",
			"16.1-bullseye",
			"latest",
		}

		newer := FindNewerVersions("15.2-alpine", tags)
		expected := []string{"16.1-alpine", "16.0-alpine", "15.3-alpine"}
		assert.Equal(t, expected, newer)

		latest, ok := GetLatestNewerVersion("15.2-alpine", tags)
		assert.True(t, ok)
		assert.Equal(t, "16.1-alpine", latest)
	})

	t.Run("semver with v prefix", func(t *testing.T) {
		tags := []string{
			"v1.0.0",
			"v1.1.0",
			"v1.2.0",
			"1.3.0", // different prefix, should be ignored
			"v2.0.0",
		}

		newer := FindNewerVersions("v1.1.0", tags)
		assert.Equal(t, []string{"v2.0.0", "v1.2.0"}, newer)
	})

	t.Run("already latest version", func(t *testing.T) {
		tags := []string{"1.0.0", "1.1.0", "1.2.0"}
		newer := FindNewerVersions("1.2.0", tags)
		assert.Empty(t, newer)

		_, ok := GetLatestNewerVersion("1.2.0", tags)
		assert.False(t, ok)
	})
}
