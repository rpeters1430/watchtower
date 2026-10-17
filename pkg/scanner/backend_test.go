package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseBackend(t *testing.T) {
	t.Parallel()

	tests := []struct{ input, want string }{
		{"", TrivyName},
		{"trivy", TrivyName},
		{" Grype ", GrypeName},
	}

	for _, test := range tests {
		got, err := ParseBackend(test.input)
		require.NoError(t, err, test.input)
		assert.Equal(t, test.want, got, test.input)
	}

	_, err := ParseBackend("clair")
	require.ErrorIs(t, err, ErrInvalidBackend)
	assert.Equal(t, []string{TrivyName, GrypeName}, Backends())
}

func TestSelectorFollowsChoice(t *testing.T) {
	t.Parallel()

	trivy := &stubScanner{results: map[string]*Result{"img": {Image: "img"}}}
	grype := &stubScanner{results: map[string]*Result{"img": {Image: "img"}}}

	choice := ""
	selector := NewSelector(func() string { return choice }, map[string]Selection{
		TrivyName: {Reviewer: NewReviewer(trivy, GateOff, 0), Image: "aquasec/trivy:latest"},
		GrypeName: {Reviewer: NewReviewer(grype, GateOff, 0), Image: "anchore/grype:latest"},
	})

	// An unset choice falls back to the default scanner.
	assert.Equal(t, "aquasec/trivy:latest", selector.Image())

	_, err := selector.Rescan(t.Context(), "img")
	require.NoError(t, err)
	assert.Equal(t, 1, trivy.calls["img"])

	choice = GrypeName

	assert.Equal(t, "anchore/grype:latest", selector.Image())

	_, err = selector.ReviewUpdate(t.Context(), "img", "img")
	require.NoError(t, err)
	assert.Equal(t, 1, grype.calls["img"], "each scanner keeps its own cache")
	assert.Equal(t, 1, trivy.calls["img"])
}
