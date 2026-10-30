package tags

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	// versionPattern extracts (prefix)(digits.digits...)(suffix).
	// Examples:
	//   "v1.2.3" -> prefix "v", nums "1.2.3", suffix ""
	//   "15.2-alpine" -> prefix "", nums "15.2", suffix "-alpine"
	//   "python:3.11-slim" tag "3.11-slim" -> prefix "", nums "3.11", suffix "-slim"
	//   "node:20.10.0-alpine3.18" tag "20.10.0-alpine3.18" -> prefix "", nums "20.10.0", suffix "-alpine3.18"
	versionPattern = regexp.MustCompile(`^([a-zA-Z_\-]*?)(\d+(?:\.\d+)*)(.*)$`)
)

// Non-version tags that should never be treated as version pins.
var unversionedTags = map[string]struct{}{
	"latest":    {},
	"edge":      {},
	"master":    {},
	"main":      {},
	"nightly":   {},
	"dev":       {},
	"stable":    {},
	"canary":    {},
	"test":      {},
	"testing":   {},
	"default":   {},
}

// ParsedTag represents a structured breakdown of an image tag.
type ParsedTag struct {
	Original string
	Prefix   string
	Numbers  []int
	Suffix   string
}

// IsVersioned reports whether tag represents a versioned release rather than a rolling/branch tag.
func IsVersioned(tag string) bool {
	trimmed := strings.ToLower(strings.TrimSpace(tag))
	if trimmed == "" {
		return false
	}

	if _, ok := unversionedTags[trimmed]; ok {
		return false
	}

	pt, ok := ParseTag(tag)
	if !ok {
		return false
	}

	return len(pt.Numbers) > 0
}

// ParseTag decomposes a tag into prefix, numeric components, and suffix.
func ParseTag(tag string) (*ParsedTag, bool) {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return nil, false
	}

	m := versionPattern.FindStringSubmatch(tag)
	if len(m) < 4 {
		return nil, false
	}

	prefix := m[1]
	numStr := m[2]
	suffix := m[3]

	numParts := strings.Split(numStr, ".")
	numbers := make([]int, 0, len(numParts))

	for _, p := range numParts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, false
		}

		numbers = append(numbers, n)
	}

	if len(numbers) == 0 {
		return nil, false
	}

	return &ParsedTag{
		Original: tag,
		Prefix:   prefix,
		Numbers:  numbers,
		Suffix:   suffix,
	}, true
}

// MatchesVariant reports whether candidate matches base's prefix and suffix structure.
func (pt *ParsedTag) MatchesVariant(candidate *ParsedTag) bool {
	if candidate == nil {
		return false
	}

	// Case-insensitive prefix and suffix match
	return strings.EqualFold(pt.Prefix, candidate.Prefix) &&
		strings.EqualFold(pt.Suffix, candidate.Suffix)
}

// Compare returns -1 if pt < other, 0 if pt == other, and 1 if pt > other.
func (pt *ParsedTag) Compare(other *ParsedTag) int {
	if other == nil {
		return 1
	}

	maxLen := len(pt.Numbers)
	if len(other.Numbers) > maxLen {
		maxLen = len(other.Numbers)
	}

	for i := 0; i < maxLen; i++ {
		a := 0
		if i < len(pt.Numbers) {
			a = pt.Numbers[i]
		}

		b := 0
		if i < len(other.Numbers) {
			b = other.Numbers[i]
		}

		if a < b {
			return -1
		}

		if a > b {
			return 1
		}
	}

	return 0
}

// FindNewerVersions finds tags in availableTags that are newer than currentTag
// while matching the same variant / flavor (e.g. -alpine, -slim, or pure semver).
// Results are returned in descending order (highest version first).
func FindNewerVersions(currentTag string, availableTags []string) []string {
	current, ok := ParseTag(currentTag)
	if !ok || len(current.Numbers) == 0 {
		return nil
	}

	type match struct {
		parsed *ParsedTag
	}

	var matches []match

	seen := make(map[string]bool)

	for _, raw := range availableTags {
		if raw == currentTag || seen[raw] {
			continue
		}

		parsed, ok := ParseTag(raw)
		if !ok {
			continue
		}

		// Must match the same variant / flavor (e.g. -alpine with -alpine)
		if !current.MatchesVariant(parsed) {
			continue
		}

		// Avoid alpha/beta/rc unless current tag itself is alpha/beta/rc
		currIsPre := strings.Contains(strings.ToLower(current.Suffix), "rc") ||
			strings.Contains(strings.ToLower(current.Suffix), "beta") ||
			strings.Contains(strings.ToLower(current.Suffix), "alpha")

		candIsPre := strings.Contains(strings.ToLower(parsed.Suffix), "rc") ||
			strings.Contains(strings.ToLower(parsed.Suffix), "beta") ||
			strings.Contains(strings.ToLower(parsed.Suffix), "alpha")

		if candIsPre && !currIsPre {
			continue
		}

		// Must be strictly greater than current version
		if parsed.Compare(current) > 0 {
			seen[raw] = true
			matches = append(matches, match{parsed: parsed})
		}
	}

	if len(matches) == 0 {
		return nil
	}

	// Sort descending (highest version first)
	sort.Slice(matches, func(i, j int) bool {
		cmp := matches[i].parsed.Compare(matches[j].parsed)
		if cmp != 0 {
			return cmp > 0
		}

		return matches[i].parsed.Original > matches[j].parsed.Original
	})

	results := make([]string, 0, len(matches))
	for _, m := range matches {
		results = append(results, m.parsed.Original)
	}

	return results
}

// GetLatestNewerVersion returns the newest available version tag greater than currentTag,
// or empty string and false if none exist.
func GetLatestNewerVersion(currentTag string, availableTags []string) (string, bool) {
	newer := FindNewerVersions(currentTag, availableTags)
	if len(newer) == 0 {
		return "", false
	}

	return newer[0], true
}
