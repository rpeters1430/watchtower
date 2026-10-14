package scanner

// Diff is what changes between the findings of a running image and the
// findings of the image that would replace it.
type Diff struct {
	// Fixed are findings in the current image that the new image no longer has.
	Fixed []Finding `json:"fixed"`
	// Introduced are findings the new image has that the current image does not.
	Introduced []Finding `json:"introduced"`
	// Remaining are findings both images share, as reported for the new image.
	Remaining []Finding `json:"remaining"`
}

// Compare reports which findings an update from current to next fixes,
// introduces, and leaves in place. Either result may be nil, which counts as
// an image with no known findings.
//
// Parameters:
//   - current: Scan of the running image.
//   - next: Scan of the image the update would switch to.
//
// Returns:
//   - Diff: Findings fixed, introduced, and remaining, each sorted worst first.
func Compare(current, next *Result) Diff {
	currentByKey := indexFindings(current)
	nextByKey := indexFindings(next)

	var diff Diff

	if current != nil {
		for _, finding := range current.Findings {
			if _, ok := nextByKey[finding.Key()]; !ok {
				diff.Fixed = append(diff.Fixed, finding)
			}
		}
	}

	if next != nil {
		for _, finding := range next.Findings {
			if _, ok := currentByKey[finding.Key()]; ok {
				diff.Remaining = append(diff.Remaining, finding)
			} else {
				diff.Introduced = append(diff.Introduced, finding)
			}
		}
	}

	diff.Fixed = dedupe(diff.Fixed)
	diff.Introduced = dedupe(diff.Introduced)
	diff.Remaining = dedupe(diff.Remaining)

	SortFindings(diff.Fixed)
	SortFindings(diff.Introduced)
	SortFindings(diff.Remaining)

	return diff
}

// Blocks reports whether the severity gate should hold back the update: the
// new image introduces at least one finding at or above the gate severity.
// Findings both images share never block, since skipping the update would
// not remove them.
//
// Parameters:
//   - gate: Lowest severity that holds an update. GateOff never blocks.
//
// Returns:
//   - bool: True when the update should be held.
func (d Diff) Blocks(gate Gate) bool {
	threshold, enabled := gate.Threshold()
	if !enabled {
		return false
	}

	for _, finding := range d.Introduced {
		if finding.Severity >= threshold {
			return true
		}
	}

	return false
}

// indexFindings maps each finding key in a result to the finding.
//
// Parameters:
//   - result: Scan result, possibly nil.
//
// Returns:
//   - map[string]Finding: Findings by Key.
func indexFindings(result *Result) map[string]Finding {
	if result == nil {
		return map[string]Finding{}
	}

	index := make(map[string]Finding, len(result.Findings))
	for _, finding := range result.Findings {
		index[finding.Key()] = finding
	}

	return index
}

// dedupe drops repeated findings, which scanners emit when the same package
// appears in several layers or targets.
//
// Parameters:
//   - findings: Findings in report order.
//
// Returns:
//   - []Finding: First occurrence of each key.
func dedupe(findings []Finding) []Finding {
	if len(findings) == 0 {
		return findings
	}

	seen := make(map[string]struct{}, len(findings))
	out := findings[:0]

	for _, finding := range findings {
		key := finding.Key()
		if _, ok := seen[key]; ok {
			continue
		}

		seen[key] = struct{}{}

		out = append(out, finding)
	}

	return out
}
