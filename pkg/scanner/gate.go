package scanner

import (
	"errors"
	"fmt"
	"strings"
)

// Gate is the lowest severity of a newly introduced finding that holds back
// an update. GateOff, the default, never holds one.
type Gate string

// Gate values.
const (
	GateOff      Gate = "off"
	GateLow      Gate = "low"
	GateMedium   Gate = "medium"
	GateHigh     Gate = "high"
	GateCritical Gate = "critical"
)

// ErrInvalidGate indicates a gate value is not off or a severity name.
var ErrInvalidGate = errors.New("invalid scan gate")

// ParseGate parses a gate value, ignoring case. An empty value means GateOff.
//
// Parameters:
//   - value: "off", "low", "medium", "high", or "critical".
//
// Returns:
//   - Gate: Parsed gate.
//   - error: Non-nil when the value is not recognized.
func ParseGate(value string) (Gate, error) {
	normalized := Gate(strings.ToLower(strings.TrimSpace(value)))

	switch normalized {
	case "", GateOff:
		return GateOff, nil
	case GateLow, GateMedium, GateHigh, GateCritical:
		return normalized, nil
	default:
		return GateOff, fmt.Errorf(
			"%w: %q (want off, low, medium, high, or critical)",
			ErrInvalidGate,
			value,
		)
	}
}

// Threshold returns the gate's severity.
//
// Returns:
//   - Severity: Lowest severity that holds an update.
//   - bool: False when the gate is off or unrecognized.
func (g Gate) Threshold() (Severity, bool) {
	switch g {
	case GateLow:
		return SeverityLow, true
	case GateMedium:
		return SeverityMedium, true
	case GateHigh:
		return SeverityHigh, true
	case GateCritical:
		return SeverityCritical, true
	case GateOff:
		return SeverityUnknown, false
	default:
		return SeverityUnknown, false
	}
}
