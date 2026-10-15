package scanner

import (
	"bytes"
	"context"
)

// maxProgressLine caps how much of one scanner output line is kept while
// waiting for its end, so a line without a newline cannot grow without bound.
const maxProgressLine = 4 << 10

// ProgressFunc receives a short, human-readable description of what a scan
// is doing right now, such as "Downloading the vulnerability database".
type ProgressFunc func(step string)

// progressKey is the context key holding a ProgressFunc.
type progressKey struct{}

// WithProgress returns a context whose scans report each step to fn.
//
// Parameters:
//   - ctx: Parent context.
//   - fn: Receives each step. Calls come from the scanning goroutine and
//     from a log reader, so fn must be safe for concurrent use.
//
// Returns:
//   - context.Context: Context carrying fn.
func WithProgress(ctx context.Context, fn ProgressFunc) context.Context {
	return context.WithValue(ctx, progressKey{}, fn)
}

// ReportProgress passes step to the context's ProgressFunc, if any.
//
// Parameters:
//   - ctx: Context that may carry a ProgressFunc.
//   - step: What the scan is doing.
func ReportProgress(ctx context.Context, step string) {
	if fn, ok := ctx.Value(progressKey{}).(ProgressFunc); ok && fn != nil && step != "" {
		fn(step)
	}
}

// hasProgress reports whether the context carries a ProgressFunc.
//
// Parameters:
//   - ctx: Context to check.
//
// Returns:
//   - bool: True when steps are being reported.
func hasProgress(ctx context.Context) bool {
	fn, ok := ctx.Value(progressKey{}).(ProgressFunc)

	return ok && fn != nil
}

// lineWriter splits written bytes into lines and passes each to fn.
type lineWriter struct {
	fn      func(line string)
	pending []byte
}

// Write implements io.Writer.
//
// Parameters:
//   - p: Bytes to split into lines.
//
// Returns:
//   - int: Always len(p).
//   - error: Always nil.
func (w *lineWriter) Write(p []byte) (int, error) {
	data := p

	for {
		end := bytes.IndexByte(data, '\n')
		if end < 0 {
			break
		}

		w.pending = append(w.pending, data[:end]...)
		w.flush()

		data = data[end+1:]
	}

	if room := maxProgressLine - len(w.pending); room > 0 {
		w.pending = append(w.pending, data[:min(len(data), room)]...)
	}

	return len(p), nil
}

// flush passes the pending line to fn and clears it.
func (w *lineWriter) flush() {
	line := string(bytes.TrimRight(w.pending, "\r"))
	w.pending = w.pending[:0]

	if line != "" {
		w.fn(line)
	}
}
