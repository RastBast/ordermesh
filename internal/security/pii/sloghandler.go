package pii

import (
	"context"
	"log/slog"
)

// ScrubbingHandler wraps a slog.Handler and runs Scrub over every string
// attribute value and the message before delegating. This is a defence-in-depth
// net: structured fields should already carry masked values, but free-text
// messages and accidental PII are redacted here automatically.
type ScrubbingHandler struct {
	inner slog.Handler
}

// NewScrubbingHandler wraps an existing handler.
func NewScrubbingHandler(inner slog.Handler) *ScrubbingHandler {
	return &ScrubbingHandler{inner: inner}
}

// Enabled implements slog.Handler.
func (h *ScrubbingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle scrubs the message and string attributes, then delegates.
func (h *ScrubbingHandler) Handle(ctx context.Context, r slog.Record) error {
	nr := slog.NewRecord(r.Time, r.Level, Scrub(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		nr.AddAttrs(scrubAttr(a))
		return true
	})
	return h.inner.Handle(ctx, nr)
}

// WithAttrs implements slog.Handler.
func (h *ScrubbingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	scrubbed := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		scrubbed[i] = scrubAttr(a)
	}
	return &ScrubbingHandler{inner: h.inner.WithAttrs(scrubbed)}
}

// WithGroup implements slog.Handler.
func (h *ScrubbingHandler) WithGroup(name string) slog.Handler {
	return &ScrubbingHandler{inner: h.inner.WithGroup(name)}
}

func scrubAttr(a slog.Attr) slog.Attr {
	switch a.Value.Kind() {
	case slog.KindString:
		a.Value = slog.StringValue(Scrub(a.Value.String()))
	case slog.KindGroup:
		grp := a.Value.Group()
		out := make([]slog.Attr, len(grp))
		for i, g := range grp {
			out[i] = scrubAttr(g)
		}
		a.Value = slog.GroupValue(out...)
	}
	return a
}
