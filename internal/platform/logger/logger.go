// Package logger provides a configured structured slog logger.
package logger

import (
	"log/slog"
	"os"
	"strings"

	"github.com/RastBast/ordermesh-/internal/security/pii"
)

// New returns a JSON slog logger at the given level, tagged with the env.
func New(level, env string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	base := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     lvl,
		AddSource: lvl == slog.LevelDebug,
	})

	// Wrap with the PII-scrubbing handler so no raw PII can reach stdout/log
	// aggregation even if a caller logs a free-text message by mistake.
	handler := pii.NewScrubbingHandler(base)

	return slog.New(handler).With(
		slog.String("service", "order-service"),
		slog.String("env", env),
	)
}
