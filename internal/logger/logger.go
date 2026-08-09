// Package logger constructs the application logger from configuration.
package logger

import (
	"fmt"
	"log/slog"
	"os"
)

// New builds a JSON slog.Logger configured for the given level string.
func New(level string) (*slog.Logger, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("APP_LOG_LEVEL: %w", err)
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: l})), nil
}
