package logger

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestNewValidLevels(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error"} {
		t.Run(level, func(t *testing.T) {
			log, err := New(level)
			if err != nil {
				t.Fatalf("New(%q): %v", level, err)
			}
			if log == nil {
				t.Fatal("logger is nil")
			}
		})
	}
}

func TestNewInvalidLevel(t *testing.T) {
	_, err := New("not-a-level")
	if err == nil {
		t.Fatal("New succeeded with invalid level, want error")
	}
	if !strings.Contains(err.Error(), "APP_LOG_LEVEL") {
		t.Errorf("error = %q, want mention of APP_LOG_LEVEL", err.Error())
	}
}

func TestNewJSONOutput(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	log := slog.New(handler)
	log.Info("test message", "key", "value")

	line := buf.String()
	var record map[string]any
	if err := json.Unmarshal([]byte(line), &record); err != nil {
		t.Fatalf("output is not valid JSON: %v\nline: %s", err, line)
	}
	if record["msg"] != "test message" {
		t.Errorf("msg = %v, want test message", record["msg"])
	}
	if record["key"] != "value" {
		t.Errorf("key = %v, want value", record["key"])
	}
}
