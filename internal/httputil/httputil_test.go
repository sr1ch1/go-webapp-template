package httputil

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestIDRoundTrip(t *testing.T) {
	ctx := context.Background()
	if got := RequestIDFromContext(ctx); got != "" {
		t.Errorf("RequestIDFromContext(empty) = %q, want empty", got)
	}

	ctx = WithRequestID(ctx, "abc-123")
	if got := RequestIDFromContext(ctx); got != "abc-123" {
		t.Errorf("RequestIDFromContext = %q, want abc-123", got)
	}
}

func TestIsRequestEntityTooLarge(t *testing.T) {
	maxErr := &http.MaxBytesError{Limit: 100}
	if !IsRequestEntityTooLarge(maxErr) {
		t.Error("IsRequestEntityTooLarge(MaxBytesError) = false, want true")
	}
	if IsRequestEntityTooLarge(errors.New("some other error")) {
		t.Error("IsRequestEntityTooLarge(other) = true, want false")
	}
	if IsRequestEntityTooLarge(nil) {
		t.Error("IsRequestEntityTooLarge(nil) = true, want false")
	}
}

func TestWriteProblem(t *testing.T) {
	t.Run("with detail", func(t *testing.T) {
		rec := httptest.NewRecorder()
		WriteProblem(rec, http.StatusBadRequest, "Bad Request", "missing field")

		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
		}
		if got := rec.Header().Get("Content-Type"); got != "application/problem+json" {
			t.Errorf("Content-Type = %q, want application/problem+json", got)
		}

		body, _ := io.ReadAll(rec.Body)
		var problem map[string]any
		if err := json.Unmarshal(body, &problem); err != nil {
			t.Fatalf("decoding body: %v", err)
		}
		want := map[string]any{
			"type":   "about:blank",
			"title":  "Bad Request",
			"status": float64(http.StatusBadRequest),
			"detail": "missing field",
		}
		for k, v := range want {
			if problem[k] != v {
				t.Errorf("problem[%q] = %v, want %v", k, problem[k], v)
			}
		}
	})

	t.Run("without detail", func(t *testing.T) {
		rec := httptest.NewRecorder()
		WriteProblem(rec, http.StatusUnauthorized, "Unauthorized", "")

		body, _ := io.ReadAll(rec.Body)
		var problem map[string]any
		if err := json.Unmarshal(body, &problem); err != nil {
			t.Fatalf("decoding body: %v", err)
		}
		if _, ok := problem["detail"]; ok {
			t.Errorf("problem must not contain detail when empty, got %v", problem)
		}
	})

	t.Run("json terminates with newline", func(t *testing.T) {
		rec := httptest.NewRecorder()
		WriteProblem(rec, http.StatusTeapot, "I'm a teapot", "")
		if !bytes.HasSuffix(rec.Body.Bytes(), []byte("\n")) {
			t.Error("problem JSON should end with newline")
		}
	})
}
