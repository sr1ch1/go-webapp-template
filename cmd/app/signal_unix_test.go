//go:build !windows

package main

import (
	"syscall"
	"testing"
)

// signalShutdown delivers SIGTERM to the test process. signal.Notify in run()
// intercepts it, so the test process survives.
func signalShutdown(t *testing.T) {
	t.Helper()
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("sending SIGTERM: %v", err)
	}
}
