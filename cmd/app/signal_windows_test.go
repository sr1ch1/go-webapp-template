//go:build windows

package main

import "testing"

// signalShutdown exists so TestRunStartsAndShutsDown compiles on Windows. It
// is never called: the test skips itself before reaching it, since Windows
// cannot self-deliver SIGTERM (no syscall.Kill; os.Interrupt delivery is
// unimplemented).
func signalShutdown(t *testing.T) {
	t.Helper()
	t.Fatal("unreachable: TestRunStartsAndShutsDown skips on Windows")
}
