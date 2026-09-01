package main_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// build compiles padl once for the tests below.
func build(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping build in short mode")
	}
	out := filepath.Join(t.TempDir(), "padl")
	if runtime.GOOS == "windows" {
		out += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", out, ".")
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, combined)
	}
	return out
}

// A terminal PADL cannot drive must produce a message and a non-zero exit.
//
// It used to panic with "close of nil channel" instead: main opened the screen
// and handed it to tview.SetScreen, which discards the Init error, so the
// failure only surfaced as a crash on shutdown. TERM=dumb is a terminal that
// exists but cannot be addressed, which fails the same way whether or not a
// tty is attached.
func TestUndrivableTerminalFailsWithAMessage(t *testing.T) {
	padl := build(t)

	cmd := exec.Command(padl)
	cmd.Env = append(os.Environ(), "TERM=dumb")
	cmd.Stdin = strings.NewReader("")
	stderr := &strings.Builder{}
	cmd.Stderr = stderr

	err := cmd.Run()
	if err == nil {
		t.Fatalf("expected a non-zero exit, got success; stderr: %s", stderr)
	}
	var exit *exec.ExitError
	if !asExitError(err, &exit) {
		t.Fatalf("expected an exit error, got %T: %v", err, err)
	}
	if code := exit.ExitCode(); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}

	got := stderr.String()
	if !strings.Contains(got, "open terminal") {
		t.Errorf("stderr should say the terminal could not be opened, got: %q", got)
	}
	for _, crash := range []string{"panic:", "goroutine", "nil channel"} {
		if strings.Contains(got, crash) {
			t.Errorf("this should be a message, not a crash; stderr contains %q:\n%s", crash, got)
		}
	}
}

// The flags that do not need a terminal must keep working without one.
func TestVersionAndPathsNeedNoTerminal(t *testing.T) {
	padl := build(t)

	for _, flag := range []string{"-version", "-paths"} {
		cmd := exec.Command(padl, flag)
		cmd.Env = append(os.Environ(), "TERM=dumb")
		cmd.Stdin = strings.NewReader("")
		out, err := cmd.Output()
		if err != nil {
			t.Errorf("%s: %v", flag, err)
			continue
		}
		if len(strings.TrimSpace(string(out))) == 0 {
			t.Errorf("%s printed nothing", flag)
		}
	}
}

func asExitError(err error, target **exec.ExitError) bool {
	e, ok := err.(*exec.ExitError)
	if ok {
		*target = e
	}
	return ok
}
