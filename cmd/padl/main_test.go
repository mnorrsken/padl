package main_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// runPadl runs the binary with a deadline, so a build that starts successfully
// when the test expected it to fail cannot sit there until the whole package
// times out.
func runPadl(t *testing.T, padl string, env []string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, padl, args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdin = strings.NewReader("")
	var out, errOut strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errOut

	err = cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("padl %v did not exit within 30s; it should have failed immediately", args)
	}
	return out.String(), errOut.String(), err
}

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
// failure only surfaced as a crash on shutdown.
//
// Unix only. TERM=dumb is a terminal that exists but cannot be addressed, and
// tcell refuses it — but on Windows tcell talks to the console API and ignores
// TERM entirely, so there is no equivalent broken terminal to point it at. The
// regression this guards is a terminfo/tty one, which is where it is tested.
func TestUndrivableTerminalFailsWithAMessage(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("tcell uses the Windows console API and ignores TERM; no undrivable terminal to test with")
	}
	padl := build(t)

	_, stderr, err := runPadl(t, padl, []string{"TERM=dumb"})
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

	if !strings.Contains(stderr, "open terminal") {
		t.Errorf("stderr should say the terminal could not be opened, got: %q", stderr)
	}
	for _, crash := range []string{"panic:", "goroutine", "nil channel"} {
		if strings.Contains(stderr, crash) {
			t.Errorf("this should be a message, not a crash; stderr contains %q:\n%s", crash, stderr)
		}
	}
}

// The flags that do not need a terminal must keep working without one.
func TestVersionAndPathsNeedNoTerminal(t *testing.T) {
	padl := build(t)

	for _, flag := range []string{"-version", "-paths"} {
		out, stderr, err := runPadl(t, padl, []string{"TERM=dumb"}, flag)
		if err != nil {
			t.Errorf("%s: %v (stderr: %s)", flag, err, stderr)
			continue
		}
		if len(strings.TrimSpace(out)) == 0 {
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
