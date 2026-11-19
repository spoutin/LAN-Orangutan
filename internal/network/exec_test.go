package network

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestExecHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	mode := os.Getenv("GO_HELPER_MODE")
	switch mode {
	case "ok":
		fmt.Print("helper-output")
		os.Exit(0)
	case "fail":
		os.Exit(2)
	case "sleep":
		time.Sleep(5 * time.Second)
		os.Exit(0)
	}
}

func fakeExecCommand(mode string) func(context.Context, string, ...string) *exec.Cmd {
	return func(ctx context.Context, name string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestExecHelperProcess", "--", name}
		cs = append(cs, args...)
		cmd := exec.CommandContext(ctx, os.Args[0], cs...)
		cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1", "GO_HELPER_MODE="+mode)
		return cmd
	}
}

func TestRunCommandTimeout_SuccessAndFailureAndDeadline(t *testing.T) {
	orig := execCommandContext
	t.Cleanup(func() { execCommandContext = orig })

	execCommandContext = fakeExecCommand("ok")
	out, err := runCommand("dummy")
	if err != nil {
		t.Fatalf("runCommand(ok) unexpected error: %v", err)
	}
	if string(out) != "helper-output" {
		t.Fatalf("runCommand(ok) = %q, want helper-output", string(out))
	}

	execCommandContext = fakeExecCommand("fail")
	if _, err := runCommandTimeout(time.Second, "dummy"); err == nil {
		t.Fatal("runCommandTimeout(fail) expected error, got nil")
	}

	execCommandContext = fakeExecCommand("sleep")
	if _, err := runCommandTimeout(30*time.Millisecond, "dummy"); err == nil {
		t.Fatal("runCommandTimeout(sleep) expected timeout error, got nil")
	}
}
