//go:build windows

package plugin

import (
	"context"
	"os/exec"
	"strconv"
	"time"
)

// no SysProcAttr knob for process-group kill on windows: taskkill /T walks the
// child tree instead; Process.Kill is the backstop
func setChildAttrs(cmd *exec.Cmd) {}

func killTree(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	// bounded: a hung taskkill must never hold the host lock indefinitely
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "taskkill", "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid)).Run()
	_ = cmd.Process.Kill()
}
