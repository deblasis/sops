//go:build !windows && !linux

package plugin

import (
	"os/exec"
	"syscall"
)

func setChildAttrs(cmd *exec.Cmd) {
	// darwin/bsd have no Pdeathsig; the pgid at least keeps tree kills clean
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func killTree(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
