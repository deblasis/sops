//go:build linux

package plugin

import (
	"os/exec"
	"syscall"
)

func setChildAttrs(cmd *exec.Cmd) {
	// no RLIMIT_CORE=0: syscall.SysProcAttr on linux has no Rlimit field in
	// this Go version, and prlimit via a wrapper is not worth the complexity
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// own process group so a wedged tree can be signalled without hitting
		// sops; die with the host so a killed sops never orphans a key-holding
		// child
		Setpgid: true,
		// Pdeathsig gotcha: the kernel fires it when the forking THREAD dies,
		// not the process, and the Go runtime retires threads, so a healthy
		// child can die spuriously under load. The respawn path self-heals,
		// but this is the prime suspect for rare "partial line" violations on
		// loaded linux CI (see go.dev/issue/27505).
		Pdeathsig: syscall.SIGKILL,
	}
}

func killTree(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) // negative pgid: whole tree
}
