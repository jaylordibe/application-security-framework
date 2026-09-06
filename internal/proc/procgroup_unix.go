//go:build !windows

package proc

import (
	"os/exec"
	"syscall"
)

// setProcessGroup gives the adapter its own process group.
//
// Without this, an adapter that spawns a child leaves that child running when
// the adapter is killed on timeout. A hung helper holding the stdout pipe open
// would then keep the whole assessment waiting on a process nobody is tracking.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// Negative pid signals the whole group.
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
