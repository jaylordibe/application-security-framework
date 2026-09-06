//go:build windows

package adapter

import "os/exec"

// setProcessGroup is a no-op on Windows, which has no process groups in the
// POSIX sense. exec.CommandContext still kills the adapter itself on
// cancellation; a grandchild it spawned may outlive it, which is recorded as a
// platform limitation in the threat model rather than papered over here.
func setProcessGroup(cmd *exec.Cmd) {}
