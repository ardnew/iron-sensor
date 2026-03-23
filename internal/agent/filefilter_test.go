package agent

import (
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsWriteOpen(t *testing.T) {
	require.False(t, isWriteOpen(syscall.O_RDONLY))
	require.True(t, isWriteOpen(syscall.O_WRONLY))
	require.True(t, isWriteOpen(syscall.O_RDWR))
	require.True(t, isWriteOpen(syscall.O_RDONLY|syscall.O_CREAT))
}

func TestIsSensitivePath(t *testing.T) {
	require.True(t, isSensitivePath("/etc/passwd"))
	require.True(t, isSensitivePath("/etc/shadow"))
	require.True(t, isSensitivePath("/etc/sudoers.d/custom"))
	require.True(t, isSensitivePath("/root/.ssh/authorized_keys"))
	require.True(t, isSensitivePath("/home/user/.ssh/id_rsa"))
	require.True(t, isSensitivePath("/proc/1234/environ"))
	require.True(t, isSensitivePath("/proc/1/mem"))
	require.True(t, isSensitivePath("/var/run/docker.sock"))

	require.False(t, isSensitivePath("/tmp/foo"))
	require.False(t, isSensitivePath("/etc/hostname"))
	require.False(t, isSensitivePath("/home/user/code/main.go"))
}

func TestShouldEmitFileEvent(t *testing.T) {
	// Write to any path — yes.
	require.True(t, shouldEmitFileEvent("/tmp/foo", syscall.O_WRONLY))
	// Read of sensitive path — yes.
	require.True(t, shouldEmitFileEvent("/etc/passwd", syscall.O_RDONLY))
	// Read of non-sensitive path — no.
	require.False(t, shouldEmitFileEvent("/tmp/foo", syscall.O_RDONLY))
}

func TestFormatFlags(t *testing.T) {
	require.Equal(t, "O_RDONLY", FormatFlags(syscall.O_RDONLY))
	require.Equal(t, "O_WRONLY", FormatFlags(syscall.O_WRONLY))
	require.Equal(t, "O_RDWR|O_CREAT|O_TRUNC", FormatFlags(syscall.O_RDWR|syscall.O_CREAT|syscall.O_TRUNC))
}
