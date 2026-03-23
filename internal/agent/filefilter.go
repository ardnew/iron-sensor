package agent

import (
	"strings"
	"syscall"
)

// sensitivePrefixes are path prefixes where even read-only opens are reported.
var sensitivePrefixes = []string{
	"/etc/shadow",
	"/etc/gshadow",
	"/etc/sudoers",
	"/etc/sudoers.d/",
	"/etc/profile",
	"/etc/profile.d/",
	"/etc/environment",
	"/etc/cron.d/",
	"/etc/cron.daily/",
	"/etc/cron.hourly/",
	"/etc/systemd/",
	"/root/.ssh/",
	"/dev/mem",
	"/dev/kmem",
	"/sys/fs/cgroup/",
	"/var/run/docker.sock",
	"/run/containerd/",
}

// sensitiveExact are exact paths where even read-only opens are reported.
var sensitiveExact = []string{
	"/etc/passwd",
	"/etc/hosts",
}

// sensitiveGlobs are patterns with a wildcard component.
// Checked by splitting on * and matching prefix/suffix.
var sensitiveGlobs = []struct {
	prefix string
	suffix string
}{
	{"/home/", "/.ssh/"},
	{"/proc/", "/mem"},
	{"/proc/", "/environ"},
}

// isWriteOpen returns true if the flags indicate a write or create.
func isWriteOpen(flags int32) bool {
	mode := flags & syscall.O_ACCMODE
	return mode == syscall.O_WRONLY || mode == syscall.O_RDWR ||
		flags&syscall.O_CREAT != 0
}

// isSensitivePath returns true if path matches the sensitive read list.
func isSensitivePath(path string) bool {
	for _, exact := range sensitiveExact {
		if path == exact {
			return true
		}
	}
	for _, prefix := range sensitivePrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	for _, g := range sensitiveGlobs {
		if strings.HasPrefix(path, g.prefix) && strings.Contains(path[len(g.prefix):], g.suffix) {
			return true
		}
	}
	return false
}

// shouldEmitFileEvent returns true if this open should be reported.
func shouldEmitFileEvent(path string, flags int32) bool {
	return isWriteOpen(flags) || isSensitivePath(path)
}

// FormatFlags returns a human-readable representation of open flags.
func FormatFlags(flags int32) string {
	var parts []string
	mode := flags & syscall.O_ACCMODE
	switch mode {
	case syscall.O_RDONLY:
		parts = append(parts, "O_RDONLY")
	case syscall.O_WRONLY:
		parts = append(parts, "O_WRONLY")
	case syscall.O_RDWR:
		parts = append(parts, "O_RDWR")
	}
	if flags&syscall.O_CREAT != 0 {
		parts = append(parts, "O_CREAT")
	}
	if flags&syscall.O_TRUNC != 0 {
		parts = append(parts, "O_TRUNC")
	}
	if flags&syscall.O_APPEND != 0 {
		parts = append(parts, "O_APPEND")
	}
	if flags&syscall.O_EXCL != 0 {
		parts = append(parts, "O_EXCL")
	}
	if len(parts) == 0 {
		return "O_RDONLY"
	}
	return strings.Join(parts, "|")
}
