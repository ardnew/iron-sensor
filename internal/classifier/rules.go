package classifier

import (
	"strings"

	"iron-sensor/internal/events"
)

var shells = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "fish": true,
}

var networkTools = map[string]bool{
	"curl": true, "wget": true, "nc": true, "ncat": true, "socat": true,
}

var privEsc = map[string]bool{
	"sudo": true, "su": true, "doas": true,
}

var ptraceTools = map[string]bool{
	"strace": true, "ltrace": true, "gdb": true,
}

var interpreters = map[string]bool{
	"python": true, "python3": true, "ruby": true, "perl": true, "node": true,
}

var packageManagers = map[string]bool{
	"apt": true, "apt-get": true, "pip": true, "pip3": true,
	"npm": true, "yarn": true, "gem": true, "cargo": true,
}

// ProcessRules are evaluated in order; first match wins.
var ProcessRules = []Rule{
	{
		Name:     "privilege_escalation",
		Severity: events.SevAlert,
		Match: func(ev events.Event, _ func(uint32) string) bool {
			return privEsc[ev.Comm]
		},
	},
	{
		Name:     "ptrace_tool",
		Severity: events.SevAlert,
		Match: func(ev events.Event, _ func(uint32) string) bool {
			return ptraceTools[ev.Comm]
		},
	},
	{
		Name:     "network_tool",
		Severity: events.SevWarn,
		Match: func(ev events.Event, _ func(uint32) string) bool {
			return networkTools[ev.Comm]
		},
	},
	{
		Name:     "interpreter_exec",
		Severity: events.SevWarn,
		Match: func(ev events.Event, lookupComm func(uint32) string) bool {
			if !interpreters[ev.Comm] {
				return false
			}
			if ev.PPID == nil {
				return false
			}
			parentComm := lookupComm(*ev.PPID)
			return shells[parentComm]
		},
	},
	{
		Name:     "shell_spawn",
		Severity: events.SevWarn,
		Match: func(ev events.Event, _ func(uint32) string) bool {
			return shells[ev.Comm]
		},
	},
	{
		Name:     "package_manager",
		Severity: events.SevInfo,
		Match: func(ev events.Event, _ func(uint32) string) bool {
			return packageManagers[ev.Comm]
		},
	},
}

// PersistenceRules are checked before FileRules on file events.
// A match re-categorizes the event as "persistence".
var PersistenceRules = []Rule{
	{
		Name:     "ssh_persistence",
		Severity: events.SevAlert,
		Match: func(ev events.Event, _ func(uint32) string) bool {
			return isSSHPersistencePath(ev.Path)
		},
	},
	{
		Name:     "cron_write",
		Severity: events.SevAlert,
		Match: func(ev events.Event, _ func(uint32) string) bool {
			return isWriteFlag(ev.Flags) && isCronPath(ev.Path)
		},
	},
	{
		Name:     "systemd_unit_write",
		Severity: events.SevAlert,
		Match: func(ev events.Event, _ func(uint32) string) bool {
			return isWriteFlag(ev.Flags) && isSystemdUnitPath(ev.Path)
		},
	},
	{
		Name:     "system_profile_write",
		Severity: events.SevAlert,
		Match: func(ev events.Event, _ func(uint32) string) bool {
			return isWriteFlag(ev.Flags) && isSystemProfilePath(ev.Path)
		},
	},
	{
		Name:     "ld_preload_write",
		Severity: events.SevAlert,
		Match: func(ev events.Event, _ func(uint32) string) bool {
			return isWriteFlag(ev.Flags) && isLdPreloadPath(ev.Path)
		},
	},
	{
		Name:     "sudoers_write",
		Severity: events.SevAlert,
		Match: func(ev events.Event, _ func(uint32) string) bool {
			return isWriteFlag(ev.Flags) &&
				(ev.Path == "/etc/sudoers" || strings.HasPrefix(ev.Path, "/etc/sudoers.d/"))
		},
	},
	{
		Name:     "shell_rc_write",
		Severity: events.SevWarn,
		Match: func(ev events.Event, _ func(uint32) string) bool {
			return isWriteFlag(ev.Flags) && isShellRCPath(ev.Path)
		},
	},
	{
		Name:     "xdg_autostart",
		Severity: events.SevWarn,
		Match: func(ev events.Event, _ func(uint32) string) bool {
			return isWriteFlag(ev.Flags) && isXDGAutostartPath(ev.Path)
		},
	},
	{
		Name:     "apt_hook",
		Severity: events.SevWarn,
		Match: func(ev events.Event, _ func(uint32) string) bool {
			return isWriteFlag(ev.Flags) && strings.HasPrefix(ev.Path, "/etc/apt/apt.conf.d/")
		},
	},
	{
		Name:     "npmrc_write",
		Severity: events.SevWarn,
		Match: func(ev events.Event, _ func(uint32) string) bool {
			return isWriteFlag(ev.Flags) && isNpmrcPath(ev.Path)
		},
	},
	{
		Name:     "git_hook_write",
		Severity: events.SevWarn,
		Match: func(ev events.Event, _ func(uint32) string) bool {
			return isWriteFlag(ev.Flags) && isGitHookPath(ev.Path)
		},
	},
}

// FileRules are evaluated in order; first match wins.
// More specific rules come before generic ones.
var FileRules = []Rule{
	{
		Name:     "ssh_key_access",
		Severity: events.SevAlert,
		Match: func(ev events.Event, _ func(uint32) string) bool {
			return isSSHPath(ev.Path)
		},
	},
	{
		Name:     "proc_mem_access",
		Severity: events.SevAlert,
		Match: func(ev events.Event, _ func(uint32) string) bool {
			return isProcMemPath(ev.Path)
		},
	},
	{
		Name:     "docker_socket",
		Severity: events.SevAlert,
		Match: func(ev events.Event, _ func(uint32) string) bool {
			return ev.Path == "/var/run/docker.sock" ||
				strings.HasPrefix(ev.Path, "/run/containerd/")
		},
	},
	{
		Name:     "cgroup_write",
		Severity: events.SevAlert,
		Match: func(ev events.Event, _ func(uint32) string) bool {
			return strings.HasPrefix(ev.Path, "/sys/fs/cgroup/") && isWriteFlag(ev.Flags)
		},
	},
	{
		Name:     "sensitive_file_write",
		Severity: events.SevAlert,
		Match: func(ev events.Event, _ func(uint32) string) bool {
			return isSensitiveFilePath(ev.Path) && isWriteFlag(ev.Flags)
		},
	},
	{
		Name:     "sensitive_file_read",
		Severity: events.SevWarn,
		Match: func(ev events.Event, _ func(uint32) string) bool {
			return isSensitiveFilePath(ev.Path) && !isWriteFlag(ev.Flags)
		},
	},
	{
		Name:     "generic_write",
		Severity: events.SevInfo,
		Match: func(ev events.Event, _ func(uint32) string) bool {
			return isWriteFlag(ev.Flags)
		},
	},
}

func isSSHPath(path string) bool {
	if strings.HasPrefix(path, "/root/.ssh/") || strings.HasPrefix(path, "/root/.ssh") && path == "/root/.ssh" {
		return true
	}
	// /home/<user>/.ssh/
	if strings.HasPrefix(path, "/home/") {
		rest := path[len("/home/"):]
		if idx := strings.Index(rest, "/"); idx >= 0 {
			after := rest[idx:]
			if strings.HasPrefix(after, "/.ssh/") || after == "/.ssh" {
				return true
			}
		}
	}
	return false
}

func isProcMemPath(path string) bool {
	if !strings.HasPrefix(path, "/proc/") {
		return false
	}
	return strings.HasSuffix(path, "/mem") || strings.HasSuffix(path, "/environ")
}

// isSensitiveFilePath checks the sensitive path list (excluding ssh/proc
// which have their own more specific rules).
var sensitivePathPrefixes = []string{
	"/etc/shadow", "/etc/gshadow",
	"/etc/sudoers",
	"/etc/profile", "/etc/environment",
	"/etc/cron.d/", "/etc/cron.daily/", "/etc/cron.hourly/",
	"/etc/systemd/",
}

var sensitivePathExact = []string{
	"/etc/passwd", "/etc/hosts",
}

func isSensitiveFilePath(path string) bool {
	for _, e := range sensitivePathExact {
		if path == e {
			return true
		}
	}
	for _, p := range sensitivePathPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func isWriteFlag(flags string) bool {
	return strings.Contains(flags, "O_WRONLY") ||
		strings.Contains(flags, "O_RDWR") ||
		strings.Contains(flags, "O_CREAT")
}

func isCronPath(path string) bool {
	return strings.HasPrefix(path, "/etc/cron") ||
		strings.HasPrefix(path, "/var/spool/cron/crontabs/") ||
		path == "/etc/anacrontab"
}

func isSystemdUnitPath(path string) bool {
	if strings.HasPrefix(path, "/etc/systemd/") || strings.HasPrefix(path, "/usr/lib/systemd/") {
		return true
	}
	// ~/.config/systemd/
	return strings.Contains(path, "/.config/systemd/")
}

func isShellRCPath(path string) bool {
	shellRCFiles := []string{
		"/.bashrc", "/.bash_profile", "/.profile", "/.bash_logout",
		"/.zshrc", "/.zprofile", "/.pam_environment",
	}
	for _, suffix := range shellRCFiles {
		if strings.HasSuffix(path, suffix) {
			// Must be in a home dir or /root
			if strings.HasPrefix(path, "/home/") || strings.HasPrefix(path, "/root/") {
				return true
			}
		}
	}
	return false
}

func isSystemProfilePath(path string) bool {
	return path == "/etc/profile" ||
		strings.HasPrefix(path, "/etc/profile.d/") ||
		path == "/etc/bash.bashrc" ||
		path == "/etc/environment"
}

func isLdPreloadPath(path string) bool {
	return strings.HasPrefix(path, "/etc/ld.so.conf.d/") ||
		path == "/etc/ld.so.preload"
}

func isSSHPersistencePath(path string) bool {
	// authorized_keys, config, sshd_config
	if strings.HasSuffix(path, "/.ssh/authorized_keys") ||
		strings.HasSuffix(path, "/.ssh/config") {
		return true
	}
	return path == "/etc/ssh/sshd_config"
}

func isXDGAutostartPath(path string) bool {
	return strings.Contains(path, "/.config/autostart/") ||
		strings.HasPrefix(path, "/etc/xdg/autostart/")
}

func isNpmrcPath(path string) bool {
	return strings.HasSuffix(path, "/.npmrc") || path == "/etc/npmrc"
}

func isGitHookPath(path string) bool {
	return strings.Contains(path, "/.git/hooks/")
}
