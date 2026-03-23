package classifier

import (
	"testing"

	"iron-sensor/internal/events"

	"github.com/stretchr/testify/require"
)

func TestPersistence_CronWrite(t *testing.T) {
	c := New(nil)
	ev := events.Event{Category: "file", Severity: events.SevInfo, Path: "/etc/cron.d/backdoor", Flags: "O_WRONLY|O_CREAT"}
	ev = c.Classify(ev, noopLookup)
	require.Equal(t, "persistence", ev.Category)
	require.Equal(t, events.SevAlert, ev.Severity)
	require.Equal(t, "cron_write", ev.RuleMatched)
}

func TestPersistence_SystemdUnitWrite(t *testing.T) {
	c := New(nil)
	ev := events.Event{Category: "file", Severity: events.SevInfo, Path: "/etc/systemd/system/backdoor.service", Flags: "O_WRONLY|O_CREAT"}
	ev = c.Classify(ev, noopLookup)
	require.Equal(t, "persistence", ev.Category)
	require.Equal(t, events.SevAlert, ev.Severity)
	require.Equal(t, "systemd_unit_write", ev.RuleMatched)
}

func TestPersistence_ShellRCWrite(t *testing.T) {
	c := New(nil)
	ev := events.Event{Category: "file", Severity: events.SevInfo, Path: "/home/user/.bashrc", Flags: "O_WRONLY"}
	ev = c.Classify(ev, noopLookup)
	require.Equal(t, "persistence", ev.Category)
	require.Equal(t, events.SevWarn, ev.Severity)
	require.Equal(t, "shell_rc_write", ev.RuleMatched)
}

func TestPersistence_SSHAuthorizedKeys(t *testing.T) {
	c := New(nil)
	ev := events.Event{Category: "file", Severity: events.SevInfo, Path: "/home/user/.ssh/authorized_keys", Flags: "O_RDONLY"}
	ev = c.Classify(ev, noopLookup)
	require.Equal(t, "persistence", ev.Category)
	require.Equal(t, events.SevAlert, ev.Severity)
	require.Equal(t, "ssh_persistence", ev.RuleMatched)
}

func TestPersistence_SSHDConfig(t *testing.T) {
	c := New(nil)
	ev := events.Event{Category: "file", Severity: events.SevInfo, Path: "/etc/ssh/sshd_config", Flags: "O_WRONLY"}
	ev = c.Classify(ev, noopLookup)
	require.Equal(t, "persistence", ev.Category)
	require.Equal(t, events.SevAlert, ev.Severity)
	require.Equal(t, "ssh_persistence", ev.RuleMatched)
}

func TestPersistence_LdPreload(t *testing.T) {
	c := New(nil)
	ev := events.Event{Category: "file", Severity: events.SevInfo, Path: "/etc/ld.so.preload", Flags: "O_WRONLY|O_CREAT"}
	ev = c.Classify(ev, noopLookup)
	require.Equal(t, "persistence", ev.Category)
	require.Equal(t, events.SevAlert, ev.Severity)
	require.Equal(t, "ld_preload_write", ev.RuleMatched)
}

func TestPersistence_SudoersWrite(t *testing.T) {
	c := New(nil)
	ev := events.Event{Category: "file", Severity: events.SevInfo, Path: "/etc/sudoers.d/backdoor", Flags: "O_WRONLY|O_CREAT"}
	ev = c.Classify(ev, noopLookup)
	require.Equal(t, "persistence", ev.Category)
	require.Equal(t, events.SevAlert, ev.Severity)
	require.Equal(t, "sudoers_write", ev.RuleMatched)
}

func TestPersistence_GitHookWrite(t *testing.T) {
	c := New(nil)
	ev := events.Event{Category: "file", Severity: events.SevInfo, Path: "/home/user/repo/.git/hooks/pre-commit", Flags: "O_WRONLY|O_CREAT"}
	ev = c.Classify(ev, noopLookup)
	require.Equal(t, "persistence", ev.Category)
	require.Equal(t, events.SevWarn, ev.Severity)
	require.Equal(t, "git_hook_write", ev.RuleMatched)
}

func TestPersistence_AptHook(t *testing.T) {
	c := New(nil)
	ev := events.Event{Category: "file", Severity: events.SevInfo, Path: "/etc/apt/apt.conf.d/99backdoor", Flags: "O_WRONLY|O_CREAT"}
	ev = c.Classify(ev, noopLookup)
	require.Equal(t, "persistence", ev.Category)
	require.Equal(t, events.SevWarn, ev.Severity)
	require.Equal(t, "apt_hook", ev.RuleMatched)
}

func TestPersistence_NpmrcWrite(t *testing.T) {
	c := New(nil)
	ev := events.Event{Category: "file", Severity: events.SevInfo, Path: "/home/user/.npmrc", Flags: "O_WRONLY"}
	ev = c.Classify(ev, noopLookup)
	require.Equal(t, "persistence", ev.Category)
	require.Equal(t, events.SevWarn, ev.Severity)
	require.Equal(t, "npmrc_write", ev.RuleMatched)
}

func TestPersistence_SystemProfileWrite(t *testing.T) {
	c := New(nil)
	ev := events.Event{Category: "file", Severity: events.SevInfo, Path: "/etc/environment", Flags: "O_WRONLY"}
	ev = c.Classify(ev, noopLookup)
	require.Equal(t, "persistence", ev.Category)
	require.Equal(t, events.SevAlert, ev.Severity)
	require.Equal(t, "system_profile_write", ev.RuleMatched)
}

func TestPersistence_ReadOnlyNonPersistence(t *testing.T) {
	c := New(nil)
	// Reading a cron file should NOT match persistence (persistence requires write).
	ev := events.Event{Category: "file", Severity: events.SevInfo, Path: "/etc/cron.d/something", Flags: "O_RDONLY"}
	ev = c.Classify(ev, noopLookup)
	// Should fall through to file rules, not persistence.
	require.NotEqual(t, "persistence", ev.Category)
}
