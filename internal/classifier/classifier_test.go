package classifier

import (
	"testing"

	"iron-sensor/internal/config"
	"iron-sensor/internal/events"

	"github.com/stretchr/testify/require"
)

func noopLookup(_ uint32) string { return "" }

func shellLookup(pid uint32) string {
	if pid == 100 {
		return "bash"
	}
	return ""
}

func TestProcessRules_ShellSpawn(t *testing.T) {
	c := New(nil)
	ev := events.Event{Category: "process", Severity: events.SevInfo, Comm: "bash"}
	ev = c.Classify(ev, noopLookup)
	require.Equal(t, events.SevWarn, ev.Severity)
	require.Equal(t, "shell_spawn", ev.RuleMatched)
}

func TestProcessRules_PrivilegeEscalation(t *testing.T) {
	c := New(nil)
	ev := events.Event{Category: "process", Severity: events.SevInfo, Comm: "sudo"}
	ev = c.Classify(ev, noopLookup)
	require.Equal(t, events.SevAlert, ev.Severity)
	require.Equal(t, "privilege_escalation", ev.RuleMatched)
}

func TestProcessRules_NetworkTool(t *testing.T) {
	c := New(nil)
	ev := events.Event{Category: "process", Severity: events.SevInfo, Comm: "curl"}
	ev = c.Classify(ev, noopLookup)
	require.Equal(t, events.SevWarn, ev.Severity)
	require.Equal(t, "network_tool", ev.RuleMatched)
}

func TestProcessRules_InterpreterFromShell(t *testing.T) {
	c := New(nil)
	ppid := uint32(100)
	ev := events.Event{Category: "process", Severity: events.SevInfo, Comm: "python3", PPID: &ppid}
	ev = c.Classify(ev, shellLookup)
	require.Equal(t, events.SevWarn, ev.Severity)
	require.Equal(t, "interpreter_exec", ev.RuleMatched)
}

func TestProcessRules_InterpreterNotFromShell(t *testing.T) {
	c := New(nil)
	ppid := uint32(200) // not a shell
	ev := events.Event{Category: "process", Severity: events.SevInfo, Comm: "python3", PPID: &ppid}
	ev = c.Classify(ev, noopLookup)
	// Should not match interpreter_exec, no other match either
	require.Equal(t, events.SevInfo, ev.Severity)
	require.Empty(t, ev.RuleMatched)
}

func TestProcessRules_PackageManager(t *testing.T) {
	c := New(nil)
	ev := events.Event{Category: "process", Severity: events.SevInfo, Comm: "npm"}
	ev = c.Classify(ev, noopLookup)
	require.Equal(t, events.SevInfo, ev.Severity)
	require.Equal(t, "package_manager", ev.RuleMatched)
}

func TestProcessRules_NoMatch(t *testing.T) {
	c := New(nil)
	ev := events.Event{Category: "process", Severity: events.SevInfo, Comm: "cat"}
	ev = c.Classify(ev, noopLookup)
	require.Equal(t, events.SevInfo, ev.Severity)
	require.Empty(t, ev.RuleMatched)
}

func TestFileRules_SSHKeyAccess(t *testing.T) {
	c := New(nil)
	ev := events.Event{Category: "file", Severity: events.SevInfo, Path: "/home/user/.ssh/id_rsa", Flags: "O_RDONLY"}
	ev = c.Classify(ev, noopLookup)
	require.Equal(t, events.SevAlert, ev.Severity)
	require.Equal(t, "ssh_key_access", ev.RuleMatched)
}

func TestFileRules_ProcMemAccess(t *testing.T) {
	c := New(nil)
	ev := events.Event{Category: "file", Severity: events.SevInfo, Path: "/proc/1234/environ", Flags: "O_RDONLY"}
	ev = c.Classify(ev, noopLookup)
	require.Equal(t, events.SevAlert, ev.Severity)
	require.Equal(t, "proc_mem_access", ev.RuleMatched)
}

func TestFileRules_DockerSocket(t *testing.T) {
	c := New(nil)
	ev := events.Event{Category: "file", Severity: events.SevInfo, Path: "/var/run/docker.sock", Flags: "O_RDWR"}
	ev = c.Classify(ev, noopLookup)
	require.Equal(t, events.SevAlert, ev.Severity)
	require.Equal(t, "docker_socket", ev.RuleMatched)
}

func TestFileRules_SensitiveFileWrite(t *testing.T) {
	c := New(nil)
	ev := events.Event{Category: "file", Severity: events.SevInfo, Path: "/etc/passwd", Flags: "O_WRONLY"}
	ev = c.Classify(ev, noopLookup)
	require.Equal(t, events.SevAlert, ev.Severity)
	require.Equal(t, "sensitive_file_write", ev.RuleMatched)
}

func TestFileRules_SensitiveFileRead(t *testing.T) {
	c := New(nil)
	ev := events.Event{Category: "file", Severity: events.SevInfo, Path: "/etc/shadow", Flags: "O_RDONLY"}
	ev = c.Classify(ev, noopLookup)
	require.Equal(t, events.SevWarn, ev.Severity)
	require.Equal(t, "sensitive_file_read", ev.RuleMatched)
}

func TestFileRules_GenericWrite(t *testing.T) {
	c := New(nil)
	ev := events.Event{Category: "file", Severity: events.SevInfo, Path: "/tmp/foo.txt", Flags: "O_WRONLY|O_CREAT"}
	ev = c.Classify(ev, noopLookup)
	require.Equal(t, events.SevInfo, ev.Severity)
	require.Equal(t, "generic_write", ev.RuleMatched)
}

func TestFileRules_CgroupWrite(t *testing.T) {
	c := New(nil)
	ev := events.Event{Category: "file", Severity: events.SevInfo, Path: "/sys/fs/cgroup/memory/limit", Flags: "O_WRONLY"}
	ev = c.Classify(ev, noopLookup)
	require.Equal(t, events.SevAlert, ev.Severity)
	require.Equal(t, "cgroup_write", ev.RuleMatched)
}

func TestAgentLifecycleNotClassified(t *testing.T) {
	c := New(nil)
	ev := events.Event{Category: "agent_lifecycle", Severity: events.SevInfo, Comm: "sudo"}
	ev = c.Classify(ev, noopLookup)
	require.Equal(t, events.SevInfo, ev.Severity)
	require.Empty(t, ev.RuleMatched)
}

func boolPtr(v bool) *bool { return &v }
func intPtr(v int) *int    { return &v }

func TestOverride_SeverityChange(t *testing.T) {
	overrides := map[string]config.RuleOverride{
		"shell_spawn": {Severity: intPtr(events.SevAlert)},
	}
	c := New(overrides)
	ev := events.Event{Category: "process", Severity: events.SevInfo, Comm: "bash"}
	ev = c.Classify(ev, noopLookup)
	require.Equal(t, events.SevAlert, ev.Severity)
	require.Equal(t, "shell_spawn", ev.RuleMatched)
}

func TestOverride_DisableRule(t *testing.T) {
	overrides := map[string]config.RuleOverride{
		"shell_spawn": {Enabled: boolPtr(false)},
	}
	c := New(overrides)
	ev := events.Event{Category: "process", Severity: events.SevInfo, Comm: "bash"}
	ev = c.Classify(ev, noopLookup)
	// bash no longer matches shell_spawn; no other rule matches
	require.Equal(t, events.SevInfo, ev.Severity)
	require.Empty(t, ev.RuleMatched)
}

func TestOverride_DisablePersistenceRule(t *testing.T) {
	overrides := map[string]config.RuleOverride{
		"ssh_persistence": {Enabled: boolPtr(false)},
	}
	c := New(overrides)
	ev := events.Event{Category: "file", Severity: events.SevInfo, Path: "/root/.ssh/authorized_keys", Flags: "O_WRONLY"}
	ev = c.Classify(ev, noopLookup)
	// Falls through to file rules instead of persistence
	require.Equal(t, "file", ev.Category)
	require.Equal(t, "ssh_key_access", ev.RuleMatched)
}

func TestOverride_UnknownRuleIgnored(t *testing.T) {
	overrides := map[string]config.RuleOverride{
		"nonexistent_rule": {Severity: intPtr(events.SevAlert)},
	}
	c := New(overrides)
	ev := events.Event{Category: "process", Severity: events.SevInfo, Comm: "bash"}
	ev = c.Classify(ev, noopLookup)
	require.Equal(t, events.SevWarn, ev.Severity)
	require.Equal(t, "shell_spawn", ev.RuleMatched)
}
