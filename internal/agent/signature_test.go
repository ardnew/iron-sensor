package agent

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMatch_ClaudeCode(t *testing.T) {
	sig, ok := Match("/home/user/.local/share/claude/versions/2.1.79", []string{
		"claude", "--dangerously-skip-permissions",
	})
	require.True(t, ok)
	require.Equal(t, "claude_code", sig)
}

func TestMatch_ClaudeCode_AbsPath(t *testing.T) {
	sig, ok := Match("/usr/local/bin/claude", []string{
		"/usr/local/bin/claude",
	})
	require.True(t, ok)
	require.Equal(t, "claude_code", sig)
}

func TestMatch_ClaudeCode_NoMatch_WrongArgv(t *testing.T) {
	_, ok := Match("/usr/bin/node", []string{
		"node", "server.js",
	})
	require.False(t, ok)
}

func TestMatch_OpenClaw(t *testing.T) {
	sig, ok := Match("/usr/local/bin/openclaw-gateway", []string{
		"openclaw-gateway", "--port", "8080",
	})
	require.True(t, ok)
	require.Equal(t, "openclaw", sig)
}

func TestMatch_OpenClaw_AbsPath(t *testing.T) {
	sig, ok := Match("/opt/openclaw/bin/openclaw-gateway", []string{
		"/opt/openclaw/bin/openclaw-gateway",
	})
	require.True(t, ok)
	require.Equal(t, "openclaw", sig)
}

func TestMatch_Codex(t *testing.T) {
	sig, ok := Match("/usr/bin/python3", []string{
		"python3",
		"-m", "codex",
	})
	require.True(t, ok)
	require.Equal(t, "codex", sig)
}

func TestMatch_Codex_NoMatch_WrongArg(t *testing.T) {
	_, ok := Match("/usr/bin/python3", []string{
		"python3", "script.py",
	})
	require.False(t, ok)
}

func TestMatch_NoMatch(t *testing.T) {
	_, ok := Match("/usr/bin/bash", []string{"bash", "-c", "echo hello"})
	require.False(t, ok)
}
