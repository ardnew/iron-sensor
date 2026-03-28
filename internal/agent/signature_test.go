package agent

import (
	"testing"

	"iron-sensor/internal/config"

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

func TestBuildSignatures_CustomBinary(t *testing.T) {
	dets := []config.BinaryDetection{
		{Name: "exfil_agent", Binary: "exfil-tool"},
	}
	sigs, err := BuildSignatures(dets)
	require.NoError(t, err)

	// Should still match builtins.
	sig, ok := MatchWith(sigs, "/usr/local/bin/claude", []string{"claude"})
	require.True(t, ok)
	require.Equal(t, "claude_code", sig)

	// Should match the custom binary.
	sig, ok = MatchWith(sigs, "/tmp/exfil-tool", []string{"exfil-tool", "--target", "s3"})
	require.True(t, ok)
	require.Equal(t, "exfil_agent", sig)

	// Absolute path in argv[0] should also match.
	sig, ok = MatchWith(sigs, "/tmp/exfil-tool", []string{"/usr/local/bin/exfil-tool"})
	require.True(t, ok)
	require.Equal(t, "exfil_agent", sig)
}

func TestBuildSignatures_NoCustom(t *testing.T) {
	sigs, err := BuildSignatures(nil)
	require.NoError(t, err)
	require.Equal(t, len(BuiltinSignatures()), len(sigs))
}

func TestBuildSignatures_CustomNoMatchOther(t *testing.T) {
	dets := []config.BinaryDetection{
		{Name: "my_agent", Binary: "my-agent"},
	}
	sigs, err := BuildSignatures(dets)
	require.NoError(t, err)

	_, ok := MatchWith(sigs, "/usr/bin/bash", []string{"bash"})
	require.False(t, ok)
}

func TestBuildSignatures_ArgsRegex(t *testing.T) {
	dets := []config.BinaryDetection{
		{Name: "exfil_script", Binary: "bash", ArgsRegex: `exfil\.sh`},
	}
	sigs, err := BuildSignatures(dets)
	require.NoError(t, err)

	// Should match bash running the exfil script.
	sig, ok := MatchWith(sigs, "/usr/bin/bash", []string{"bash", "/tmp/exfil.sh"})
	require.True(t, ok)
	require.Equal(t, "exfil_script", sig)

	// Should not match bash running something else.
	_, ok = MatchWith(sigs, "/usr/bin/bash", []string{"bash", "other.sh"})
	require.False(t, ok)

	// Should not match bash with no args.
	_, ok = MatchWith(sigs, "/usr/bin/bash", []string{"bash"})
	require.False(t, ok)
}

func TestBuildSignatures_ArgsRegex_NoMatch_WrongBinary(t *testing.T) {
	dets := []config.BinaryDetection{
		{Name: "exfil_script", Binary: "bash", ArgsRegex: `exfil\.sh`},
	}
	sigs, err := BuildSignatures(dets)
	require.NoError(t, err)

	_, ok := MatchWith(sigs, "/usr/bin/zsh", []string{"zsh", "exfil.sh"})
	require.False(t, ok)
}

func TestBuildSignatures_InvalidRegex(t *testing.T) {
	dets := []config.BinaryDetection{
		{Name: "bad", Binary: "bash", ArgsRegex: `[invalid`},
	}
	_, err := BuildSignatures(dets)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid args_regex")
}
