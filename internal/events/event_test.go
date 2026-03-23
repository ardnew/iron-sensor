package events

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewStartEvent(t *testing.T) {
	ev := NewStartEvent(1234, 1234, "node", "/usr/bin/node",
		[]string{"node", "cli.js"}, "claude_code", false)

	require.Equal(t, "agent_lifecycle", ev.Category)
	require.Equal(t, "start", ev.Action)
	require.Equal(t, uint32(1234), ev.PID)
	require.Equal(t, "claude_code", ev.SignatureMatch)
	require.NotNil(t, ev.DiscoveredAtStartup)
	require.False(t, *ev.DiscoveredAtStartup)
	require.Nil(t, ev.ExitCode)
	require.Nil(t, ev.DurationMs)
	require.NotEmpty(t, ev.EventID)
	require.NotEmpty(t, ev.Timestamp)
}

func TestNewStopEvent(t *testing.T) {
	ev := NewStopEvent(1234, 1234, "claude_code", 0, 5000)

	require.Equal(t, "stop", ev.Action)
	require.NotNil(t, ev.ExitCode)
	require.Equal(t, int32(0), *ev.ExitCode)
	require.NotNil(t, ev.DurationMs)
	require.Equal(t, int64(5000), *ev.DurationMs)
	require.Nil(t, ev.DiscoveredAtStartup)
	require.Empty(t, ev.Exe)
	require.Nil(t, ev.Argv)
}

func TestMarshal_NDJSON(t *testing.T) {
	ev := NewStartEvent(42, 42, "node", "/usr/bin/node",
		[]string{"node"}, "claude_code", true)

	data, err := Marshal(ev)
	require.NoError(t, err)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(data, &parsed))
	require.Equal(t, "start", parsed["action"])
	require.Equal(t, float64(42), parsed["pid"])
	// vm_id and sensor_version should not be present
	_, hasVMID := parsed["vm_id"]
	require.False(t, hasVMID)
	_, hasSV := parsed["sensor_version"]
	require.False(t, hasSV)
	// severity should be a number
	require.Equal(t, float64(SevInfo), parsed["severity"])
}
