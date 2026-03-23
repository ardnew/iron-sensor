package events

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type bufSink struct{ bytes.Buffer }

func (b *bufSink) Close() error { return nil }

func intPtr(v int) *int { return &v }

func TestEmitter_NoFilter(t *testing.T) {
	s := &bufSink{}
	em := NewEmitter(s, nil)

	require.NoError(t, em.Emit(Event{Category: "process", Severity: SevInfo}))
	require.NoError(t, em.Emit(Event{Category: "file", Severity: SevWarn}))
	require.NoError(t, em.Emit(Event{Category: "persistence", Severity: SevAlert}))

	lines := nonEmptyLines(s.String())
	require.Len(t, lines, 3)
}

func TestEmitter_MinSeverity_DropsLow(t *testing.T) {
	s := &bufSink{}
	em := NewEmitter(s, intPtr(SevWarn))

	require.NoError(t, em.Emit(Event{Category: "process", Severity: SevAlert}))
	require.NoError(t, em.Emit(Event{Category: "process", Severity: SevWarn}))
	require.NoError(t, em.Emit(Event{Category: "process", Severity: SevInfo})) // dropped

	lines := nonEmptyLines(s.String())
	require.Len(t, lines, 2)

	var ev Event
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &ev))
	require.Equal(t, SevAlert, ev.Severity)
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &ev))
	require.Equal(t, SevWarn, ev.Severity)
}

func TestEmitter_MinSeverity_ExemptsLifecycle(t *testing.T) {
	s := &bufSink{}
	em := NewEmitter(s, intPtr(SevAlert)) // only alert

	require.NoError(t, em.Emit(Event{Category: "agent_lifecycle", Severity: SevInfo}))
	require.NoError(t, em.Emit(Event{Category: "process", Severity: SevInfo})) // dropped

	lines := nonEmptyLines(s.String())
	require.Len(t, lines, 1)

	var ev Event
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &ev))
	require.Equal(t, "agent_lifecycle", ev.Category)
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}
