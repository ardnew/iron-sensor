package events

import (
	"crypto/rand"
	"encoding/json"
	"time"

	"github.com/oklog/ulid/v2"
)

const SensorVersion = "0.1.0"

const (
	SevAlert = 0
	SevWarn  = 1
	SevInfo  = 2
)

// Event represents an NDJSON event emitted by the sensor.
type Event struct {
	EventID        string   `json:"event_id"`
	Timestamp      string   `json:"ts"`
	Category       string   `json:"category"`
	Severity       int      `json:"severity"`
	Action         string   `json:"action,omitempty"`
	PID            uint32   `json:"pid"`
	PPID           *uint32  `json:"ppid,omitempty"`
	Comm           string   `json:"comm,omitempty"`
	Exe            string   `json:"exe,omitempty"`
	Argv           []string `json:"argv,omitempty"`
	Cwd            string   `json:"cwd,omitempty"`
	SignatureMatch string   `json:"signature_matched,omitempty"`
	AgentRootPID   uint32   `json:"agent_root_pid"`
	InAgentSubtree *bool    `json:"in_agent_subtree,omitempty"`
	RuleMatched    string   `json:"rule_matched,omitempty"`

	// File/persistence event fields.
	Path     string `json:"path,omitempty"`
	PathHint string `json:"path_hint,omitempty"`
	Flags    string `json:"flags,omitempty"`
	Mode     *uint32 `json:"mode,omitempty"`

	// Start-only fields.
	DiscoveredAtStartup *bool `json:"discovered_at_startup,omitempty"`

	// Stop-only fields.
	ExitCode   *int32 `json:"exit_code,omitempty"`
	DurationMs *int64 `json:"duration_ms,omitempty"`
}

func NewEventID() string {
	return ulid.MustNew(ulid.Now(), rand.Reader).String()
}

func NowTimestamp() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func NewStartEvent(pid, rootPID uint32, comm, exe string, argv []string, sig string, startup bool) Event {
	return Event{
		EventID:             NewEventID(),
		Timestamp:           NowTimestamp(),
		Category:            "agent_lifecycle",
		Severity:            SevInfo,
		Action:              "start",
		PID:                 pid,
		Comm:                comm,
		Exe:                 exe,
		Argv:                argv,
		SignatureMatch:      sig,
		AgentRootPID:        rootPID,
		DiscoveredAtStartup: &startup,
	}
}

func NewStopEvent(pid, rootPID uint32, sig string, exitCode int32, durationMs int64) Event {
	return Event{
		EventID:        NewEventID(),
		Timestamp:      NowTimestamp(),
		Category:       "agent_lifecycle",
		Severity:       SevInfo,
		Action:         "stop",
		PID:            pid,
		SignatureMatch: sig,
		AgentRootPID:   rootPID,
		ExitCode:       &exitCode,
		DurationMs:     &durationMs,
	}
}

func NewProcessEvent(pid, ppid, rootPID uint32, comm, exe string, argv []string, cwd string) Event {
	inSubtree := true
	return Event{
		EventID:        NewEventID(),
		Timestamp:      NowTimestamp(),
		Category:       "process",
		Severity:       SevInfo,
		PID:            pid,
		PPID:           &ppid,
		Comm:           comm,
		Exe:            exe,
		Argv:           argv,
		Cwd:            cwd,
		AgentRootPID:   rootPID,
		InAgentSubtree: &inSubtree,
	}
}

func NewFileEvent(pid, rootPID uint32, comm, exe, path, pathHint, flags string) Event {
	inSubtree := true
	return Event{
		EventID:        NewEventID(),
		Timestamp:      NowTimestamp(),
		Category:       "file",
		Severity:       SevInfo,
		PID:            pid,
		Comm:           comm,
		Exe:            exe,
		Path:           path,
		PathHint:       pathHint,
		Flags:          flags,
		AgentRootPID:   rootPID,
		InAgentSubtree: &inSubtree,
	}
}

func NewChmodEvent(pid, rootPID uint32, comm, path string, mode uint32) Event {
	inSubtree := true
	return Event{
		EventID:        NewEventID(),
		Timestamp:      NowTimestamp(),
		Category:       "persistence",
		Severity:       SevAlert,
		PID:            pid,
		Comm:           comm,
		Path:           path,
		Mode:           &mode,
		AgentRootPID:   rootPID,
		InAgentSubtree: &inSubtree,
		RuleMatched:    "setuid_bit",
	}
}

func Marshal(ev Event) ([]byte, error) {
	return json.Marshal(ev)
}
