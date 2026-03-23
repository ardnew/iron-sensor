//go:build e2e

// Package e2e contains end-to-end tests for the iron-sensor.
// These tests boot a real sensor (with eBPF), launch stub binaries
// that mimic known AI coding agents, and assert that the expected
// detection events are emitted.
//
// Requirements:
//   - Root privileges (BPF needs CAP_BPF / CAP_SYS_ADMIN)
//   - BPF toolchain for building the sensor (clang, bpf2go)
//   - curl and sudo on PATH (for process-spawn scenarios)
//
// Run:
//
//	sudo go test -tags e2e -v -count=1 ./test/e2e/
package e2e

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"iron-sensor/internal/events"

	"github.com/stretchr/testify/require"
)

// sensorEvent is a thin wrapper used only for JSON unmarshalling so
// we don't depend on the exact shape of events.Event for the test
// assertions (the struct has json tags that match the wire format).
type sensorEvent = events.Event

func projectRoot(t *testing.T) string {
	t.Helper()
	// test/e2e -> project root is ../..
	wd, err := os.Getwd()
	require.NoError(t, err)
	return filepath.Join(wd, "..", "..")
}

// buildBinary runs `go build` for the given package and writes the
// output to dst. Returns dst.
func buildBinary(t *testing.T, root, pkg, dst string) string {
	t.Helper()
	cmd := exec.Command("go", "build", "-o", dst, pkg)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "building %s:\n%s", pkg, string(out))
	return dst
}

// copyFile copies src to dst and makes dst executable.
func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(dst, data, 0o755))
}

// waitForReady reads from r (sensor stderr) until it sees the
// "live detection started" log line or the timeout fires.
func waitForReady(t *testing.T, r io.Reader, timeout time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), "live detection started") {
				close(done)
				// Keep draining so the pipe doesn't block.
				for scanner.Scan() {
				}
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		t.Fatal("timed out waiting for sensor to become ready")
	}
}

// runStub executes the stub binary at binPath with the given args,
// waits for it to finish, and returns its PID (for event correlation).
func runStub(t *testing.T, binPath string, args ...string) int {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	cmd.Stdout = os.Stderr // surface stub output in test logs
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start(), "starting stub %s", filepath.Base(binPath))
	pid := cmd.Process.Pid
	require.NoError(t, cmd.Wait(), "running stub %s", filepath.Base(binPath))
	return pid
}

// parseEvents reads NDJSON lines from path and returns parsed events.
func parseEvents(t *testing.T, path string) []sensorEvent {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var result []sensorEvent
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var ev sensorEvent
		require.NoError(t, json.Unmarshal([]byte(line), &ev), "bad NDJSON line: %s", line)
		result = append(result, ev)
	}
	return result
}

// filterEvents returns events for which fn returns true.
func filterEvents(all []sensorEvent, fn func(sensorEvent) bool) []sensorEvent {
	var out []sensorEvent
	for _, ev := range all {
		if fn(ev) {
			out = append(out, ev)
		}
	}
	return out
}

// requireEvent asserts at least one event matches fn and returns the first.
func requireEvent(t *testing.T, all []sensorEvent, desc string, fn func(sensorEvent) bool) sensorEvent {
	t.Helper()
	matches := filterEvents(all, fn)
	require.NotEmpty(t, matches, "expected event: %s\ngot %d total events", desc, len(all))
	return matches[0]
}

func TestSensorDetections(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("e2e tests require root (BPF)")
	}

	root := projectRoot(t)

	// Build the sensor: generate BPF bindings then compile.
	t.Log("building sensor…")
	genCmd := exec.Command("go", "generate", "./internal/agent/")
	genCmd.Dir = root
	genOut, err := genCmd.CombinedOutput()
	require.NoError(t, err, "go generate:\n%s", string(genOut))

	buildCmd := exec.Command("go", "build", "-o", "bin/iron-sensor", "./cmd/iron-sensor/")
	buildCmd.Dir = root
	buildCmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	buildOut, err := buildCmd.CombinedOutput()
	require.NoError(t, err, "go build:\n%s", string(buildOut))
	sensorBin := filepath.Join(root, "bin", "iron-sensor")

	// Build the stub binary.
	tmpDir := t.TempDir()
	stubBin := buildBinary(t, root, "./test/e2e/stub/", filepath.Join(tmpDir, "stub"))

	// Create agent-named copies of the stub.
	claudeBin := filepath.Join(tmpDir, "claude")
	openclawBin := filepath.Join(tmpDir, "openclaw-gateway")
	python3Bin := filepath.Join(tmpDir, "python3")
	copyFile(t, stubBin, claudeBin)
	copyFile(t, stubBin, openclawBin)
	copyFile(t, stubBin, python3Bin)

	eventsFile := filepath.Join(tmpDir, "events.ndjson")
	cfgFile := filepath.Join(tmpDir, "config.yaml")
	cfgYAML := fmt.Sprintf("sink_type: file\nfile_sink:\n  output_path: %s\n", eventsFile)
	require.NoError(t, os.WriteFile(cfgFile, []byte(cfgYAML), 0o644))
	sensorCmd := exec.Command(sensorBin, "--config", cfgFile)
	sensorCmd.Dir = root

	// Capture stderr so we can detect readiness and surface logs.
	stderrR, stderrW := io.Pipe()
	sensorCmd.Stderr = io.MultiWriter(stderrW, os.Stderr)

	t.Log("starting sensor…")
	require.NoError(t, sensorCmd.Start(), "starting sensor")

	// Ensure the sensor is killed on test exit.
	t.Cleanup(func() {
		if sensorCmd.Process != nil {
			_ = sensorCmd.Process.Signal(syscall.SIGTERM)
			_ = sensorCmd.Wait()
		}
	})

	waitForReady(t, stderrR, 30*time.Second)
	t.Log("sensor ready")

	t.Log("running claude_code stub (read-etc-shadow, spawn-curl)…")
	claudePID := runStub(t, claudeBin, "read-etc-shadow", "spawn-curl")
	_ = claudePID

	t.Log("running openclaw stub (write-cron)…")
	openclawPID := runStub(t, openclawBin, "write-cron")
	_ = openclawPID

	t.Log("running codex stub (write-systemd)…")
	codexPID := runStub(t, python3Bin, "-m", "codex", "write-systemd")
	_ = codexPID

	// Give the sensor a moment to flush remaining events.
	time.Sleep(2 * time.Second)

	t.Log("stopping sensor…")
	require.NoError(t, sensorCmd.Process.Signal(syscall.SIGTERM))
	_ = sensorCmd.Wait()
	// Close stderr writer so the pipe reader unblocks.
	stderrW.Close()

	allEvents := parseEvents(t, eventsFile)
	t.Logf("collected %d events", len(allEvents))
	require.NotEmpty(t, allEvents, "sensor produced no events")

	t.Run("claude_code_start", func(t *testing.T) {
		requireEvent(t, allEvents, "claude_code agent start", func(ev sensorEvent) bool {
			return ev.Category == "agent_lifecycle" &&
				ev.Action == "start" &&
				ev.SignatureMatch == "claude_code"
		})
	})

	t.Run("claude_code_stop", func(t *testing.T) {
		requireEvent(t, allEvents, "claude_code agent stop", func(ev sensorEvent) bool {
			return ev.Category == "agent_lifecycle" &&
				ev.Action == "stop" &&
				ev.SignatureMatch == "claude_code"
		})
	})

	t.Run("sensitive_file_read_etc_shadow", func(t *testing.T) {
		ev := requireEvent(t, allEvents, "sensitive_file_read on /etc/shadow", func(ev sensorEvent) bool {
			return ev.Category == "file" &&
				ev.Path == "/etc/shadow" &&
				ev.RuleMatched == "sensitive_file_read"
		})
		require.Equal(t, events.SevWarn, ev.Severity)
	})

	t.Run("network_tool_curl", func(t *testing.T) {
		ev := requireEvent(t, allEvents, "network_tool detection for curl", func(ev sensorEvent) bool {
			return ev.Category == "process" &&
				ev.Comm == "curl" &&
				ev.RuleMatched == "network_tool"
		})
		require.Equal(t, events.SevWarn, ev.Severity)
	})

	t.Run("openclaw_start", func(t *testing.T) {
		requireEvent(t, allEvents, "openclaw agent start", func(ev sensorEvent) bool {
			return ev.Category == "agent_lifecycle" &&
				ev.Action == "start" &&
				ev.SignatureMatch == "openclaw"
		})
	})

	t.Run("openclaw_stop", func(t *testing.T) {
		requireEvent(t, allEvents, "openclaw agent stop", func(ev sensorEvent) bool {
			return ev.Category == "agent_lifecycle" &&
				ev.Action == "stop" &&
				ev.SignatureMatch == "openclaw"
		})
	})

	t.Run("cron_write_persistence", func(t *testing.T) {
		ev := requireEvent(t, allEvents, "cron_write persistence for openclaw", func(ev sensorEvent) bool {
			return ev.Category == "persistence" &&
				ev.RuleMatched == "cron_write" &&
				strings.HasPrefix(ev.Path, "/etc/cron.d/")
		})
		require.Equal(t, events.SevAlert, ev.Severity)
	})

	t.Run("codex_start", func(t *testing.T) {
		requireEvent(t, allEvents, "codex agent start", func(ev sensorEvent) bool {
			return ev.Category == "agent_lifecycle" &&
				ev.Action == "start" &&
				ev.SignatureMatch == "codex"
		})
	})

	t.Run("codex_stop", func(t *testing.T) {
		requireEvent(t, allEvents, "codex agent stop", func(ev sensorEvent) bool {
			return ev.Category == "agent_lifecycle" &&
				ev.Action == "stop" &&
				ev.SignatureMatch == "codex"
		})
	})

	t.Run("systemd_unit_write_persistence", func(t *testing.T) {
		ev := requireEvent(t, allEvents, "systemd_unit_write persistence for codex", func(ev sensorEvent) bool {
			return ev.Category == "persistence" &&
				ev.RuleMatched == "systemd_unit_write" &&
				strings.HasPrefix(ev.Path, "/etc/systemd/system/")
		})
		require.Equal(t, events.SevAlert, ev.Severity)
	})
}
