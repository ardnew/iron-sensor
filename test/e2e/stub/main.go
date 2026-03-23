// stub is a minimal binary that mimics AI coding agent processes.
// It is compiled once and copied with different names (claude,
// openclaw-gateway, python3) so the sensor's signature matching
// recognises each variant. Actions passed as CLI arguments trigger
// detectable behaviours (file reads, writes, child processes).
package main

import (
	"os"
	"os/exec"
	"strings"
	"time"
)

func main() {
	// Give the sensor time to process our exec event and register
	// this process as an agent in the BPF map.
	time.Sleep(500 * time.Millisecond)

	for _, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "-") {
			continue // skip flags like -m
		}

		switch arg {
		case "codex":
			// Identity marker for codex argv matching; no action.

		case "noop":
			// Exist briefly as an agent, then exit.

		case "read-etc-shadow":
			f, err := os.Open("/etc/shadow")
			if err == nil {
				f.Close()
			}

		case "read-etc-passwd":
			f, err := os.Open("/etc/passwd")
			if err == nil {
				f.Close()
			}

		case "write-cron":
			p := "/etc/cron.d/e2e-iron-sensor-test"
			_ = os.MkdirAll("/etc/cron.d", 0o755)
			_ = os.WriteFile(p, []byte("# e2e test\n"), 0o644)
			defer os.Remove(p)

		case "write-systemd":
			d := "/etc/systemd/system"
			_ = os.MkdirAll(d, 0o755)
			p := d + "/e2e-iron-sensor-test.service"
			_ = os.WriteFile(p, []byte("[Unit]\nDescription=e2e\n"), 0o644)
			defer os.Remove(p)

		case "spawn-curl":
			_ = exec.Command("curl", "--version").Run()

		case "spawn-sudo":
			_ = exec.Command("sudo", "--version").Run()
		}

		// Small delay between actions for event propagation.
		time.Sleep(100 * time.Millisecond)
	}

	// Let the sensor observe remaining events before we exit.
	time.Sleep(500 * time.Millisecond)
}
