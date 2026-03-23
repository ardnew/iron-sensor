package agent

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// readExe resolves /proc/<pid>/exe symlink.
func readExe(pid uint32) (string, error) {
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", err
	}
	// Kernel appends " (deleted)" if the binary was replaced.
	target = strings.TrimSuffix(target, " (deleted)")
	return target, nil
}

// readCmdline reads /proc/<pid>/cmdline and splits on null bytes.
func readCmdline(pid uint32) ([]string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	// cmdline is null-separated; trim trailing null.
	data = bytes.TrimRight(data, "\x00")
	parts := bytes.Split(data, []byte{0})
	argv := make([]string, len(parts))
	for i, p := range parts {
		argv[i] = string(p)
	}
	return argv, nil
}

// readFdPath resolves /proc/<pid>/fd/<fd> symlink.
func readFdPath(pid uint32, fd int32) string {
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
	if err != nil {
		return ""
	}
	return target
}

// readCwd resolves /proc/<pid>/cwd symlink.
func readCwd(pid uint32) string {
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	if err != nil {
		return ""
	}
	return target
}

// readComm reads /proc/<pid>/comm.
func readComm(pid uint32) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// readStartTimeTicks reads field 22 (starttime) from /proc/<pid>/stat.
// Returns the value in clock ticks since boot.
func readStartTimeTicks(pid uint32) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	// Field parsing: fields are space-separated, but field 2 (comm) may
	// contain spaces and is wrapped in parens. Find the last ')' to skip it.
	s := string(data)
	idx := strings.LastIndex(s, ")")
	if idx < 0 {
		return 0, fmt.Errorf("malformed /proc/%d/stat", pid)
	}
	// Fields after comm start at index 3. Field 22 is starttime (index 21, 0-based).
	// After ")" we have fields 3..N, so starttime is at offset 21-2 = 19 in the remainder.
	fields := strings.Fields(s[idx+1:])
	if len(fields) < 20 {
		return 0, fmt.Errorf("not enough fields in /proc/%d/stat", pid)
	}
	return strconv.ParseUint(fields[19], 10, 64)
}

// readChildren returns direct child PIDs of a process.
func readChildren(pid uint32) []uint32 {
	// Try /proc/<pid>/task/<pid>/children first (requires CONFIG_PROC_CHILDREN).
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/children", pid, pid))
	if err == nil && len(data) > 0 {
		var children []uint32
		for _, f := range strings.Fields(string(data)) {
			if cpid, err := strconv.ParseUint(f, 10, 32); err == nil {
				children = append(children, uint32(cpid))
			}
		}
		return children
	}
	return nil
}

// scanProcs returns PIDs of all processes in /proc.
func scanProcs() ([]uint32, error) {
	entries, err := filepath.Glob("/proc/[0-9]*")
	if err != nil {
		return nil, err
	}
	var pids []uint32
	for _, e := range entries {
		base := filepath.Base(e)
		pid, err := strconv.ParseUint(base, 10, 32)
		if err != nil {
			continue
		}
		pids = append(pids, uint32(pid))
	}
	return pids, nil
}
