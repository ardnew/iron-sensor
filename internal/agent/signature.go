package agent

import (
	"fmt"
	"regexp"
	"strings"

	"iron-sensor/internal/config"
)

// Signature defines how to identify an AI coding agent process.
type Signature struct {
	Name     string
	MatchExe func(exe string) bool
	MatchArg func(argv []string) bool
}

func baseName(path string) string {
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[i+1:]
	}
	return path
}

// BuiltinSignatures returns the default set of agent signatures.
func BuiltinSignatures() []Signature {
	return builtinSignatures
}

// BuildSignatures returns builtin signatures plus any configured binary detections.
func BuildSignatures(dets []config.BinaryDetection) ([]Signature, error) {
	sigs := make([]Signature, len(builtinSignatures))
	copy(sigs, builtinSignatures)
	for _, d := range dets {
		bin := d.Binary
		name := d.Name
		argsPattern := d.ArgsRegex

		var argsRe *regexp.Regexp
		if argsPattern != "" {
			var err error
			argsRe, err = regexp.Compile(argsPattern)
			if err != nil {
				return nil, fmt.Errorf("detection %q: invalid args_regex: %w", name, err)
			}
		}

		sigs = append(sigs, Signature{
			Name: name,
			MatchExe: func(_ string) bool {
				return true
			},
			MatchArg: func(argv []string) bool {
				if len(argv) == 0 {
					return false
				}
				if baseName(argv[0]) != bin {
					return false
				}
				if argsRe == nil {
					return true
				}
				for _, a := range argv[1:] {
					if argsRe.MatchString(a) {
						return true
					}
				}
				return false
			},
		})
	}
	return sigs, nil
}

var builtinSignatures = []Signature{
	{
		Name: "claude_code",
		MatchExe: func(_ string) bool {
			return true // matched via argv[0]
		},
		MatchArg: func(argv []string) bool {
			if len(argv) == 0 {
				return false
			}
			return baseName(argv[0]) == "claude"
		},
	},
	{
		Name: "openclaw",
		MatchExe: func(_ string) bool {
			return true
		},
		MatchArg: func(argv []string) bool {
			if len(argv) == 0 {
				return false
			}
			return baseName(argv[0]) == "openclaw-gateway"
		},
	},
	{
		Name: "codex",
		MatchExe: func(exe string) bool {
			base := baseName(exe)
			return base == "python" || base == "python3" ||
				strings.HasPrefix(base, "python3.")
		},
		MatchArg: func(argv []string) bool {
			for _, a := range argv {
				if strings.Contains(a, "codex") {
					return true
				}
			}
			return false
		},
	},
}

// Match checks if a process matches any known agent signature.
// Returns the signature name and true if matched.
func Match(exe string, argv []string) (string, bool) {
	return MatchWith(builtinSignatures, exe, argv)
}

// MatchWith checks a process against the given set of signatures.
func MatchWith(sigs []Signature, exe string, argv []string) (string, bool) {
	for _, sig := range sigs {
		if sig.MatchExe(exe) && sig.MatchArg(argv) {
			return sig.Name, true
		}
	}
	return "", false
}
