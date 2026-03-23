package classifier

import (
	"iron-sensor/internal/config"
	"iron-sensor/internal/events"
)

// Rule defines a classification rule that sets severity on matching events.
type Rule struct {
	Name     string
	Severity int // events.SevAlert (0), SevWarn (1), SevInfo (2)
	Match    func(ev events.Event, lookupComm func(pid uint32) string) bool
}

// Classifier applies rules to events to set severity and rule_matched.
type Classifier struct {
	processRules     []Rule
	persistenceRules []Rule
	fileRules        []Rule
}

func New(overrides map[string]config.RuleOverride) *Classifier {
	return &Classifier{
		processRules:     applyOverrides(ProcessRules, overrides),
		persistenceRules: applyOverrides(PersistenceRules, overrides),
		fileRules:        applyOverrides(FileRules, overrides),
	}
}

func applyOverrides(rules []Rule, overrides map[string]config.RuleOverride) []Rule {
	if len(overrides) == 0 {
		return rules
	}
	var result []Rule
	for _, r := range rules {
		o, ok := overrides[r.Name]
		if ok && o.Enabled != nil && !*o.Enabled {
			continue
		}
		if ok && o.Severity != nil {
			r.Severity = *o.Severity
		}
		result = append(result, r)
	}
	return result
}

// Classify applies rules to the event and returns the modified event.
// lookupComm resolves a PID to its comm name (for ppid lookups).
func (c *Classifier) Classify(ev events.Event, lookupComm func(pid uint32) string) events.Event {
	switch ev.Category {
	case "process":
		return c.applyRules(ev, c.processRules, lookupComm)
	case "file":
		// Check persistence rules first; if matched, re-categorize.
		for _, r := range c.persistenceRules {
			if r.Match(ev, lookupComm) {
				ev.Category = "persistence"
				ev.Severity = r.Severity
				ev.RuleMatched = r.Name
				return ev
			}
		}
		return c.applyRules(ev, c.fileRules, lookupComm)
	case "persistence":
		// Already classified (e.g. chmod events).
		return ev
	default:
		return ev
	}
}

func (c *Classifier) applyRules(ev events.Event, rules []Rule, lookupComm func(pid uint32) string) events.Event {
	for _, r := range rules {
		if r.Match(ev, lookupComm) {
			ev.Severity = r.Severity
			ev.RuleMatched = r.Name
			return ev
		}
	}
	return ev
}
