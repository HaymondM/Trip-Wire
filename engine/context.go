package engine

import (
	"fmt"
	"strings"
)

// WithoutVisible exempts visible text from the given instruction rules and
// rescores the report. It's for content that is expected to address an AI in
// plain sight, like an AGENTS.md or CLAUDE.md, where "if you are an AI
// agent..." is the point of the file rather than a sign of injection. Hidden
// text, HTML comments, invisible characters and every other rule still count.
//
// A passage matching several rules is one finding, so it's dropped only when
// every rule it matched is exempt; otherwise it's kept and relabeled with the
// first rule that isn't.
//
// ruleIDs are instruction pattern ids, such as "addresses-ai".
func WithoutVisible(r Report, ruleIDs ...string) Report {
	exempt := map[string]bool{}
	for _, id := range ruleIDs {
		exempt["instruction-"+id] = true
	}
	kept := make([]Finding, 0, len(r.Findings))
	for _, f := range r.Findings {
		// Instruction findings are medium exactly when the text is visible
		// (hidden or non-text locations are high; see analyzeSegment).
		visible := strings.HasPrefix(f.RuleID, "instruction-") && f.Severity == SeverityMedium && len(f.HiddenReasons) == 0
		if !visible {
			kept = append(kept, f)
			continue
		}
		rules := f.MatchedRules
		if len(rules) == 0 {
			rules = []string{f.RuleID}
		}
		var remaining []string
		for _, id := range rules {
			if !exempt[id] {
				remaining = append(remaining, id)
			}
		}
		if len(remaining) == 0 {
			continue
		}
		if remaining[0] != f.RuleID {
			f.RuleID = remaining[0]
			f.Message = "Visible text " + describeRule(remaining[0])
			if extra := len(remaining) - 1; extra > 0 {
				f.Message += fmt.Sprintf(" (+%d more injection pattern%s)", extra, plural(extra))
			}
			f.Message += "."
		}
		f.MatchedRules = remaining
		kept = append(kept, f)
	}
	r.Findings = kept
	r.Score = score(kept)
	r.Verdict = verdict(r.Score)
	return r
}

func describeRule(ruleID string) string {
	for _, p := range instructionPatterns {
		if "instruction-"+p.id == ruleID {
			return p.description
		}
	}
	return "matches a prompt-injection pattern"
}
