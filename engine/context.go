package engine

import "strings"

// WithoutVisible drops visible-text findings from the given instruction rules
// and rescores the report. It's for content that is expected to address an AI
// in plain sight, like an AGENTS.md or CLAUDE.md, where "if you are an AI
// agent..." is the point of the file rather than a sign of injection. Hidden
// text, HTML comments, invisible characters and every other rule still count.
//
// ruleIDs are instruction pattern ids, such as "addresses-ai".
func WithoutVisible(r Report, ruleIDs ...string) Report {
	drop := map[string]bool{}
	for _, id := range ruleIDs {
		drop["instruction-"+id] = true
	}
	kept := make([]Finding, 0, len(r.Findings))
	for _, f := range r.Findings {
		// Instruction findings are medium exactly when the text is visible
		// (hidden or non-text locations are high; see analyzeSegment).
		visible := strings.HasPrefix(f.RuleID, "instruction-") && f.Severity == SeverityMedium && len(f.HiddenReasons) == 0
		if visible && drop[f.RuleID] {
			continue
		}
		kept = append(kept, f)
	}
	r.Findings = kept
	r.Score = score(kept)
	r.Verdict = verdict(r.Score)
	return r
}
