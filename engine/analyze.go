package engine

import (
	"fmt"
	"sort"
	"strings"
)

var hiddenReasonLabels = map[string]string{
	"display-none":             "display:none",
	"visibility-hidden":        "visibility:hidden",
	"transparent":              "zero opacity",
	"transparent-text":         "transparent text color",
	"tiny-font":                "near-zero font size",
	"color-matches-background": "text color matches background",
	"offscreen":                "positioned off-screen",
	"clipped":                  "clipped to nothing",
	"zero-size":                "zero-size container",
}

const (
	longHiddenThreshold = 160
	excerptRadius       = 90
	// Low-severity findings are common on legitimate pages (collapsed menus,
	// accordions), so on their own they must never push a page past "clean".
	maxLowScore = 9
)

var severityRank = map[Severity]int{SeverityHigh: 0, SeverityMedium: 1, SeverityLow: 2}

// Analyze scores a page's extracted text for prompt injection.
func Analyze(segments []Segment) Report {
	report := Report{Findings: []Finding{}}
	report.Stats.SegmentsScanned = len(segments)
	for _, seg := range segments {
		if seg.Hidden() {
			report.Stats.HiddenSegments++
		}
		report.Findings = append(report.Findings, analyzeSegment(seg)...)
	}
	sort.SliceStable(report.Findings, func(i, j int) bool {
		return severityRank[report.Findings[i].Severity] < severityRank[report.Findings[j].Severity]
	})
	report.Score = score(report.Findings)
	report.Verdict = verdict(report.Score)
	return report
}

func analyzeSegment(seg Segment) []Finding {
	var findings []Finding
	newFinding := func(ruleID string, sev Severity, message, excerpt string) Finding {
		return Finding{
			SegmentID:     seg.ID,
			RuleID:        ruleID,
			Severity:      sev,
			Message:       message,
			Excerpt:       excerpt,
			HiddenReasons: seg.HiddenReasons,
		}
	}

	if decoded := decodeTagSmuggling(seg.Text); decoded != "" {
		message := "Invisible Unicode tag characters smuggle hidden text into this passage"
		if matched := matchInstructions(decoded); len(matched) > 0 {
			message += " — the hidden text " + matched[0].description
		}
		f := newFinding("unicode-tag-smuggling", SeverityHigh, message+".", excerptAround(stripTags(seg.Text), nil))
		f.Decoded = decoded
		findings = append(findings, f)
	}

	if matched := matchInstructions(seg.Text); len(matched) > 0 {
		severity := SeverityMedium
		message := "Visible text " + matched[0].description
		if seg.Hidden() || seg.Source != "text" {
			severity = SeverityHigh
			message = describeLocation(seg) + " " + matched[0].description
		}
		if extra := len(matched) - 1; extra > 0 {
			message += fmt.Sprintf(" (+%d more injection pattern%s)", extra, plural(extra))
		}
		loc := matched[0].re.FindStringIndex(seg.Text)
		findings = append(findings, newFinding("instruction-"+matched[0].id, severity, message+".", excerptAround(seg.Text, loc)))
	} else if seg.Hidden() && seg.Source == "text" && len([]rune(strings.TrimSpace(seg.Text))) >= longHiddenThreshold {
		findings = append(findings, newFinding("hidden-text-block", SeverityLow,
			describeLocation(seg)+" is a large block a human can't see.", excerptAround(seg.Text, nil)))
	}

	if n := countZeroWidth(seg.Text); n >= 3 {
		findings = append(findings, newFinding("zero-width-characters", SeverityMedium,
			fmt.Sprintf("%d zero-width characters are hidden inside this text.", n), excerptAround(seg.Text, nil)))
	}
	if countBidiControls(seg.Text) > 0 {
		findings = append(findings, newFinding("bidi-control", SeverityMedium,
			"Bidirectional control characters make this text read differently than it displays.", excerptAround(seg.Text, nil)))
	}
	return findings
}

// describeLocation names where a segment lives, e.g. "Hidden text (display:none)".
func describeLocation(seg Segment) string {
	switch {
	case seg.Source == "comment":
		return "An HTML comment"
	case seg.Source == "meta":
		return "Page metadata"
	case strings.HasPrefix(seg.Source, "attr:"):
		return fmt.Sprintf("The %s attribute on <%s>", strings.TrimPrefix(seg.Source, "attr:"), strings.ToLower(seg.Tag))
	case seg.Hidden():
		labels := make([]string, 0, len(seg.HiddenReasons))
		for _, r := range seg.HiddenReasons {
			if label, ok := hiddenReasonLabels[r]; ok {
				labels = append(labels, label)
			} else {
				labels = append(labels, r)
			}
		}
		return "Hidden text (" + strings.Join(labels, ", ") + ")"
	}
	return "Text"
}

func score(findings []Finding) int {
	total, low := 0, 0
	for _, f := range findings {
		switch f.Severity {
		case SeverityHigh:
			total += 40
		case SeverityMedium:
			total += 15
		case SeverityLow:
			low += 2
		}
	}
	total += min(low, maxLowScore)
	return min(total, 100)
}

func verdict(score int) string {
	switch {
	case score >= 40:
		return "dangerous"
	case score >= 10:
		return "suspicious"
	}
	return "clean"
}

// excerptAround returns a short, single-line window of text centered on loc
// (a [start, end) byte range), or the start of the text when loc is nil.
func excerptAround(text string, loc []int) string {
	start, end := 0, len(text)
	if loc != nil {
		start, end = max(loc[0]-excerptRadius, 0), min(loc[1]+excerptRadius, len(text))
	} else if end > 2*excerptRadius {
		end = 2 * excerptRadius
	}
	start, end = runeBoundary(text, start), runeBoundary(text, end)
	out := strings.Join(strings.Fields(text[start:end]), " ")
	if start > 0 {
		out = "…" + out
	}
	if end < len(text) {
		out += "…"
	}
	return out
}

func runeBoundary(s string, i int) int {
	for i > 0 && i < len(s) && s[i]&0xC0 == 0x80 {
		i--
	}
	return i
}

func stripTags(text string) string {
	return strings.Map(func(r rune) rune {
		if r >= tagStart && r <= tagCancel {
			return -1
		}
		return r
	}, text)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
