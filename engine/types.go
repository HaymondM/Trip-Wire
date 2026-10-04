// Package engine decides which pieces of page text look like prompt
// injection aimed at an AI agent. It is pure Go with no browser
// dependencies, so it can be unit tested natively and compiled to
// WebAssembly for the extension.
package engine

// Segment is one piece of text the content script pulled from a page,
// along with why (if at all) a human viewer can't see it.
type Segment struct {
	ID            int      `json:"id"`
	Text          string   `json:"text"`
	Source        string   `json:"source"`
	Tag           string   `json:"tag"`
	HiddenReasons []string `json:"hiddenReasons"`
}

// Hidden reports whether a human viewing the rendered page can't see this text.
func (s Segment) Hidden() bool {
	return len(s.HiddenReasons) > 0
}

type Severity string

const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
)

type Finding struct {
	SegmentID     int      `json:"segmentId"`
	RuleID        string   `json:"ruleId"`
	Severity      Severity `json:"severity"`
	Message       string   `json:"message"`
	Excerpt       string   `json:"excerpt"`
	Decoded       string   `json:"decoded,omitempty"`
	HiddenReasons []string `json:"hiddenReasons,omitempty"`
}

type Stats struct {
	SegmentsScanned int `json:"segmentsScanned"`
	HiddenSegments  int `json:"hiddenSegments"`
}

type Report struct {
	Score    int       `json:"score"`
	Verdict  string    `json:"verdict"`
	Findings []Finding `json:"findings"`
	Stats    Stats     `json:"stats"`
}
