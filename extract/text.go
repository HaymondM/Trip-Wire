package extract

import (
	"regexp"
	"strings"

	"github.com/HaymondM/Trip-Wire/engine"
)

var paragraphBreakRe = regexp.MustCompile(`\n\s*\n`)

// Text splits non-HTML content (plain text, Markdown, JSON) into one visible
// segment per paragraph. Nothing is hidden in the CSS sense, but invisible
// Unicode and visible instructions aimed at an AI are still detected.
//
// Source code gets a MatchText with its literals blanked (see Code), so
// fixtures and detection patterns aren't mistaken for instructions, while
// Unicode checks still see the original text.
func Text(content string) []engine.Segment {
	x := &extractor{}
	masked, isCode := Code(content)
	start := 0
	for _, brk := range append(paragraphBreakRe.FindAllStringIndex(content, -1), []int{len(content), len(content)}) {
		paragraph := content[start:brk[0]]
		if isCode {
			// mask preserves byte offsets, so the same slice lines up.
			x.addMasked(paragraph, masked[start:brk[0]])
		} else {
			x.add(paragraph, "text", "", nil)
		}
		start = brk[1]
	}
	return x.segments
}

// addMasked adds a visible text segment whose instructions are matched
// against match instead of text.
func (x *extractor) addMasked(text, match string) {
	before := len(x.segments)
	x.add(text, "text", "", nil)
	if len(x.segments) > before {
		m := strings.TrimSpace(whitespaceRe.ReplaceAllString(match, " "))
		x.segments[before].MatchText = &m
	}
}
