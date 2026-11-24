package extract

import (
	"regexp"

	"github.com/HaymondM/Trip-Wire/engine"
)

var paragraphBreakRe = regexp.MustCompile(`\n\s*\n`)

// Text splits non-HTML content (plain text, Markdown, JSON) into one visible
// segment per paragraph. Nothing is hidden in the CSS sense, but invisible
// Unicode and visible instructions aimed at an AI are still detected.
//
// Source code is scanned with its string literals blanked (see Code), so
// fixtures and detection patterns aren't mistaken for instructions.
func Text(content string) []engine.Segment {
	if neutral, ok := Code(content); ok {
		content = neutral
	}
	x := &extractor{}
	for _, paragraph := range paragraphBreakRe.Split(content, -1) {
		x.add(paragraph, "text", "", nil)
	}
	return x.segments
}
