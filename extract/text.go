package extract

import (
	"regexp"

	"github.com/HaymondM/Trip-Wire/engine"
)

var paragraphBreakRe = regexp.MustCompile(`\n\s*\n`)

// Text splits non-HTML content (plain text, Markdown, JSON) into one visible
// segment per paragraph. Nothing is hidden in the CSS sense, but invisible
// Unicode and visible instructions aimed at an AI are still detected.
func Text(content string) []engine.Segment {
	x := &extractor{}
	for _, paragraph := range paragraphBreakRe.Split(content, -1) {
		x.add(paragraph, "text", "", nil)
	}
	return x.segments
}
