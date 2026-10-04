package engine

import (
	"strings"
	"unicode"
)

const (
	tagStart      = 0xE0000
	tagPrintStart = 0xE0020
	tagPrintEnd   = 0xE007E
	tagCancel     = 0xE007F
	blackFlag     = 0x1F3F4
	emojiVS       = 0xFE0F
)

// decodeTagSmuggling recovers ASCII hidden in Unicode tag characters
// (U+E0020–U+E007E). They render as nothing, but many LLM tokenizers read
// them, which makes them a way to smuggle instructions inside normal text.
// Tag runs that follow a black flag are real subdivision flags (e.g. the
// England flag) and are skipped.
func decodeTagSmuggling(text string) string {
	var b strings.Builder
	inFlag := false
	for _, r := range text {
		switch {
		case r == blackFlag:
			inFlag = true
		case r >= tagStart && r <= tagCancel:
			if inFlag {
				if r == tagCancel {
					inFlag = false
				}
				continue
			}
			if r >= tagPrintStart && r <= tagPrintEnd {
				b.WriteRune(r - tagStart)
			}
		default:
			inFlag = false
		}
	}
	return b.String()
}

// countZeroWidth counts invisible formatting characters, ignoring the
// joiners that legitimately glue emoji sequences and non-Latin scripts together.
func countZeroWidth(text string) int {
	count := 0
	var prev rune
	for _, r := range text {
		switch r {
		case '\u200B', '\u2060', '\uFEFF', '\u180E':
			count++
		case '\u200D':
			if !isEmojiLike(prev) {
				count++
			}
		case '\u200C':
			if prev < unicode.MaxASCII {
				count++
			}
		}
		prev = r
	}
	return count
}

func isEmojiLike(r rune) bool {
	return r >= 0x1F000 || r == emojiVS || unicode.Is(unicode.So, r)
}

func countBidiControls(text string) int {
	count := 0
	for _, r := range text {
		if (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) {
			count++
		}
	}
	return count
}
