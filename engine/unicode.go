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

// rgiSubdivisionFlags are the only subdivision flags emoji fonts actually
// render (England, Scotland, Wales), keyed by their decoded tag payload.
// Every other tag run is treated as possible smuggling, so an attacker can't
// hide a payload by putting a black flag in front of it.
var rgiSubdivisionFlags = map[string]bool{"gbeng": true, "gbsct": true, "gbwls": true}

func isTag(r rune) bool {
	return r >= tagStart && r <= tagCancel
}

// decodeTagSmuggling recovers ASCII hidden in Unicode tag characters
// (U+E0020-U+E007E). They render as nothing, but many LLM tokenizers read
// them, which makes them a way to smuggle instructions inside normal text.
func decodeTagSmuggling(text string) string {
	runes := []rune(text)
	var decoded strings.Builder
	for i := 0; i < len(runes); {
		if !isTag(runes[i]) {
			i++
			continue
		}
		// A run ends after a cancel tag or at the first non-tag rune.
		end := i
		for end < len(runes) && isTag(runes[end]) {
			end++
			if runes[end-1] == tagCancel {
				break
			}
		}
		run := runes[i:end]
		if !(i > 0 && runes[i-1] == blackFlag && isRGISubdivisionFlag(run)) {
			for _, r := range run {
				if r >= tagPrintStart && r <= tagPrintEnd {
					decoded.WriteRune(r - tagStart)
				}
			}
		}
		i = end
	}
	return decoded.String()
}

func isRGISubdivisionFlag(run []rune) bool {
	if len(run) < 2 || run[len(run)-1] != tagCancel {
		return false
	}
	var payload strings.Builder
	for _, r := range run[:len(run)-1] {
		payload.WriteRune(r - tagStart)
	}
	return rgiSubdivisionFlags[payload.String()]
}

// stripInvisible removes format characters (zero-width spaces, joiners, soft
// hyphens, bidi controls, tag characters) so they can't split a keyword and
// slip it past the instruction patterns.
func stripInvisible(text string) string {
	return strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, text)
}

// countZeroWidth counts invisible formatting characters, ignoring joiners
// that have a legitimate shaping role where they appear.
func countZeroWidth(text string) int {
	count := 0
	var prev rune
	for _, r := range text {
		switch r {
		case '\u200B', '\u2060', '\uFEFF', '\u180E':
			count++
		case '\u200C', '\u200D':
			if !joinerHasLegitimateContext(prev) {
				count++
			}
		}
		prev = r
	}
	return count
}

// Joiners legitimately follow emoji (ZWJ sequences), combining marks such as
// an Indic virama, and letters of non-Latin scripts (Persian ZWNJ, Malayalam
// chillu forms). After Latin letters or punctuation they shape nothing.
func joinerHasLegitimateContext(prev rune) bool {
	return isEmojiLike(prev) ||
		unicode.Is(unicode.M, prev) ||
		(unicode.IsLetter(prev) && !unicode.Is(unicode.Latin, prev))
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
