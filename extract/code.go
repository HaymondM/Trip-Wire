package extract

import (
	"regexp"
	"strings"
)

// Source code is full of text that looks like prompt injection but is data:
// test fixtures, detection patterns, error messages. Agents read a lot of
// code (cat, grep, git diff, file-reading tools), so treating every string
// literal as an instruction buries real findings under false ones.
//
// Code splits the difference: string literals are data, so their visible
// characters are blanked before matching; comments and docstrings are
// prose an agent reads as guidance, so they're scanned as written. Invisible
// characters (zero-width, bidi controls, Unicode tags) inside literals are
// kept, since hiding them in strings is an attack of its own.

var (
	// codeLineRe matches a line that reads as code, allowing for a grep
	// ("path:12:") or diff ("+", "-") prefix.
	codeLineRe = regexp.MustCompile(`(^\s*([-+]|[\w./-]+:\d+[:-])?\s*(func|package|import|return|if|else|for|while|switch|case|var|const|let|type|def|class|function|export|from|struct|enum|impl|fn|pub|public|private|static|async|await|#include|//|/\*|\*/|#!)\b)|([{}\[\](;,]\s*$)|(:=|=>|==|!=|&&|\|\||\)\s*\{)`)
	// strongCodeRe is evidence that can't plausibly come from prose.
	strongCodeRe = regexp.MustCompile(`:=|=>|\b[A-Za-z_]\w*\.[A-Za-z_]\w*\(|\bfunc\s+\w*\(|\bfunction\b|\bdef\s+\w+\(|\breturn\b|^\s*(package|import)\s|\w\([^()]*\)\s*[{;]\s*$|^\s*[}\])]+[,;]?\s*$`)
	// markupRe finds HTML tags. Tags outside string literals mean markup
	// (an HTML page, JSX), which must keep its hidden-text analysis.
	markupRe = regexp.MustCompile(`<[a-zA-Z!/][^>]*>`)
)

// minCodeRatio is the share of non-blank lines that must read as code.
const minCodeRatio = 0.5

// Code reports whether content is source code and, if so, returns it with the
// visible characters of string literals blanked out. Line structure is kept,
// so line-anchored patterns still behave.
func Code(content string) (string, bool) {
	if !looksLikeCode(content) {
		return "", false
	}
	// Markup check ignores comments too: a comment mentioning <noscript>
	// doesn't make Go source an HTML page.
	if markupRe.MatchString(blankLiterals(content, true)) {
		return "", false
	}
	return blankLiterals(content, false), true
}

func looksLikeCode(content string) bool {
	code, total, strong := 0, 0, false
	for _, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		total++
		if codeLineRe.MatchString(line) {
			code++
		}
		if !strong && strongCodeRe.MatchString(line) {
			strong = true
		}
	}
	return total > 0 && strong && float64(code) >= minCodeRatio*float64(total)
}

// blankLiterals replaces the visible characters inside string literals with
// spaces. It's a lexer for the common C-family, Go, JS, Python and shell
// shapes, not a parser: a quote with no closing quote on the same line is
// treated as an ordinary character, so a stray apostrophe can't blank the
// rest of the text. With comments set, comments and docstrings are blanked
// as well.
func blankLiterals(src string, comments bool) string {
	r := []rune(src)
	out := make([]rune, len(r))
	copy(out, r)
	n := len(r)
	at := func(i int, s string) bool { return strings.HasPrefix(string(r[i:min(i+len(s), n)]), s) }
	lineEnd := func(i int) int {
		for i < n && r[i] != '\n' {
			i++
		}
		return i
	}
	blank := func(from, to int) {
		for k := from; k < to; k++ {
			if r[k] != '\n' && !keepInLiteral(r[k]) {
				out[k] = ' '
			}
		}
	}

	for i := 0; i < n; {
		switch {
		case at(i, "//") || (r[i] == '#' && (i == 0 || r[i-1] == ' ' || r[i-1] == '\t' || r[i-1] == '\n')):
			// Line comment: scanned as written.
			end := lineEnd(i)
			if comments {
				blank(i, end)
			}
			i = end
		case at(i, "/*"):
			// Block comment: scanned as written.
			end := indexFrom(r, i+2, "*/")
			if end < 0 {
				end = n - 2
			}
			if comments {
				blank(i, end+2)
			}
			i = end + 2
		case at(i, `"""`) || at(i, "'''"):
			// Python docstrings are documentation: scanned as written.
			end := indexFrom(r, i+3, string(r[i:i+3]))
			if end < 0 {
				end = n - 3
			}
			if comments {
				blank(i, end+3)
			}
			i = end + 3
		case r[i] == '"' || r[i] == '\'':
			if end := closingQuote(r, i, r[i], true); end > 0 {
				blank(i+1, end)
				i = end + 1
			} else {
				i++
			}
		case r[i] == '`':
			if end := closingQuote(r, i, '`', false); end > 0 {
				blank(i+1, end)
				i = end + 1
			} else {
				i++
			}
		default:
			i++
		}
	}
	return string(out)
}

// indexFrom returns the rune index of the first pat at or after from, or -1.
func indexFrom(r []rune, from int, pat string) int {
	p := []rune(pat)
	for k := from; k+len(p) <= len(r); k++ {
		if string(r[k:k+len(p)]) == pat {
			return k
		}
	}
	return -1
}

// closingQuote finds the quote ending the literal opened at start, honoring
// backslash escapes. sameLine limits the search to the current line.
func closingQuote(r []rune, start int, q rune, sameLine bool) int {
	for k := start + 1; k < len(r); k++ {
		switch {
		case r[k] == '\\' && q != '`':
			k++
		case r[k] == q:
			return k
		case r[k] == '\n' && sameLine:
			return -1
		}
	}
	return -1
}

// keepInLiteral keeps characters that are invisible or reorder text: they are
// an attack even inside a string (Trojan Source, tag smuggling).
func keepInLiteral(c rune) bool {
	switch {
	case c == 0x200B, c == 0x200C, c == 0x200D, c == 0x2060, c == 0xFEFF:
		return true
	case c >= 0x202A && c <= 0x202E, c >= 0x2066 && c <= 0x2069, c == 0x200E, c == 0x200F, c == 0x061C:
		return true
	case c >= 0xE0000 && c <= 0xE007F:
		return true
	}
	return false
}
