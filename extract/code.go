package extract

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// Source code is full of text that looks like prompt injection but is data:
// test fixtures, detection patterns, error messages. Agents read a lot of
// code (cat, grep, git diff, file-reading tools), so treating every string
// literal as an instruction buries real findings under false ones.
//
// Code splits the difference: string and regex literals are data, so they're
// blanked before instruction matching; comments, docstrings and code inside
// template interpolations are scanned as written, because that's where a
// planted instruction would hide. Unicode checks (zero-width, bidi, tag
// smuggling) always run on the original text, so blanking can't hide or
// invent those findings.

var (
	// codeLineRe matches a line that reads as code, allowing for a grep
	// ("path:12:") or diff ("+", "-") prefix.
	codeLineRe = regexp.MustCompile(`(^\s*([-+]|[\w./-]+:\d+[:-])?\s*(func|package|import|return|if|else|for|while|switch|case|var|const|let|type|def|class|function|export|from|struct|enum|impl|fn|pub|public|private|static|async|await|#include|//|/\*|\*/|#!)\b)|([{}\[\](;,]\s*$)|(:=|=>|==|!=|&&|\|\||\)\s*\{)`)
	// strongCodeRe is evidence that can't plausibly come from prose.
	strongCodeRe = regexp.MustCompile(`:=|=>|\b[A-Za-z_]\w*\.[A-Za-z_]\w*\(|\bfunc\s+\w*\(|\bfunction\b|\bdef\s+\w+\(|\breturn\b|^\s*(package|import)\s|\w\([^()]*\)\s*[{;]\s*$|^\s*[}\])]+[,;]?\s*$`)
	// markupRe finds HTML tags. Tags outside literals and comments mean
	// markup (an HTML page, JSX), which must keep its hidden-text analysis.
	markupRe = regexp.MustCompile(`<[a-zA-Z!/][^>]*>`)
)

// minCodeRatio is the share of non-blank lines that must read as code.
const minCodeRatio = 0.5

// Code reports whether content is source code and, if so, returns it with
// string and regex literals blanked. Each blanked character becomes as many
// spaces as it has UTF-8 bytes, so byte offsets (and line structure) match
// the original exactly.
func Code(content string) (string, bool) {
	if !looksLikeCode(content) {
		return "", false
	}
	// Markup check ignores comments too: a comment mentioning <noscript>
	// doesn't make Go source an HTML page.
	if markupRe.MatchString(mask(content, true)) {
		return "", false
	}
	return mask(content, false), true
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

// mask blanks string and regex literals (and, with comments set, comments
// and docstrings too). It's a lexer for common C-family, Go, JS, Python and
// shell shapes, not a parser. Where it's unsure, it errs toward scanning: a
// quote or backtick with no closing partner is an ordinary character, so a
// stray one can't blank the text after it.
func mask(src string, comments bool) string {
	l := &lexer{r: []rune(src), comments: comments}
	l.blank = make([]bool, len(l.r))
	l.code(0, false)
	var b strings.Builder
	b.Grow(len(src))
	for i, c := range l.r {
		if l.blank[i] && c != '\n' {
			b.WriteString(strings.Repeat(" ", utf8.RuneLen(c)))
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}

type lexer struct {
	r        []rune
	blank    []bool
	comments bool
}

func (l *lexer) at(i int, s string) bool {
	return strings.HasPrefix(string(l.r[i:min(i+len(s), len(l.r))]), s)
}

func (l *lexer) mark(from, to int) {
	for k := from; k < to && k < len(l.r); k++ {
		l.blank[k] = true
	}
}

func (l *lexer) lineEnd(i int) int {
	for i < len(l.r) && l.r[i] != '\n' {
		i++
	}
	return i
}

// code lexes code from i. Inside a template interpolation (interp), it stops
// at the brace that closes it and returns its index.
func (l *lexer) code(i int, interp bool) int {
	n := len(l.r)
	depth := 0
	var prev rune // last significant character, for telling a regex from division
	for i < n {
		c := l.r[i]
		switch {
		case interp && c == '{':
			depth++
			prev = c
			i++
		case interp && c == '}':
			if depth == 0 {
				return i
			}
			depth--
			prev = c
			i++
		case l.at(i, "//") || c == '#':
			// Line comment (any '#' outside a literal: Python needs no space
			// before it). Scanned as written.
			end := l.lineEnd(i)
			if l.comments {
				l.mark(i, end)
			}
			i = end
		case l.at(i, "/*"):
			end := indexFrom(l.r, i+2, "*/")
			if end < 0 {
				end = n - 2
			}
			if l.comments {
				l.mark(i, end+2)
			}
			i = end + 2
		case l.at(i, `"""`) || l.at(i, "'''"):
			// Python docstrings are documentation: scanned as written.
			end := indexFrom(l.r, i+3, string(l.r[i:i+3]))
			if end < 0 {
				end = n - 3
			}
			if l.comments {
				l.mark(i, end+3)
			}
			i = end + 3
		case c == '"' || c == '\'':
			if end := l.closingQuote(i, c); end > 0 {
				l.mark(i+1, end)
				i, prev = end+1, 'a'
			} else {
				i, prev = i+1, c
			}
		case c == '`':
			if end, ok := l.template(i); ok {
				i, prev = end, 'a'
			} else {
				i, prev = i+1, c
			}
		case c == '/' && l.regexAllowed(i, prev):
			if end := l.regexEnd(i); end > 0 {
				l.mark(i+1, end)
				i, prev = end+1, 'a'
			} else {
				i, prev = i+1, c
			}
		default:
			if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
				prev = c
			}
			i++
		}
	}
	return n
}

// template lexes a backtick literal starting at i: the literal parts are
// blanked and ${...} bodies are lexed as code. It returns the index after the
// closing backtick, or ok=false (with nothing blanked) if there isn't one.
func (l *lexer) template(i int) (int, bool) {
	saved := append([]bool(nil), l.blank[i:]...)
	n := len(l.r)
	k, start := i+1, i+1
	for k < n {
		switch {
		case l.r[k] == '\\':
			k += 2
		case l.r[k] == '`':
			l.mark(start, k)
			return k + 1, true
		case l.at(k, "${"):
			l.mark(start, k)
			k = l.code(k+2, true) + 1
			start = k
		default:
			k++
		}
	}
	copy(l.blank[i:], saved)
	return 0, false
}

// regexAllowed reports whether a '/' at i starts a JavaScript regex literal
// rather than division: it must follow an operator, an opening bracket, the
// start of the text, or a keyword like return.
func (l *lexer) regexAllowed(i int, prev rune) bool {
	if l.at(i, "//") || l.at(i, "/*") {
		return false
	}
	if prev == 0 || strings.ContainsRune("(,=:[!&|?{};+-*%<>~^", prev) {
		return true
	}
	k := i - 1
	for k >= 0 && (l.r[k] == ' ' || l.r[k] == '\t') {
		k--
	}
	end := k + 1
	for k >= 0 && (l.r[k] >= 'a' && l.r[k] <= 'z') {
		k--
	}
	switch string(l.r[k+1 : end]) {
	case "return", "typeof", "case", "in", "of", "void", "throw", "delete":
		return true
	}
	return false
}

// regexEnd finds the '/' closing a regex literal on the same line, skipping
// escapes and character classes, or returns -1.
func (l *lexer) regexEnd(i int) int {
	inClass := false
	for k := i + 1; k < len(l.r) && l.r[k] != '\n'; k++ {
		switch l.r[k] {
		case '\\':
			k++
		case '[':
			inClass = true
		case ']':
			inClass = false
		case '/':
			if !inClass && k > i+1 {
				return k
			}
		}
	}
	return -1
}

// closingQuote finds the quote closing the literal opened at start on the
// same line, honoring backslash escapes, or returns -1.
func (l *lexer) closingQuote(start int, q rune) int {
	for k := start + 1; k < len(l.r); k++ {
		switch {
		case l.r[k] == '\\':
			k++
		case l.r[k] == q:
			return k
		case l.r[k] == '\n':
			return -1
		}
	}
	return -1
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
