package extract

import (
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/html"
)

// declarations is a parsed CSS declaration block: lowercase property -> value.
type declarations map[string]string

func parseDeclarations(block string) declarations {
	decls := declarations{}
	for _, part := range strings.Split(block, ";") {
		prop, value, ok := strings.Cut(part, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(strings.ToLower(value)), "!important"))
		decls[strings.TrimSpace(strings.ToLower(prop))] = strings.TrimSpace(value)
	}
	return decls
}

// simpleSelector matches one element by tag, id, and classes, e.g. "div.note#x".
// Anything more complex (descendants, pseudo-classes, attributes) is skipped:
// raw-HTML scanning is best effort, and agents read hidden text regardless.
type simpleSelector struct {
	tag     string
	id      string
	classes []string
}

var simpleSelectorRe = regexp.MustCompile(`^([a-z][a-z0-9]*)?((?:[#.][\w-]+)*)$`)
var selectorPartRe = regexp.MustCompile(`[#.][\w-]+`)

func parseSelector(s string) (simpleSelector, bool) {
	s = strings.TrimSpace(s)
	m := simpleSelectorRe.FindStringSubmatch(s)
	if s == "" || m == nil {
		return simpleSelector{}, false
	}
	sel := simpleSelector{tag: m[1]}
	for _, part := range selectorPartRe.FindAllString(m[2], -1) {
		if part[0] == '#' {
			sel.id = part[1:]
		} else {
			sel.classes = append(sel.classes, part[1:])
		}
	}
	return sel, true
}

func (s simpleSelector) matches(n *html.Node) bool {
	if s.tag != "" && s.tag != n.Data {
		return false
	}
	if s.id != "" && attr(n, "id") != s.id {
		return false
	}
	classes := strings.Fields(attr(n, "class"))
	for _, want := range s.classes {
		found := false
		for _, c := range classes {
			if c == want {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

type rule struct {
	selector simpleSelector
	decls    declarations
}

var cssCommentRe = regexp.MustCompile(`(?s)/\*.*?\*/`)

// parseStylesheet extracts top-level rules with simple selectors. Rules inside
// at-rules (@media, @supports) are skipped.
func parseStylesheet(css string) []rule {
	css = cssCommentRe.ReplaceAllString(css, "")
	var rules []rule
	depth := 0
	start := 0
	selectorText := ""
	for i, ch := range css {
		switch ch {
		case '{':
			if depth == 0 {
				selectorText = css[start:i]
				start = i + 1
			}
			depth++
		case '}':
			depth--
			if depth == 0 {
				if !strings.HasPrefix(strings.TrimSpace(selectorText), "@") {
					decls := parseDeclarations(css[start:i])
					for _, s := range strings.Split(selectorText, ",") {
						if sel, ok := parseSelector(strings.ToLower(s)); ok {
							rules = append(rules, rule{selector: sel, decls: decls})
						}
					}
				}
				start = i + 1
			}
			if depth < 0 {
				depth = 0
			}
		}
	}
	return rules
}

// Utility classes from common CSS frameworks that hide content.
var hidingClasses = map[string]string{
	"hidden":             "display-none",
	"d-none":             "display-none",
	"is-hidden":          "display-none",
	"invisible":          "visibility-hidden",
	"sr-only":            "clipped",
	"visually-hidden":    "clipped",
	"screen-reader-text": "clipped",
}

// length parses a CSS length to approximate pixels. ok is false for values
// it can't interpret (auto, calc(), percentages of unknown boxes).
func length(v string) (px float64, ok bool) {
	v = strings.TrimSpace(v)
	if v == "0" {
		return 0, true
	}
	for _, unit := range []struct {
		suffix string
		scale  float64
	}{{"px", 1}, {"rem", 16}, {"em", 16}, {"pt", 4.0 / 3}} {
		if strings.HasSuffix(v, unit.suffix) {
			n, err := strconv.ParseFloat(strings.TrimSuffix(v, unit.suffix), 64)
			return n * unit.scale, err == nil
		}
	}
	return 0, false
}

type rgba struct{ r, g, b, a float64 }

var namedColors = map[string]rgba{
	"white":       {255, 255, 255, 1},
	"black":       {0, 0, 0, 1},
	"transparent": {0, 0, 0, 0},
}

var rgbFuncRe = regexp.MustCompile(`^rgba?\(([^)]*)\)$`)

func parseColor(v string) (rgba, bool) {
	v = strings.TrimSpace(v)
	if c, ok := namedColors[v]; ok {
		return c, true
	}
	if strings.HasPrefix(v, "#") {
		hex := v[1:]
		if len(hex) == 3 || len(hex) == 4 {
			var expanded strings.Builder
			for _, ch := range hex {
				expanded.WriteRune(ch)
				expanded.WriteRune(ch)
			}
			hex = expanded.String()
		}
		if len(hex) != 6 && len(hex) != 8 {
			return rgba{}, false
		}
		n, err := strconv.ParseUint(hex, 16, 32)
		if err != nil {
			return rgba{}, false
		}
		if len(hex) == 6 {
			return rgba{float64(n >> 16 & 0xff), float64(n >> 8 & 0xff), float64(n & 0xff), 1}, true
		}
		return rgba{float64(n >> 24 & 0xff), float64(n >> 16 & 0xff), float64(n >> 8 & 0xff), float64(n&0xff) / 255}, true
	}
	if m := rgbFuncRe.FindStringSubmatch(v); m != nil {
		fields := strings.FieldsFunc(m[1], func(r rune) bool { return r == ',' || r == ' ' || r == '/' })
		if len(fields) < 3 {
			return rgba{}, false
		}
		var c [4]float64
		c[3] = 1
		for i := 0; i < len(fields) && i < 4; i++ {
			f, err := strconv.ParseFloat(strings.TrimSuffix(fields[i], "%"), 64)
			if err != nil {
				return rgba{}, false
			}
			c[i] = f
		}
		return rgba{c[0], c[1], c[2], c[3]}, true
	}
	return rgba{}, false
}

// backgroundColor pulls a color out of a background or background-color value.
func backgroundColor(d declarations) (string, bool) {
	if v, ok := d["background-color"]; ok {
		return v, true
	}
	if v, ok := d["background"]; ok {
		for _, token := range strings.Fields(v) {
			if _, ok := parseColor(token); ok {
				return token, true
			}
		}
	}
	return "", false
}
