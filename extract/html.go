// Package extract turns raw page content, as an AI agent fetches it with no
// browser, into engine segments.
//
// Without a rendering engine it can only see hiding done with inline styles,
// <style> rules on simple selectors, the hidden attribute, <noscript>, and
// common utility classes; text hidden by an external stylesheet looks visible.
// That gap matters less for agents than for people: an agent reads every word
// either way, so the engine's instruction patterns carry most of the weight.
package extract

import (
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/net/html"

	"github.com/HaymondM/Trip-Wire/engine"
)

var (
	skipTags = map[string]bool{"script": true, "style": true, "template": true, "svg": true, "head": true}
	// Tags that don't start a new block, so "ignore <b>previous</b> instructions"
	// stays one segment.
	inlineTags = map[string]bool{
		"a": true, "abbr": true, "b": true, "bdi": true, "bdo": true, "br": true, "cite": true,
		"code": true, "data": true, "dfn": true, "em": true, "font": true, "i": true, "kbd": true,
		"label": true, "mark": true, "q": true, "s": true, "samp": true, "small": true, "span": true,
		"strong": true, "sub": true, "sup": true, "time": true, "u": true, "var": true, "wbr": true,
	}
	textAttributes   = []string{"aria-label", "alt", "title"}
	metaKeys         = regexp.MustCompile(`description|title|keywords|^og:|^twitter:|^ai[-_:]|robots`)
	whitespaceRe     = regexp.MustCompile(`[ \t\n\r\f]+`)
	clipPathHiddenRe = regexp.MustCompile(`inset\((50|100)%`)
)

const colorMatchDistance = 24

var (
	defaultColor      = rgba{0, 0, 0, 1}
	defaultBackground = rgba{255, 255, 255, 1}
)

// inherited is the slice of computed style that flows from parent to child.
type inherited struct {
	containerReasons map[string]bool // hide the element and everything inside it
	visibilityHidden bool
	tinyFont         bool
	color            *rgba
	background       *rgba // nil when unknown (e.g. a background image)
	block            *html.Node
}

func (in inherited) child() inherited {
	reasons := make(map[string]bool, len(in.containerReasons))
	for r := range in.containerReasons {
		reasons[r] = true
	}
	in.containerReasons = reasons
	return in
}

type extractor struct {
	rules    []rule
	segments []engine.Segment
	group    *textGroup
}

type textGroup struct {
	block   *html.Node
	key     string
	reasons []string
	text    strings.Builder
}

// HTML parses a page and returns every piece of text an AI agent would read,
// tagged with the reasons a human viewer wouldn't see it.
func HTML(r io.Reader) ([]engine.Segment, error) {
	// Parse with scripting disabled so <noscript> content becomes real nodes:
	// an agent fetching the page sees it, a person with JavaScript on doesn't.
	doc, err := html.ParseWithOptions(r, html.ParseOptionEnableScripting(false))
	if err != nil {
		return nil, err
	}
	x := &extractor{}
	x.collectStylesheets(doc)
	white, black := defaultBackground, defaultColor
	x.walk(doc, inherited{containerReasons: map[string]bool{}, color: &black, background: &white, block: doc})
	x.flush()
	return x.segments, nil
}

func (x *extractor) collectStylesheets(n *html.Node) {
	if n.Type == html.ElementNode && n.Data == "style" && n.FirstChild != nil {
		x.rules = append(x.rules, parseStylesheet(n.FirstChild.Data)...)
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		x.collectStylesheets(c)
	}
}

func (x *extractor) add(text, source, tag string, reasons []string) {
	text = strings.TrimSpace(whitespaceRe.ReplaceAllString(text, " "))
	if text == "" {
		return
	}
	if reasons == nil {
		reasons = []string{}
	}
	x.segments = append(x.segments, engine.Segment{
		ID:            len(x.segments),
		Text:          text,
		Source:        source,
		Tag:           strings.ToUpper(tag),
		HiddenReasons: reasons,
	})
}

func (x *extractor) flush() {
	if x.group != nil {
		x.add(x.group.text.String(), "text", x.group.block.Data, x.group.reasons)
		x.group = nil
	}
}

func (x *extractor) walk(n *html.Node, in inherited) {
	switch n.Type {
	case html.CommentNode:
		x.flush()
		x.add(n.Data, "comment", parentTag(n), []string{"html-comment"})
		return
	case html.TextNode:
		x.addText(n, in)
		return
	case html.ElementNode:
		if n.Data == "meta" {
			x.addMeta(n)
			return
		}
		if skipTags[n.Data] {
			// Still visit comments inside <head>, and meta tags.
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				if c.Type == html.CommentNode || (c.Type == html.ElementNode && c.Data == "meta") {
					x.walk(c, in)
				}
			}
			return
		}
		in = x.applyStyle(n, in)
		x.addAttributes(n)
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		x.walk(c, in)
	}
}

func (x *extractor) addText(n *html.Node, in inherited) {
	if strings.TrimSpace(n.Data) == "" {
		// Keep the space between inline elements ("<b>previous</b> <em>instructions</em>")
		// so words don't fuse and slip past the patterns.
		if x.group != nil && x.group.block == in.block {
			x.group.text.WriteString(" ")
		}
		return
	}
	reasons := textReasons(in)
	key := strings.Join(reasons, ",")
	if x.group != nil && x.group.block == in.block && x.group.key == key {
		x.group.text.WriteString(n.Data)
		return
	}
	x.flush()
	x.group = &textGroup{block: in.block, key: key, reasons: reasons}
	x.group.text.WriteString(n.Data)
}

func textReasons(in inherited) []string {
	reasons := make([]string, 0, len(in.containerReasons)+2)
	for r := range in.containerReasons {
		reasons = append(reasons, r)
	}
	if in.visibilityHidden {
		reasons = append(reasons, "visibility-hidden")
	}
	if in.tinyFont {
		reasons = append(reasons, "tiny-font")
	}
	if in.color != nil {
		switch {
		case in.color.a < 0.05:
			reasons = append(reasons, "transparent-text")
		case in.background != nil && colorDistance(*in.color, *in.background) < colorMatchDistance:
			reasons = append(reasons, "color-matches-background")
		}
	}
	sort.Strings(reasons)
	return reasons
}

func colorDistance(x, y rgba) float64 {
	return math.Sqrt((x.r-y.r)*(x.r-y.r) + (x.g-y.g)*(x.g-y.g) + (x.b-y.b)*(x.b-y.b))
}

// cascaded is a candidate value for one property, with what the CSS cascade
// needs to pick a winner.
type cascaded struct {
	value     string
	important bool
	inline    bool
	spec      specificity
	order     int
}

// beats reports whether c wins over other: !important first, then the style
// attribute over stylesheet rules, then specificity, then later source order.
func (c cascaded) beats(other cascaded) bool {
	if c.important != other.important {
		return c.important
	}
	if c.inline != other.inline {
		return c.inline
	}
	if c.spec != other.spec {
		return other.spec.less(c.spec)
	}
	return c.order > other.order
}

// computedStyle resolves the element's declarations from matching <style>
// rules and its style attribute.
func (x *extractor) computedStyle(n *html.Node) declarations {
	winners := map[string]cascaded{}
	consider := func(prop string, c cascaded) {
		if current, ok := winners[prop]; !ok || c.beats(current) {
			winners[prop] = c
		}
	}
	for i, r := range x.rules {
		if !r.selector.matches(n) {
			continue
		}
		spec := r.selector.specificity()
		for prop, d := range r.decls {
			consider(prop, cascaded{value: d.value, important: d.important, spec: spec, order: i})
		}
	}
	for prop, d := range parseDeclarations(attr(n, "style")) {
		consider(prop, cascaded{value: d.value, important: d.important, inline: true, order: len(x.rules)})
	}
	decls := make(declarations, len(winners))
	for prop, c := range winners {
		decls[prop] = c.value
	}
	return decls
}

// applyStyle folds the element's computed style into what its children inherit.
func (x *extractor) applyStyle(n *html.Node, parent inherited) inherited {
	in := parent.child()
	decls := x.computedStyle(n)

	for _, class := range strings.Fields(attr(n, "class")) {
		switch hidingClasses[class] {
		case "display-none":
			in.containerReasons["display-none"] = true
		case "clipped":
			in.containerReasons["clipped"] = true
		case "visibility-hidden":
			in.visibilityHidden = true
		}
	}
	if hasAttr(n, "hidden") || decls["display"] == "none" {
		in.containerReasons["display-none"] = true
	}
	if n.Data == "noscript" {
		in.containerReasons["noscript"] = true
	}
	if v, ok := decls["opacity"]; ok {
		if f, ok := parseNumber(v); ok && f < 0.05 {
			in.containerReasons["transparent"] = true
		}
	}
	if strings.HasPrefix(decls["clip"], "rect(0") || clipPathHiddenRe.MatchString(decls["clip-path"]) {
		in.containerReasons["clipped"] = true
	}
	if offscreen(decls) {
		in.containerReasons["offscreen"] = true
	}
	if clipsOverflow(decls["overflow"]) && (isZero(decls["width"]) || isZero(decls["height"]) || isZero(decls["max-height"])) {
		in.containerReasons["zero-size"] = true
	}

	switch decls["visibility"] {
	case "hidden", "collapse":
		in.visibilityHidden = true
	case "visible":
		in.visibilityHidden = false
	}
	if v, ok := decls["font-size"]; ok {
		if px, ok := length(v); ok {
			in.tinyFont = px < 2
		}
	}
	if v, ok := decls["color"]; ok {
		if c, ok := parseColor(v); ok {
			in.color = &c
		}
	}
	if img := decls["background-image"]; (img != "" && img != "none") || strings.Contains(decls["background"], "url(") {
		in.background = nil
	} else if v, ok := backgroundColor(decls); ok {
		if c, ok := parseColor(v); ok && c.a > 0.5 {
			in.background = &c
		}
	}
	if !inlineTags[n.Data] && decls["display"] != "inline" && decls["display"] != "contents" {
		in.block = n
	}
	return in
}

func offscreen(d declarations) bool {
	if pos := d["position"]; pos == "absolute" || pos == "fixed" {
		for _, side := range []string{"left", "top", "right"} {
			if px, ok := length(d[side]); ok && px <= -999 {
				return true
			}
		}
		if px, ok := length(d["left"]); ok && px >= 5000 {
			return true
		}
	}
	if px, ok := length(d["text-indent"]); ok && px <= -999 {
		return true
	}
	return false
}

func clipsOverflow(v string) bool {
	return strings.Contains(v, "hidden") || strings.Contains(v, "clip")
}

func isZero(v string) bool {
	px, ok := length(v)
	return ok && px <= 1
}

func parseNumber(v string) (float64, bool) {
	v = strings.TrimSpace(v)
	if strings.HasSuffix(v, "%") {
		f, ok := parseNumber(strings.TrimSuffix(v, "%"))
		return f / 100, ok
	}
	f, err := strconv.ParseFloat(v, 64)
	return f, err == nil
}

func (x *extractor) addAttributes(n *html.Node) {
	for _, name := range textAttributes {
		if v := attr(n, name); v != "" {
			x.add(v, "attr:"+name, n.Data, []string{"attribute"})
		}
	}
}

func (x *extractor) addMeta(n *html.Node) {
	key := strings.ToLower(attr(n, "name"))
	if key == "" {
		key = strings.ToLower(attr(n, "property"))
	}
	if content := attr(n, "content"); content != "" && metaKeys.MatchString(key) {
		x.add(content, "meta", "", []string{"meta-tag"})
	}
}

func parentTag(n *html.Node) string {
	if n.Parent != nil && n.Parent.Type == html.ElementNode {
		return n.Parent.Data
	}
	return ""
}

func attr(n *html.Node, name string) string {
	for _, a := range n.Attr {
		if a.Key == name {
			return a.Val
		}
	}
	return ""
}

func hasAttr(n *html.Node, name string) bool {
	for _, a := range n.Attr {
		if a.Key == name {
			return true
		}
	}
	return false
}
