package extract

import (
	"math"
	"testing"
)

func TestParseColorPercentages(t *testing.T) {
	cases := map[string]rgba{
		"rgb(100% 100% 100%)":      {255, 255, 255, 1},
		"rgb(0%, 50%, 100%)":       {0, 127.5, 255, 1},
		"rgba(0, 0, 0, 1%)":        {0, 0, 0, 0.01},
		"rgb(255 255 255 / 50%)":   {255, 255, 255, 0.5},
		"rgba(255, 255, 255, 0.2)": {255, 255, 255, 0.2},
	}
	for in, want := range cases {
		got, ok := parseColor(in)
		if !ok {
			t.Errorf("parseColor(%q) failed", in)
			continue
		}
		if math.Abs(got.r-want.r) > 0.01 || math.Abs(got.g-want.g) > 0.01 || math.Abs(got.b-want.b) > 0.01 || math.Abs(got.a-want.a) > 0.001 {
			t.Errorf("parseColor(%q) = %+v, want %+v", in, got, want)
		}
	}
}

func TestPercentWhiteTextOnWhiteIsHidden(t *testing.T) {
	reasons := hiddenReasonsFor(t, `<body><p style="color:rgb(100% 100% 100%)">payload</p></body>`, "payload")
	found := false
	for _, r := range reasons {
		found = found || r == "color-matches-background"
	}
	if !found {
		t.Fatalf("white text via percentages should be hidden, got %v", reasons)
	}
}
