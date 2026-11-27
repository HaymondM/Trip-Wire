package main

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/HaymondM/Trip-Wire/engine"
)

type detectionCorpus struct {
	MaxMissedPercent        int          `json:"max_missed_percent"`
	MaxFalsePositivePercent int          `json:"max_false_positive_percent"`
	MinBlockedPercent       int          `json:"min_blocked_percent"`
	KnownMisses             []string     `json:"known_misses"`
	KnownFalsePositives     []string     `json:"known_false_positives"`
	Cases                   []corpusCase `json:"cases"`
}

type corpusCase struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Context string `json:"context"`
	Content string `json:"content"`
}

func loadDetectionCorpus(tb testing.TB) detectionCorpus {
	tb.Helper()
	data, err := os.ReadFile("testdata/detection-corpus.json")
	if err != nil {
		tb.Fatal(err)
	}
	var corpus detectionCorpus
	if err := json.Unmarshal(data, &corpus); err != nil {
		tb.Fatal(err)
	}
	if corpus.MaxMissedPercent < 0 || corpus.MaxMissedPercent > 100 ||
		corpus.MaxFalsePositivePercent < 0 || corpus.MaxFalsePositivePercent > 100 ||
		corpus.MinBlockedPercent < 0 || corpus.MinBlockedPercent > 100 || len(corpus.Cases) == 0 {
		tb.Fatal("invalid corpus limits or empty corpus")
	}
	ids := make(map[string]string)
	for _, sample := range corpus.Cases {
		if sample.ID == "" || ids[sample.ID] != "" || sample.Content == "" ||
			(sample.Label != "attack" && sample.Label != "benign") {
			tb.Fatalf("invalid or duplicate corpus case: %+v", sample)
		}
		ids[sample.ID] = sample.Label
	}
	for _, id := range corpus.KnownMisses {
		if ids[id] != "attack" {
			tb.Fatalf("known miss %q is not an attack case", id)
		}
	}
	for _, id := range corpus.KnownFalsePositives {
		if ids[id] != "benign" {
			tb.Fatalf("known false positive %q is not a benign case", id)
		}
	}
	return corpus
}

func scanCorpusCase(tb testing.TB, sample corpusCase) engine.Report {
	tb.Helper()
	var report engine.Report
	var err error
	switch sample.Context {
	case "html":
		report, err = analyze([]byte(sample.Content), "text/html")
	case "text":
		report, err = analyze([]byte(sample.Content), "text/plain")
	case "tool", "agent":
		var adjust func(engine.Report) engine.Report
		if sample.Context == "agent" {
			adjust = forAgentFile
		}
		var found bool
		report, found, err = worstReportWith([]string{sample.Content}, adjust)
		if err != nil {
			tb.Fatalf("%s: %v", sample.ID, err)
		}
		if !found {
			tb.Fatalf("%s produced no report", sample.ID)
		}
	default:
		tb.Fatalf("%s has unknown context %q", sample.ID, sample.Context)
	}
	if err != nil {
		tb.Fatalf("%s: %v", sample.ID, err)
	}
	return report
}

func TestDetectionCorpus(t *testing.T) {
	corpus := loadDetectionCorpus(t)
	knownMisses, knownFalsePositives := make(map[string]bool), make(map[string]bool)
	for _, id := range corpus.KnownMisses {
		knownMisses[id] = true
	}
	for _, id := range corpus.KnownFalsePositives {
		knownFalsePositives[id] = true
	}
	var attacks, benign, caught, blocked int
	var missed, falsePositives []string
	durations := make([]time.Duration, 0, len(corpus.Cases))
	for _, sample := range corpus.Cases {
		start := time.Now()
		report := scanCorpusCase(t, sample)
		durations = append(durations, time.Since(start))
		if sample.Label == "attack" {
			attacks++
			if report.Verdict == "clean" {
				missed = append(missed, sample.ID)
				if !knownMisses[sample.ID] {
					t.Errorf("new missed attack: %s", sample.ID)
				}
			} else {
				caught++
			}
			if report.Verdict == "dangerous" {
				blocked++
			}
		} else {
			benign++
			if report.Verdict != "clean" {
				falsePositives = append(falsePositives, sample.ID)
				if !knownFalsePositives[sample.ID] {
					t.Errorf("new false positive: %s", sample.ID)
				}
			}
		}
	}
	if attacks == 0 || benign == 0 {
		t.Fatal("corpus needs both attack and benign cases")
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	p50 := durations[(len(durations)*50+99)/100-1]
	p95 := durations[(len(durations)*95+99)/100-1]
	t.Logf("synthetic corpus: %d/%d attacks detected, %d/%d blocked by the default threshold; %d/%d benign flagged",
		caught, attacks, blocked, attacks, len(falsePositives), benign)
	t.Logf("missed: %s; false positives: %s", strings.Join(missed, ", "), strings.Join(falsePositives, ", "))
	t.Logf("single-scan latency: p50=%s p95=%s (informational, environment dependent)", p50, p95)
	if len(missed)*100 > attacks*corpus.MaxMissedPercent {
		t.Errorf("missed %d/%d attacks, exceeding the %d%% regression limit", len(missed), attacks, corpus.MaxMissedPercent)
	}
	if len(falsePositives)*100 > benign*corpus.MaxFalsePositivePercent {
		t.Errorf("flagged %d/%d benign cases, exceeding the %d%% regression limit", len(falsePositives), benign, corpus.MaxFalsePositivePercent)
	}
	if blocked*100 < attacks*corpus.MinBlockedPercent {
		t.Errorf("blocked %d/%d attacks by default, below the %d%% regression limit", blocked, attacks, corpus.MinBlockedPercent)
	}
}

func BenchmarkDetectionCorpus(b *testing.B) {
	corpus := loadDetectionCorpus(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanCorpusCase(b, corpus.Cases[i%len(corpus.Cases)])
	}
}
