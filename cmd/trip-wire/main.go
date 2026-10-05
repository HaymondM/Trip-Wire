// Command trip-wire scans web content for hidden prompt injection, the way an
// AI agent would fetch it: raw content, no browser.
//
//	trip-wire scan <url | file | ->   scan and report; exit 0 below the
//	                                  --fail-on threshold, 1 at or above it, 2 on error
//	trip-wire hook claude-code        run as a Claude Code hook (JSON on stdin/stdout)
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/HaymondM/Trip-Wire/engine"
	"github.com/HaymondM/Trip-Wire/extract"
)

const (
	maxBodyBytes = 5 << 20
	userAgent    = "TripWire/0.1 (+https://github.com/HaymondM/Trip-Wire)"
)

const (
	exitOK      = 0
	exitTripped = 1
	exitError   = 2
)

var verdictRank = map[string]int{"clean": 0, "suspicious": 1, "dangerous": 2}

type result struct {
	Source      string        `json:"source"`
	ContentType string        `json:"contentType"`
	Report      engine.Report `json:"report"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

const usage = `usage:
  trip-wire scan [--json] [--fail-on dangerous|suspicious|never] [--timeout 15s] <url | file | ->
  trip-wire hook claude-code`

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	switch {
	case len(args) >= 1 && args[0] == "scan":
		return scanCommand(args, stdin, stdout, stderr)
	case len(args) == 2 && args[0] == "hook" && args[1] == "claude-code":
		return runClaudeCodeHook(stdin, stdout, stderr)
	}
	fmt.Fprintln(stderr, usage)
	return exitError
}

// analyze turns fetched content into a report.
func analyze(body []byte, contentType string) (engine.Report, error) {
	segments, err := segmentsFor(body, contentType)
	if err != nil {
		return engine.Report{}, err
	}
	return engine.Analyze(segments), nil
}

func scanCommand(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "print the report as JSON")
	failOn := fs.String("fail-on", "dangerous", "exit 1 when the verdict is at least this severe: dangerous, suspicious, or never")
	timeout := fs.Duration("timeout", 15*time.Second, "timeout for fetching a URL")
	if err := fs.Parse(args[1:]); err != nil {
		return exitError
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "trip-wire scan: expected exactly one URL, file path, or - for stdin")
		return exitError
	}
	threshold, ok := verdictRank[*failOn]
	if !ok && *failOn != "never" {
		fmt.Fprintf(stderr, "trip-wire scan: unknown --fail-on value %q\n", *failOn)
		return exitError
	}

	source := fs.Arg(0)
	body, contentType, err := load(source, stdin, *timeout)
	if err != nil {
		fmt.Fprintf(stderr, "trip-wire scan: %v\n", err)
		return exitError
	}
	report, err := analyze(body, contentType)
	if err != nil {
		fmt.Fprintf(stderr, "trip-wire scan: %v\n", err)
		return exitError
	}
	res := result{Source: source, ContentType: contentType, Report: report}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			fmt.Fprintf(stderr, "trip-wire scan: %v\n", err)
			return exitError
		}
	} else {
		printHuman(stdout, res)
	}

	if *failOn != "never" && verdictRank[res.Report.Verdict] >= threshold && res.Report.Verdict != "clean" {
		return exitTripped
	}
	return exitOK
}

// readLimited reads all of r, refusing input over the limit rather than
// scanning only a prefix: an injection placed past the cutoff must never
// come back as a clean verdict.
func readLimited(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxBodyBytes {
		return nil, fmt.Errorf("input exceeds the %d MiB limit; refusing to scan only part of it", maxBodyBytes>>20)
	}
	return body, nil
}

func load(source string, stdin io.Reader, timeout time.Duration) ([]byte, string, error) {
	if source == "-" {
		body, err := readLimited(stdin)
		return body, sniff(body, ""), err
	}
	if u, err := url.Parse(source); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		return fetch(u.String(), timeout)
	}
	f, err := os.Open(source)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	body, err := readLimited(f)
	return body, sniff(body, ""), err
}

func fetch(target string, timeout time.Duration) ([]byte, string, error) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, "", fmt.Errorf("fetching %s: %s", target, resp.Status)
	}
	body, err := readLimited(resp.Body)
	return body, sniff(body, resp.Header.Get("Content-Type")), err
}

// sniff reports the content type, trusting the server's header when present.
func sniff(body []byte, header string) string {
	if header != "" {
		return strings.ToLower(strings.TrimSpace(strings.Split(header, ";")[0]))
	}
	return strings.Split(http.DetectContentType(body), ";")[0]
}

func segmentsFor(body []byte, contentType string) ([]engine.Segment, error) {
	if strings.Contains(contentType, "html") || strings.Contains(contentType, "xml") {
		return extract.HTML(bytes.NewReader(body))
	}
	if strings.HasPrefix(contentType, "text/") || contentType == "application/json" {
		return extract.Text(string(body)), nil
	}
	return nil, errors.New("unsupported content type " + contentType)
}

func printHuman(w io.Writer, res result) {
	r := res.Report
	fmt.Fprintf(w, "Trip Wire: %s (score %d)  %s\n", strings.ToUpper(r.Verdict), r.Score, res.Source)
	fmt.Fprintf(w, "%d finding%s · %d hidden of %d text segments\n", len(r.Findings), plural(len(r.Findings)), r.Stats.HiddenSegments, r.Stats.SegmentsScanned)
	for _, f := range r.Findings {
		fmt.Fprintf(w, "\n[%s] %s\n", strings.ToUpper(string(f.Severity)), f.Message)
		if f.Decoded != "" {
			fmt.Fprintf(w, "    decoded: %q\n", f.Decoded)
		} else if f.Excerpt != "" {
			fmt.Fprintf(w, "    %q\n", f.Excerpt)
		}
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
