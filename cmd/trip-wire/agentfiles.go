package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/HaymondM/Trip-Wire/engine"
)

// Coding agents treat some files as standing instructions rather than data:
// CLAUDE.md, AGENTS.md, Cursor rules, skills, and so on. A hidden instruction
// in one of these, planted in a cloned repo or a dependency, steers the agent
// for the whole session, which makes them a higher-value target than a web page.

// agentFileNames are matched by name wherever they appear.
var agentFileNames = map[string]bool{
	"claude.md":               true,
	"claude.local.md":         true,
	"agents.md":               true,
	"agent.md":                true,
	"gemini.md":               true,
	"skill.md":                true,
	"copilot-instructions.md": true,
	".cursorrules":            true,
	".windsurfrules":          true,
	".clinerules":             true,
}

// agentDirs hold instruction files under any name (markdown or text only).
var agentDirs = []string{
	".claude/commands",
	".claude/agents",
	".claude/skills",
	".cursor/rules",
	".github/instructions",
	".github/prompts",
	".clinerules",
	".windsurf/rules",
}

// isAgentInstructionFile reports whether an agent would read the file at p as
// instructions. Only these files are scanned on Read: scanning every file
// would flag ordinary code, such as Trip Wire's own detection patterns.
func isAgentInstructionFile(p string) bool {
	p = filepath.ToSlash(p)
	base := strings.ToLower(path.Base(p))
	if agentFileNames[base] || strings.HasSuffix(base, ".instructions.md") || strings.HasSuffix(base, ".prompt.md") {
		return true
	}
	switch path.Ext(base) {
	case ".md", ".mdc", ".txt":
	default:
		return false
	}
	dir := "/" + strings.ToLower(path.Dir(p)) + "/"
	for _, d := range agentDirs {
		if strings.Contains(dir, "/"+d+"/") {
			return true
		}
	}
	return false
}

// forAgentFile tunes a report for an agent instruction file. These files
// exist to talk to an AI, so visible wording that addresses one or gives it a
// role is expected; hidden text, invisible characters, override and conceal
// wording, exfiltration and risky commands still count.
func forAgentFile(r engine.Report) engine.Report {
	return engine.WithoutVisible(r, "addresses-ai", "role-reassignment")
}

// afterRead scans agent instruction files that Claude reads. Dangerous content
// is replaced in the tool's own response shape; if the shape isn't recognized,
// Claude still gets the warning as added context.
//
// Claude Code loads the project's own CLAUDE.md at startup without a Read, so
// this hook can't see that one: run `trip-wire scan-agent-files` on a repo
// before opening it in an agent.
func afterRead(in hookInput) *hookOutput {
	var input struct {
		FilePath string `json:"file_path"`
	}
	if err := json.Unmarshal(in.ToolInput, &input); err != nil || !isAgentInstructionFile(input.FilePath) {
		return nil
	}
	report, ok := worstReportWith(collectStrings(in.ToolResponse), forAgentFile)
	if !ok {
		return nil
	}
	source := "the agent instruction file " + truncate(input.FilePath, 160)
	switch report.Verdict {
	case "dangerous":
		notice := describe("Trip Wire withheld this file", source, report)
		out := &hookSpecificOutput{HookEventName: "PostToolUse", AdditionalContext: notice}
		if replaced, ok := replaceReadOutput(in.ToolResponse, notice); ok {
			out.UpdatedToolOutput = replaced
		}
		return &hookOutput{HookSpecificOutput: out}
	case "suspicious":
		return &hookOutput{HookSpecificOutput: &hookSpecificOutput{
			HookEventName:     "PostToolUse",
			AdditionalContext: describe("Trip Wire warning", source, report),
		}}
	}
	return nil
}

// replaceReadOutput swaps the file content in Read's response
// ({type, file: {filePath, content, numLines, ...}}) for the notice.
func replaceReadOutput(original json.RawMessage, notice string) (any, bool) {
	var v any
	if err := json.Unmarshal(original, &v); err != nil {
		return nil, false
	}
	switch t := v.(type) {
	case string:
		return notice, true
	case map[string]any:
		file, ok := t["file"].(map[string]any)
		if !ok {
			return nil, false
		}
		if _, ok := file["content"].(string); !ok {
			return nil, false
		}
		file["content"] = notice
		if _, ok := file["numLines"]; ok {
			file["numLines"] = strings.Count(notice, "\n") + 1
		}
		return t, true
	}
	return nil, false
}

// afterMCP scans the result of every MCP tool call. MCP servers return
// whatever their upstream source holds (tickets, docs, chat messages, web
// pages), so their results get the same content-based scan as Bash output.
func afterMCP(in hookInput) *hookOutput {
	report, ok := worstReport(collectStrings(in.ToolResponse))
	if !ok {
		return nil
	}
	source := "the result of MCP tool " + truncate(in.ToolName, 120)
	switch report.Verdict {
	case "dangerous":
		notice := describe("Trip Wire withheld this tool result", source, report)
		replaced := replaceMCPOutput(in.ToolResponse, notice)
		return &hookOutput{HookSpecificOutput: &hookSpecificOutput{
			HookEventName:        "PostToolUse",
			UpdatedToolOutput:    replaced,
			UpdatedMCPToolOutput: replaced,
			// Also sent as context, so Claude is warned even if a Claude Code
			// version doesn't apply the replacement.
			AdditionalContext: notice,
		}}
	case "suspicious":
		return &hookOutput{HookSpecificOutput: &hookSpecificOutput{
			HookEventName:     "PostToolUse",
			AdditionalContext: describe("Trip Wire warning", source, report),
		}}
	}
	return nil
}

// replaceMCPOutput builds a replacement in the shape of an MCP result: a list
// of content blocks, an object with a content list, or a plain string.
func replaceMCPOutput(original json.RawMessage, notice string) any {
	blocks := []any{map[string]any{"type": "text", "text": notice}}
	var v any
	if err := json.Unmarshal(original, &v); err != nil {
		return notice
	}
	switch t := v.(type) {
	case string:
		return notice
	case map[string]any:
		if _, ok := t["content"]; ok {
			t["content"] = blocks
			// Structured results can carry the same injected text.
			delete(t, "structuredContent")
			return t
		}
	}
	return blocks
}

// skippedDirs aren't walked by scan-agent-files.
var skippedDirs = map[string]bool{".git": true, "node_modules": true}

type agentFilesResult struct {
	Root  string   `json:"root"`
	Files []result `json:"files"`
}

// scanAgentFilesCommand scans every agent instruction file under a directory,
// for checking a repo before an agent works in it, or as a CI gate.
func scanAgentFilesCommand(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("scan-agent-files", flag.ContinueOnError)
	flags.SetOutput(stderr)
	asJSON := flags.Bool("json", false, "print the report as JSON")
	explain := flags.Bool("explain", false, "include matched rules, hiding techniques, and full extracted segments for findings")
	failOn := flags.String("fail-on", "dangerous", "exit 1 when any file's verdict is at least this severe: dangerous, suspicious, or never")
	if err := flags.Parse(args[1:]); err != nil {
		return exitError
	}
	if flags.NArg() > 1 {
		fmt.Fprintln(stderr, "trip-wire scan-agent-files: expected at most one directory")
		return exitError
	}
	threshold, ok := verdictRank[*failOn]
	if !ok && *failOn != "never" {
		fmt.Fprintf(stderr, "trip-wire scan-agent-files: unknown --fail-on value %q\n", *failOn)
		return exitError
	}
	root := "."
	if flags.NArg() == 1 {
		root = flags.Arg(0)
	}

	out := agentFilesResult{Root: root, Files: []result{}}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && skippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || !isAgentInstructionFile(p) {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		body, err := readLimited(f)
		f.Close()
		if err != nil {
			// Refuse rather than skip: an unscanned file must not pass as clean.
			return fmt.Errorf("%s: %w", p, err)
		}
		report, segments, found := worstReportWithSegments([]string{string(body)}, forAgentFile)
		if !found {
			report = engine.Report{Verdict: "clean", Findings: []engine.Finding{}}
		}
		res := result{Source: p, ContentType: "text/plain", Report: report}
		if *explain {
			res.Segments = findingSegments(report, segments)
		}
		out.Files = append(out.Files, res)
		return nil
	})
	if err != nil {
		fmt.Fprintf(stderr, "trip-wire scan-agent-files: %v\n", err)
		return exitError
	}

	tripped := false
	counts := map[string]int{}
	for _, r := range out.Files {
		counts[r.Report.Verdict]++
		if *failOn != "never" && r.Report.Verdict != "clean" && verdictRank[r.Report.Verdict] >= threshold {
			tripped = true
		}
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fmt.Fprintf(stderr, "trip-wire scan-agent-files: %v\n", err)
			return exitError
		}
	} else {
		printAgentFiles(stdout, out, counts)
	}

	if tripped {
		return exitTripped
	}
	return exitOK
}

func printAgentFiles(w io.Writer, out agentFilesResult, counts map[string]int) {
	if len(out.Files) == 0 {
		fmt.Fprintf(w, "Trip Wire: no agent instruction files found under %s\n", out.Root)
		return
	}
	fmt.Fprintf(w, "Trip Wire: scanned %d agent instruction file%s under %s: %d dangerous, %d suspicious, %d clean\n",
		len(out.Files), plural(len(out.Files)), out.Root, counts["dangerous"], counts["suspicious"], counts["clean"])
	for _, r := range out.Files {
		if r.Report.Verdict == "clean" && len(r.Segments) == 0 {
			fmt.Fprintf(w, "\nCLEAN  %s\n", r.Source)
			continue
		}
		fmt.Fprintln(w)
		printHuman(w, r)
	}
}
