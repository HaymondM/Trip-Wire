package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/HaymondM/Trip-Wire/engine"
)

const (
	policyEnv      = "TRIP_WIRE_POLICY"
	maxPolicyBytes = 1 << 20
)

type hookPolicy struct {
	Version    int               `json:"version"`
	Strict     bool              `json:"strict"`
	WarnOn     string            `json:"warn_on"`
	BlockOn    string            `json:"block_on"`
	Exceptions []policyException `json:"exceptions"`
	Audit      *auditSettings    `json:"audit,omitempty"`
	digest     string
}

type policyException struct {
	ID            string    `json:"id"`
	Event         string    `json:"event"`
	Tool          string    `json:"tool"`
	InputSHA256   string    `json:"input_sha256"`
	ContentSHA256 string    `json:"content_sha256"`
	ExpiresAt     time.Time `json:"expires_at"`
	Reason        string    `json:"reason"`
}

type auditSettings struct {
	Path         string `json:"path"`
	IncludeClean bool   `json:"include_clean"`
}

var (
	exceptionIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	toolNameRe    = regexp.MustCompile(`^(WebFetch|Bash|Read|mcp__[A-Za-z0-9_-]{1,120})$`)
	sha256Re      = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

func defaultHookPolicy() hookPolicy {
	return hookPolicy{Version: 1, WarnOn: "suspicious", BlockOn: "dangerous"}
}

func loadHookPolicy() (hookPolicy, error) {
	p := defaultHookPolicy()
	policyPath := os.Getenv(policyEnv)
	if policyPath == "" {
		return p, nil
	}
	if !filepath.IsAbs(policyPath) {
		return p, errors.New("policy path must be absolute")
	}
	info, err := os.Stat(policyPath)
	if err != nil {
		return p, fmt.Errorf("inspect policy: %w", err)
	}
	if !info.Mode().IsRegular() {
		return p, errors.New("policy must be a regular file")
	}
	f, err := os.Open(policyPath)
	if err != nil {
		return p, fmt.Errorf("open policy: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxPolicyBytes+1))
	if err != nil {
		return p, fmt.Errorf("read policy: %w", err)
	}
	if len(data) > maxPolicyBytes {
		return p, errors.New("policy exceeds 1 MiB")
	}
	p.Version = 0
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return p, fmt.Errorf("decode policy: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return p, errors.New("policy must contain exactly one JSON object")
	}
	if err := p.validate(); err != nil {
		return p, err
	}
	p.digest = fingerprintBytes(data)
	return p, nil
}

func (p hookPolicy) validate() error {
	if p.Version != 1 {
		return errors.New("policy version must be 1")
	}
	rank := func(value string) (int, bool) {
		switch value {
		case "suspicious":
			return 1, true
		case "dangerous":
			return 2, true
		case "never":
			return 3, true
		default:
			return 0, false
		}
	}
	warn, ok := rank(p.WarnOn)
	if !ok {
		return errors.New("warn_on must be suspicious, dangerous, or never")
	}
	block, ok := rank(p.BlockOn)
	if !ok {
		return errors.New("block_on must be suspicious, dangerous, or never")
	}
	if warn != 3 && warn > block {
		return errors.New("warn_on must not be more severe than block_on")
	}
	if p.Strict && p.BlockOn == "never" {
		return errors.New("strict policy cannot disable blocking")
	}
	if p.Audit != nil && !filepath.IsAbs(p.Audit.Path) {
		return errors.New("audit path must be absolute")
	}
	ids := make(map[string]bool)
	for _, e := range p.Exceptions {
		if !exceptionIDRe.MatchString(e.ID) || ids[e.ID] {
			return errors.New("exception IDs must be unique and contain only letters, digits, dot, underscore, or hyphen")
		}
		ids[e.ID] = true
		if !toolNameRe.MatchString(e.Tool) ||
			(e.Event != "PreToolUse" && e.Event != "PostToolUse") ||
			(e.Tool == "WebFetch") != (e.Event == "PreToolUse") {
			return fmt.Errorf("exception %s has an unsupported event or tool", e.ID)
		}
		if !sha256Re.MatchString(e.InputSHA256) || !sha256Re.MatchString(e.ContentSHA256) {
			return fmt.Errorf("exception %s needs lowercase SHA-256 input and content fingerprints", e.ID)
		}
		if e.ExpiresAt.IsZero() || strings.TrimSpace(e.Reason) == "" {
			return fmt.Errorf("exception %s needs an expiry and reason", e.ID)
		}
	}
	return nil
}

func fingerprintBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// fingerprintJSON is independent of object-key order and insignificant whitespace.
func fingerprintJSON(raw json.RawMessage) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return "", err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return "", errors.New("expected exactly one JSON value")
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return fingerprintBytes(canonical), nil
}

func (p hookPolicy) action(in hookInput, report engine.Report, contentHash string, now time.Time) (string, string, error) {
	rank, ok := verdictRank[report.Verdict]
	if !ok {
		return "", "", fmt.Errorf("unknown scan verdict %q", report.Verdict)
	}
	if report.Verdict == "clean" {
		return "allow", "", nil
	}
	if p.BlockOn != "never" && rank >= verdictRank[p.BlockOn] {
		inputHash, err := fingerprintJSON(in.ToolInput)
		if err == nil && contentHash != "" {
			for _, e := range p.Exceptions {
				if e.Event == in.HookEventName && e.Tool == in.ToolName &&
					e.InputSHA256 == inputHash && e.ContentSHA256 == contentHash && now.Before(e.ExpiresAt) {
					return "warn", e.ID, nil
				}
			}
		}
		return "block", "", nil
	}
	if p.WarnOn != "never" && rank >= verdictRank[p.WarnOn] {
		return "warn", "", nil
	}
	return "allow", "", nil
}

type auditEvent struct {
	SchemaVersion int       `json:"schema_version"`
	Timestamp     time.Time `json:"timestamp"`
	Event         string    `json:"event"`
	Tool          string    `json:"tool"`
	PolicySHA256  string    `json:"policy_sha256,omitempty"`
	InputSHA256   string    `json:"input_sha256,omitempty"`
	ContentSHA256 string    `json:"content_sha256,omitempty"`
	Action        string    `json:"action"`
	Reason        string    `json:"reason"`
	Verdict       string    `json:"verdict,omitempty"`
	Score         *int      `json:"score,omitempty"`
	RuleIDs       []string  `json:"rule_ids,omitempty"`
	ExceptionID   string    `json:"exception_id,omitempty"`
}

func writeAudit(settings *auditSettings, in hookInput, result hookResult, policyHash string) error {
	if settings == nil || result.action == "" {
		return nil
	}
	if result.action == "allow" && !settings.IncludeClean && (result.report == nil || result.report.Verdict == "clean") {
		return nil
	}
	event := auditEvent{
		SchemaVersion: 1, Timestamp: time.Now().UTC(), Event: in.HookEventName, Tool: in.ToolName,
		PolicySHA256: policyHash, ContentSHA256: result.contentHash, Action: result.action, Reason: result.reason,
		ExceptionID: result.exceptionID,
	}
	if !toolNameRe.MatchString(event.Tool) {
		event.Tool = "unknown"
	}
	if hash, err := fingerprintJSON(in.ToolInput); err == nil {
		event.InputSHA256 = hash
	}
	if result.report != nil {
		event.Verdict = result.report.Verdict
		event.Score = &result.report.Score
		ids := make(map[string]bool)
		for _, finding := range result.report.Findings {
			ids[finding.RuleID] = true
			for _, id := range finding.MatchedRules {
				ids[id] = true
			}
		}
		for id := range ids {
			event.RuleIDs = append(event.RuleIDs, id)
		}
		sort.Strings(event.RuleIDs)
	}
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode audit event: %w", err)
	}
	data = append(data, '\n')
	info, err := os.Lstat(settings.Path)
	if err == nil && !info.Mode().IsRegular() {
		return errors.New("audit path must be a regular file, not a symlink")
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect audit log: %w", err)
	}
	f, err := os.OpenFile(settings.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	n, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil {
		return fmt.Errorf("write audit event: %w", writeErr)
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	if closeErr != nil {
		return fmt.Errorf("close audit log: %w", closeErr)
	}
	return nil
}
