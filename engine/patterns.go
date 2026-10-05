package engine

import "regexp"

// instructionPattern is a phrase shape that's common in prompt injection
// and rare in ordinary page copy.
type instructionPattern struct {
	id          string
	description string
	re          *regexp.Regexp
}

var instructionPatterns = []instructionPattern{
	{
		id:          "override-instructions",
		description: "tells an AI to ignore or replace its instructions",
		re:          regexp.MustCompile(`(?i)\b(ignore|disregard|forget|override|bypass)\b[^.!?\n]{0,40}\b(previous|prior|above|earlier|all|any|your|system|original)\b[^.!?\n]{0,25}\b(instructions?|prompts?|rules|directions|guidelines|directives)\b`),
	},
	{
		id:          "addresses-ai",
		description: "speaks directly to an AI reading the page",
		re:          regexp.MustCompile(`(?i)(\bif you are an? (ai|llm|large language model|language model|assistant|agent|bot|chatbot)\b|\b(note|message|instructions?) (to|for) (the |any )?(ai|llm|assistant|agent|model|bot)s?\b|\b(ai|llm) (assistants?|agents?|models?)\b[^.!?\n]{0,30}\b(reading|summari[sz]ing|processing|browsing)\b)`),
	},
	{
		id:          "role-reassignment",
		description: "tries to give an AI a new role or persona",
		re:          regexp.MustCompile(`(?i)\byou are (now|no longer)\b|\bfrom now on,? you\b|\byour new (role|task|instructions?|goal) (is|are)\b`),
	},
	{
		id:          "fake-system-marker",
		description: "imitates chat-format or system-prompt markers",
		re:          regexp.MustCompile(`(?i)(<\|im_start\|>|<\|im_end\|>|<\|system\|>|\[/?INST\]|<<SYS>>|###\s*(system|instruction)|\bsystem prompt\b|(^|\n)\s*(system|assistant)\s*:)`),
	},
	{
		id:          "conceal-from-user",
		description: "asks an AI to hide something from the person using it",
		re:          regexp.MustCompile(`(?i)\b(do not|don't|never)\b[^.!?\n]{0,15}\b(tell|inform|mention|reveal|show|disclose)\b[^.!?\n]{0,25}\b(the )?(user|human|reader|person)\b`),
	},
	{
		id:          "exfiltration",
		description: "asks for data to be sent to an outside address",
		re:          regexp.MustCompile(`(?i)(\b(send|forward|post|upload|email|transmit|include)\b[^.!?\n]{0,60}\b(password|api key|token|credentials?|cookies?|session|email address|conversation|chat history|personal (data|information))\b|!\[[^\]]*\]\(https?://[^)\s]*\?[^)\s]*\))`),
	},
}

// matchInstructions returns every pattern that matches text.
func matchInstructions(text string) []instructionPattern {
	var matched []instructionPattern
	for _, p := range instructionPatterns {
		if p.re.MatchString(text) {
			matched = append(matched, p)
		}
	}
	return matched
}

// Shared by commandRe and riskyCommandRe so the two can't drift apart.
const (
	// A download piped into something that executes it: any sh-family shell
	// or common interpreter, by bare name or path, optionally behind sudo
	// (with flags) or /usr/bin/env.
	pipeToExecutor = `\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+(-\S+\s+)*)?(\S*/)?(env\s+)?((a|ba|da|fi|k|z|c|tc)?sh|python[0-9.]*|perl|ruby|node)\b`
	// Software from somewhere other than the default registry, or a decoded
	// payload being executed.
	riskyFlags = `--(extra-)?index-url\b|--trusted-host\b|--registry\b|\bbase64\s+(-d|--decode)\b|\b(iex|Invoke-Expression)\b`
)

// commandRe matches text telling the reader to run something: package
// installs, downloads piped into a shell, and flags that change where software
// comes from. A subtle injection doesn't need to address an AI; it only needs
// an agent to carry out a command that a person never saw.
var commandRe = regexp.MustCompile(`(?i)(\b(pip3?|pipx|npm|npx|yarn|pnpm|gem|cargo|go|brew|apt-get|apt|yum|dnf|choco|winget|conda)\s+(install|add|get)\b|` +
	pipeToExecutor + `|` + riskyFlags + `|\bsudo\s+\S|\bchmod\s+\+x\b)`)

// riskyCommandRe is the subset of commands that's risky even on a legitimate
// page: a download piped straight into a shell or interpreter, software from
// a non-default package source, or a decoded payload being executed.
var riskyCommandRe = regexp.MustCompile(`(?i)(` + pipeToExecutor + `|` + riskyFlags + `)`)

var linkRe = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>]+`)
