package shield

import "regexp"

// SecretPattern defines a regex pattern paired with an identification label.
type SecretPattern struct {
	Name    string
	Regex   *regexp.Regexp
	MinLen  int
	Entropy float64
}

// BuiltinPatterns provides curated high-fidelity detection rules for credentials.
var BuiltinPatterns = []SecretPattern{
	{
		Name:  "AWS Access Key ID",
		Regex: regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	},
	{
		Name:  "Anthropic API Key",
		Regex: regexp.MustCompile(`\bsk-ant-[a-zA-Z0-9_\-]{32,}\b`),
	},
	{
		Name:  "OpenAI API Key",
		Regex: regexp.MustCompile(`\bsk-[a-zA-Z0-9_\-]{20,}\b`),
	},
	{
		Name:  "Google API Key",
		Regex: regexp.MustCompile(`\bAIza[0-9A-Za-z\\-_]{35}\b`),
	},
	{
		Name:  "GitHub Personal Access Token",
		Regex: regexp.MustCompile(`\bghp_[a-zA-Z0-9]{36}\b`),
	},
	{
		Name:  "GitHub Fine-Grained Token",
		Regex: regexp.MustCompile(`\bgithub_pat_[a-zA-Z0-9_]{82}\b`),
	},
	{
		Name:  "Slack Token",
		Regex: regexp.MustCompile(`\bxox[baprs]-[0-9a-zA-Z]{10,48}\b`),
	},
	{
		Name:  "Database Connection URI",
		Regex: regexp.MustCompile(`\b(?:postgres|mysql|mongodb|redis|amqp):\/\/[^:\s]+:([^@\s]+)@[^\s]+\b`),
	},
	{
		Name:  "Private Key Header",
		Regex: regexp.MustCompile(`-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----[\s\S]+?-----END (?:RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----`),
	},
	{
		Name:  "Generic Key Assignment",
		Regex: regexp.MustCompile(`(?i)(?:api_key|apikey|secret|password|token|bearer|credential)\s*[:=]\s*["']([^"']{8,})["']`),
	},
}
