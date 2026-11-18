// Package injection detects injection-shaped text in untrusted, display-bound
// fields. It is a veto only: a finding denies the request, while a clean result
// never lowers risk, selects a target, or grants authority. Matching is
// deterministic and reasons contain only fixed category names, never the
// untrusted text that produced them.
package injection

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// Field is one display-bound value. Name must be a fixed label chosen by the
// core; Value is untrusted data.
type Field struct {
	Name  string
	Value string
}

// Finding records a stable category for one field. The offending value is
// deliberately not retained.
type Finding struct {
	Field    string `json:"field"`
	Category string `json:"category"`
}

// Stable category names. They are safe to log and to expose in denial
// summaries because they are constants, not data-derived strings.
const (
	InstructionOverride = "instruction_override"
	RoleOverride        = "role_override"
	SecretAccess        = "secret_access"
	ShellSyntax         = "shell_syntax"
	Exfiltration        = "exfiltration"
	ProtocolSpoof       = "protocol_spoof"
	DisplayControl      = "display_control"
)

var patterns = []struct {
	category string
	re       *regexp.Regexp
}{
	{InstructionOverride, regexp.MustCompile(`(?i)(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|prompts)`)},
	{RoleOverride, regexp.MustCompile(`(?i)(you\s+are\s+now|act\s+as|new\s+(system\s+)?prompt|developer\s+mode)`)},
	{SecretAccess, regexp.MustCompile(`(?i)(/etc/(shadow|passwd|sudoers)|id_rsa|\.ssh/|api[_-]?key|secret|token)`)},
	{ShellSyntax, regexp.MustCompile("(?i)(rm\\s+-rf|;\\s*(sh|bash|zsh)\\b|\\$\\(|`[^`]+`|\\|\\s*(sh|bash)\\b|curl\\s+http)")},
	{Exfiltration, regexp.MustCompile(`(?i)(exfiltrat|send\s+(this|the)\s+(data|file|content)\s+to|base64\s+-d|nc\s+-e)`)},
	{ProtocolSpoof, regexp.MustCompile(`(?i)"(action|type)"\s*:\s*"(process\.(kill|terminate)|shell\.exec|command\.run)"`)},
}

// invisible matches characters used to hide or reorder displayed text. The
// same characters are removed from a copy before phrase matching so a payload
// cannot evade detection by splitting a phrase with zero-width characters.
var invisible = map[rune]bool{
	'\u061c': true,
	'\u200b': true, '\u200c': true, '\u200d': true,
	'\u200e': true, '\u200f': true,
	'\u202a': true, '\u202b': true, '\u202c': true,
	'\u202d': true, '\u202e': true,
	'\u2066': true, '\u2067': true, '\u2068': true, '\u2069': true,
	'\ufeff': true,
}

// Scan returns every category matched by a field. Findings are ordered by
// field order and then category order, so logs and tests are deterministic.
func Scan(fields ...Field) []Finding {
	out := []Finding{}
	for _, field := range fields {
		categories := map[string]bool{}
		if hasDisplayControl(field.Value) {
			categories[DisplayControl] = true
		}
		matchText := normalizeForMatch(field.Value)
		for _, pattern := range patterns {
			if pattern.re.MatchString(matchText) {
				categories[pattern.category] = true
			}
		}
		ordered := make([]string, 0, len(categories))
		for category := range categories {
			ordered = append(ordered, category)
		}
		sort.Strings(ordered)
		for _, category := range ordered {
			out = append(out, Finding{Field: field.Name, Category: category})
		}
	}
	return out
}

// Veto returns a content-free error when any field fails the scan. A nil
// result means "no finding"; it is not an authorization decision and grants
// nothing by itself.
func Veto(fields ...Field) error {
	findings := Scan(fields...)
	if len(findings) == 0 {
		return nil
	}
	return fmt.Errorf("injection veto: %s", Summary(findings))
}

// Summary reduces findings to sorted, fixed category names. No field value is
// ever included, so the result is safe for a denial reason or audit row.
func Summary(findings []Finding) string {
	seen := map[string]bool{}
	categories := []string{}
	for _, finding := range findings {
		if seen[finding.Category] {
			continue
		}
		seen[finding.Category] = true
		categories = append(categories, finding.Category)
	}
	sort.Strings(categories)
	return strings.Join(categories, ", ")
}

func hasDisplayControl(value string) bool {
	for _, r := range value {
		if invisible[r] {
			return true
		}
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return true
		}
	}
	return false
}

func normalizeForMatch(value string) string {
	var builder strings.Builder
	for _, r := range value {
		if invisible[r] {
			continue
		}
		if unicode.IsControl(r) {
			builder.WriteByte(' ')
			continue
		}
		builder.WriteRune(r)
	}
	return builder.String()
}
