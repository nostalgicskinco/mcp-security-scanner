// Copyright 2024 Nostalgic Skin Co.
// SPDX-License-Identifier: AGPL-3.0-or-later

package rules

import (
	"regexp"
	"strings"
)

// PromptInjectionRule detects prompt injection surfaces in MCP tool outputs.
type PromptInjectionRule struct{}

var injectionRiskPatterns = []*regexp.Regexp{
	// Tool output directly from user/external input without sanitization.
	regexp.MustCompile(`(?i)(?:return|yield|respond)\s*.*(?:raw|unsanitized|unescaped|user_input|external)`),
	// String formatting with external data in tool responses.
	regexp.MustCompile(`(?i)(?:f["']|\.format\(|%s|fmt\.Sprintf)\s*.*(?:result|output|response|data)\s*.*(?:tool|mcp)`),
	// Direct HTML/markdown injection in tool outputs.
	regexp.MustCompile(`(?i)(?:TextContent|text_content|content=)\s*.*(?:request|input|query|fetch|http|url)`),
	// Unvalidated URL/link inclusion in responses.
	regexp.MustCompile(`(?i)(?:href|src|url|link)\s*=\s*(?:request|input|param|data|result)`),
}

var sanitizationPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:sanitize|escape|encode|strip|clean|purify|bleach|DOMPurify|html\.escape|markupsafe)`),
	regexp.MustCompile(`(?i)(?:allowlist|whitelist|validate_output|output_filter|content_filter)`),
}

func (r *PromptInjectionRule) ID() string               { return "MCP-003" }
func (r *PromptInjectionRule) Name() string              { return "Prompt Injection Surface" }
func (r *PromptInjectionRule) DefaultSeverity() Severity { return SeverityHigh }
func (r *PromptInjectionRule) Description() string {
	return "Detects tool outputs that may pass unsanitized external data back to the LLM, creating prompt injection attack surfaces."
}

func (r *PromptInjectionRule) Check(filePath string, content []byte) []Finding {
	var findings []Finding
	lines := strings.Split(string(content), "\n")

	for i, line := range lines {
		for _, pattern := range injectionRiskPatterns {
			if pattern.MatchString(line) {
				start := max(0, i-5)
				end := min(len(lines), i+5)
				context := strings.Join(lines[start:end], "\n")

				hasSanitization := false
				for _, sanitPattern := range sanitizationPatterns {
					if sanitPattern.MatchString(context) {
						hasSanitization = true
						break
					}
				}

				if !hasSanitization {
					findings = append(findings, Finding{
						RuleID:      r.ID(),
						Title:       "Potential prompt injection surface in tool output",
						Description: "Tool output may include unsanitized external data that could be used for prompt injection when returned to the LLM.",
						Severity:    r.DefaultSeverity(),
						FilePath:    filePath,
						Line:        i + 1,
						Column:      1,
						Snippet:     strings.TrimSpace(line),
						Remediation: "Sanitize all external data before including in tool responses. Consider output filtering, content-type restrictions, and structured output formats.",
					})
				}
			}
		}
	}
	return findings
}
