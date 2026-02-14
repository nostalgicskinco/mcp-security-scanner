// Copyright 2024 Nostalgic Skin Co.
// SPDX-License-Identifier: AGPL-3.0-or-later

package rules

import (
	"regexp"
	"strings"
)

// SecretsExposureRule detects hardcoded secrets and credentials in MCP servers.
type SecretsExposureRule struct{}

var secretPatterns = []*regexp.Regexp{
	// API keys.
	regexp.MustCompile(`(?i)(?:api[_-]?key|apikey)\s*[:=]\s*["'][a-zA-Z0-9]{16,}["']`),
	// Bearer tokens.
	regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9\-\._~\+\/]{20,}`),
	// OpenAI keys.
	regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`),
	// AWS keys.
	regexp.MustCompile(`(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}`),
	// Generic secrets.
	regexp.MustCompile(`(?i)(?:password|passwd|secret|token|credential)\s*[:=]\s*["'][^"']{8,}["']`),
	// Private keys.
	regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----`),
	// GitHub tokens.
	regexp.MustCompile(`(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}`),
	// Anthropic keys.
	regexp.MustCompile(`sk-ant-[a-zA-Z0-9\-]{20,}`),
}

var secretExcludePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:example|sample|placeholder|test|mock|fake|dummy|xxx|changeme)`),
	regexp.MustCompile(`(?i)(?:\.env|environ|getenv|config\[|settings\.)`),
}

func (r *SecretsExposureRule) ID() string               { return "MCP-005" }
func (r *SecretsExposureRule) Name() string              { return "Hardcoded Secrets" }
func (r *SecretsExposureRule) DefaultSeverity() Severity { return SeverityCritical }
func (r *SecretsExposureRule) Description() string {
	return "Detects hardcoded API keys, tokens, passwords, and other secrets in MCP server code."
}

func (r *SecretsExposureRule) Check(filePath string, content []byte) []Finding {
	var findings []Finding
	lines := strings.Split(string(content), "\n")

	for i, line := range lines {
		for _, pattern := range secretPatterns {
			if pattern.MatchString(line) {
				isExcluded := false
				for _, exclude := range secretExcludePatterns {
					if exclude.MatchString(line) {
						isExcluded = true
						break
					}
				}

				if !isExcluded {
					findings = append(findings, Finding{
						RuleID:      r.ID(),
						Title:       "Hardcoded secret detected",
						Description: "Potential hardcoded secret or credential found in source code. This could lead to unauthorized access if the code is shared or committed.",
						Severity:    r.DefaultSeverity(),
						FilePath:    filePath,
						Line:        i + 1,
						Column:      1,
						Snippet:     maskSecret(strings.TrimSpace(line)),
						Remediation: "Move secrets to environment variables or a secrets manager. Never commit credentials to source control.",
					})
				}
			}
		}
	}
	return findings
}

// maskSecret partially redacts the secret value in findings.
func maskSecret(line string) string {
	for _, p := range secretPatterns {
		line = p.ReplaceAllStringFunc(line, func(match string) string {
			if len(match) > 12 {
				return match[:8] + "****" + match[len(match)-4:]
			}
			return "****"
		})
	}
	return line
}
