// Copyright 2024 Nostalgic Skin Co.
// SPDX-License-Identifier: AGPL-3.0-or-later

package rules

import (
	"regexp"
	"strings"
)

// AuthGapsRule detects missing authentication/authorization in MCP servers.
type AuthGapsRule struct{}

var authMissingPatterns = []*regexp.Regexp{
	// MCP tool handlers without auth checks.
	regexp.MustCompile(`(?i)(?:@server\.tool|@app\.tool|tool_handler|handle_tool|CallToolResult)\s*`),
	// Endpoints without auth middleware.
	regexp.MustCompile(`(?i)(?:\.get|\.post|\.put|\.delete|\.patch)\s*\(\s*["'/]`),
	// Direct resource access without permission checks.
	regexp.MustCompile(`(?i)(?:read_resource|write_resource|list_resources|ResourceTemplate)\s*`),
}

var authPresentPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:authenticate|authorize|auth_required|check_permission|verify_token|api_key|bearer|jwt|oauth)`),
	regexp.MustCompile(`(?i)(?:middleware.*auth|auth.*middleware|requireAuth|isAuthenticated|@login_required|@requires_auth)`),
	regexp.MustCompile(`(?i)(?:session\.user|request\.user|ctx\.user|current_user|get_user)`),
}

func (r *AuthGapsRule) ID() string               { return "MCP-002" }
func (r *AuthGapsRule) Name() string              { return "Missing Authentication/Authorization" }
func (r *AuthGapsRule) DefaultSeverity() Severity { return SeverityHigh }
func (r *AuthGapsRule) Description() string {
	return "Detects MCP tool handlers and resource endpoints that may lack authentication or authorization checks."
}

func (r *AuthGapsRule) Check(filePath string, content []byte) []Finding {
	var findings []Finding
	lines := strings.Split(string(content), "\n")
	fullContent := string(content)

	// Check if there's any auth anywhere in the file.
	hasGlobalAuth := false
	for _, pattern := range authPresentPatterns {
		if pattern.MatchString(fullContent) {
			hasGlobalAuth = true
			break
		}
	}

	// If there's global auth, likely the file is protected.
	if hasGlobalAuth {
		return findings
	}

	for i, line := range lines {
		for _, pattern := range authMissingPatterns {
			if pattern.MatchString(line) {
				// Check nearby lines for auth.
				start := max(0, i-10)
				end := min(len(lines), i+10)
				context := strings.Join(lines[start:end], "\n")

				hasLocalAuth := false
				for _, authPattern := range authPresentPatterns {
					if authPattern.MatchString(context) {
						hasLocalAuth = true
						break
					}
				}

				if !hasLocalAuth {
					findings = append(findings, Finding{
						RuleID:      r.ID(),
						Title:       "MCP handler without authentication",
						Description: "Tool or resource handler appears to lack authentication/authorization checks. Unauthenticated access could allow unauthorized operations.",
						Severity:    r.DefaultSeverity(),
						FilePath:    filePath,
						Line:        i + 1,
						Column:      1,
						Snippet:     strings.TrimSpace(line),
						Remediation: "Add authentication middleware or explicit permission checks before processing tool calls. Implement least-privilege access controls.",
					})
				}
			}
		}
	}
	return findings
}
