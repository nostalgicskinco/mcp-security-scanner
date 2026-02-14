// Copyright 2024 Nostalgic Skin Co.
// SPDX-License-Identifier: AGPL-3.0-or-later

package rules

import (
	"regexp"
	"strings"
)

// ExcessivePermissionsRule detects overly broad permissions in MCP servers.
type ExcessivePermissionsRule struct{}

var excessivePermPatterns = []*regexp.Regexp{
	// Wildcard or overly broad file system access.
	regexp.MustCompile(`(?i)(?:glob|walk|listdir|readdir|scandir)\s*\(\s*["']/["']`),
	// Root-level file access.
	regexp.MustCompile(`(?i)(?:open|read|write)\s*\(\s*["']/(?:etc|usr|var|root|home)`),
	// Broad network access without restrictions.
	regexp.MustCompile(`(?i)(?:0\.0\.0\.0|INADDR_ANY|bind.*["']0\.0\.0\.0)`),
	// Shell execution capabilities.
	regexp.MustCompile(`(?i)(?:subprocess\.(?:call|run|Popen)|os\.(?:system|exec|popen)|exec\.Command)\s*\(`),
	// Database access - broad statements (DROP TABLE, DELETE FROM without WHERE checked separately).
	regexp.MustCompile(`(?i)(?:DROP\s+TABLE|TRUNCATE\s+TABLE)`),
	// Unrestricted environment variable access.
	regexp.MustCompile(`(?i)(?:os\.environ|process\.env|os\.Getenv)\s*(?:\[|\()\s*(?:request|input|param)`),
}

func (r *ExcessivePermissionsRule) ID() string               { return "MCP-004" }
func (r *ExcessivePermissionsRule) Name() string              { return "Excessive Permissions" }
func (r *ExcessivePermissionsRule) DefaultSeverity() Severity { return SeverityMedium }
func (r *ExcessivePermissionsRule) Description() string {
	return "Detects MCP server tools with overly broad permissions: unrestricted file system access, shell execution, broad network binding, or unscoped database queries."
}

func (r *ExcessivePermissionsRule) Check(filePath string, content []byte) []Finding {
	var findings []Finding
	lines := strings.Split(string(content), "\n")

	for i, line := range lines {
		for _, pattern := range excessivePermPatterns {
			if pattern.MatchString(line) {
				findings = append(findings, Finding{
					RuleID:      r.ID(),
					Title:       "Excessive permissions detected",
					Description: "MCP server tool has overly broad capabilities that violate the principle of least privilege. OWASP identifies 'Excessive Agency' as a top LLM risk.",
					Severity:    r.DefaultSeverity(),
					FilePath:    filePath,
					Line:        i + 1,
					Column:      1,
					Snippet:     strings.TrimSpace(line),
					Remediation: "Apply least-privilege: scope file access to specific directories, restrict network binding, use parameterized queries, and avoid shell execution where possible.",
				})
			}
		}
	}
	return findings
}
