// Copyright 2024 Nostalgic Skin Co.
// SPDX-License-Identifier: AGPL-3.0-or-later

package rules

import (
	"regexp"
	"strings"
)

// PathTraversalRule detects potential path traversal vulnerabilities in MCP servers.
type PathTraversalRule struct{}

var pathTraversalPatterns = []*regexp.Regexp{
	// Direct file path construction without validation.
	regexp.MustCompile(`(?i)(os\.path\.join|path\.join|filepath\.Join)\s*\([^)]*(?:request|input|param|arg|tool_input)`),
	// Unvalidated path from user input.
	regexp.MustCompile(`(?i)(open|readFile|writeFile|read_file|write_file)\s*\([^)]*(?:request|input|param|arg|tool_input)`),
	// Missing path validation before file operations.
	regexp.MustCompile(`(?i)(?:\.\.\/|\.\.\\\\)`),
	// Direct concatenation with user input for file paths.
	regexp.MustCompile(`(?i)(root_dir|base_path|repository)\s*[\+\/]\s*(?:request|input|param|arg|name)`),
	// subprocess/exec with path from input.
	regexp.MustCompile(`(?i)(subprocess|exec|spawn|system)\s*\([^)]*(?:request|input|param|tool_input)`),
}

var pathValidationPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:realpath|abspath|resolve|Clean|sanitize|validate.*path|normpath)`),
	regexp.MustCompile(`(?i)(?:startswith|HasPrefix|strings\.Contains.*\.\.|path_traversal)`),
}

func (r *PathTraversalRule) ID() string             { return "MCP-001" }
func (r *PathTraversalRule) Name() string            { return "Path Traversal" }
func (r *PathTraversalRule) DefaultSeverity() Severity { return SeverityCritical }
func (r *PathTraversalRule) Description() string {
	return "Detects potential path traversal vulnerabilities where user-controlled input is used in file system operations without proper validation."
}

func (r *PathTraversalRule) Check(filePath string, content []byte) []Finding {
	var findings []Finding
	lines := strings.Split(string(content), "\n")

	for i, line := range lines {
		for _, pattern := range pathTraversalPatterns {
			if pattern.MatchString(line) {
				// Check if there's path validation nearby (within 5 lines).
				hasValidation := false
				start := max(0, i-5)
				end := min(len(lines), i+5)
				context := strings.Join(lines[start:end], "\n")

				for _, valPattern := range pathValidationPatterns {
					if valPattern.MatchString(context) {
						hasValidation = true
						break
					}
				}

				if !hasValidation {
					findings = append(findings, Finding{
						RuleID:      r.ID(),
						Title:       "Potential path traversal vulnerability",
						Description: "User-controlled input used in file path without validation. Attackers could access files outside the intended directory.",
						Severity:    r.DefaultSeverity(),
						FilePath:    filePath,
						Line:        i + 1,
						Column:      1,
						Snippet:     strings.TrimSpace(line),
						Remediation: "Validate and sanitize all file paths. Use realpath/abspath to resolve paths and verify they start with the expected base directory.",
					})
				}
			}
		}
	}
	return findings
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
