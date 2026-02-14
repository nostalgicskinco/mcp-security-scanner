// Copyright 2024 Nostalgic Skin Co.
// SPDX-License-Identifier: AGPL-3.0-or-later

package rules

// Severity levels for findings.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Finding represents a security issue discovered by a rule.
type Finding struct {
	RuleID      string   `json:"rule_id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	FilePath    string   `json:"file_path"`
	Line        int      `json:"line"`
	Column      int      `json:"column"`
	Snippet     string   `json:"snippet"`
	Remediation string   `json:"remediation"`
}

// Rule is the interface all security rules must implement.
type Rule interface {
	// ID returns the unique rule identifier (e.g., "MCP-001").
	ID() string
	// Name returns the human-readable rule name.
	Name() string
	// Description returns what the rule checks for.
	Description() string
	// Severity returns the default severity level.
	DefaultSeverity() Severity
	// Check scans a file's content and returns findings.
	Check(filePath string, content []byte) []Finding
}
