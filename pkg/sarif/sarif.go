// Copyright 2024 Nostalgic Skin Co.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package sarif produces SARIF v2.1.0 output for GitHub Code Scanning.
package sarif

import (
	"encoding/json"

	"github.com/nostalgicskinco/mcp-security-scanner/pkg/rules"
	"github.com/nostalgicskinco/mcp-security-scanner/pkg/scanner"
)

// SarifReport is a SARIF v2.1.0 report.
type SarifReport struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

// Run represents a single analysis run.
type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

// Tool describes the scanner tool.
type Tool struct {
	Driver Driver `json:"driver"`
}

// Driver is the tool driver info.
type Driver struct {
	Name           string         `json:"name"`
	Version        string         `json:"version"`
	InformationURI string         `json:"informationUri"`
	Rules          []ReportingRule `json:"rules"`
}

// ReportingRule is a SARIF rule descriptor.
type ReportingRule struct {
	ID               string        `json:"id"`
	Name             string        `json:"name"`
	ShortDescription MessageObj    `json:"shortDescription"`
	DefaultConfig    DefaultConfig `json:"defaultConfiguration"`
}

// DefaultConfig is the default rule configuration.
type DefaultConfig struct {
	Level string `json:"level"`
}

// MessageObj is a SARIF message object.
type MessageObj struct {
	Text string `json:"text"`
}

// Result is a single SARIF finding.
type Result struct {
	RuleID    string      `json:"ruleId"`
	Level     string      `json:"level"`
	Message   MessageObj  `json:"message"`
	Locations []Location  `json:"locations"`
}

// Location describes where a finding occurred.
type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

// PhysicalLocation is a file location.
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region"`
}

// ArtifactLocation is the file URI.
type ArtifactLocation struct {
	URI string `json:"uri"`
}

// Region is the line/column range.
type Region struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
}

// severityToLevel converts our severity to SARIF level.
func severityToLevel(s rules.Severity) string {
	switch s {
	case rules.SeverityCritical, rules.SeverityHigh:
		return "error"
	case rules.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// Generate produces a SARIF report from scan results.
func Generate(result *scanner.ScanResult) ([]byte, error) {
	// Build unique rule list.
	ruleMap := make(map[string]bool)
	var sarifRules []ReportingRule
	for _, f := range result.Findings {
		if !ruleMap[f.RuleID] {
			ruleMap[f.RuleID] = true
			sarifRules = append(sarifRules, ReportingRule{
				ID:               f.RuleID,
				Name:             f.Title,
				ShortDescription: MessageObj{Text: f.Description},
				DefaultConfig:    DefaultConfig{Level: severityToLevel(f.Severity)},
			})
		}
	}

	// Build results.
	var results []Result
	for _, f := range result.Findings {
		results = append(results, Result{
			RuleID:  f.RuleID,
			Level:   severityToLevel(f.Severity),
			Message: MessageObj{Text: f.Description + "\n\nRemediation: " + f.Remediation},
			Locations: []Location{
				{
					PhysicalLocation: PhysicalLocation{
						ArtifactLocation: ArtifactLocation{URI: f.FilePath},
						Region: Region{
							StartLine:   f.Line,
							StartColumn: f.Column,
						},
					},
				},
			},
		})
	}

	report := SarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []Run{
			{
				Tool: Tool{
					Driver: Driver{
						Name:           "mcp-security-scanner",
						Version:        "0.1.0",
						InformationURI: "https://github.com/nostalgicskinco/mcp-security-scanner",
						Rules:          sarifRules,
					},
				},
				Results: results,
			},
		},
	}

	return json.MarshalIndent(report, "", "  ")
}
