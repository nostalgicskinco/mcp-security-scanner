// Copyright 2024 Nostalgic Skin Co.
// SPDX-License-Identifier: AGPL-3.0-or-later

package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nostalgicskinco/mcp-security-scanner/pkg/rules"
)

// Scanner runs security rules against MCP server source code.
type Scanner struct {
	rules      []rules.Rule
	extensions []string
}

// ScanResult holds the aggregated results of a scan.
type ScanResult struct {
	Findings    []rules.Finding `json:"findings"`
	FilesScanned int            `json:"files_scanned"`
	RulesRun     int            `json:"rules_run"`
}

// New creates a scanner with the default rule set.
func New() *Scanner {
	return &Scanner{
		rules: []rules.Rule{
			&rules.PathTraversalRule{},
			&rules.AuthGapsRule{},
			&rules.PromptInjectionRule{},
			&rules.ExcessivePermissionsRule{},
			&rules.SecretsExposureRule{},
		},
		extensions: []string{
			".py", ".js", ".ts", ".go", ".rs", ".java",
			".jsx", ".tsx", ".mjs", ".cjs",
		},
	}
}

// ScanDirectory recursively scans a directory.
func (s *Scanner) ScanDirectory(dir string) (*ScanResult, error) {
	result := &ScanResult{
		RulesRun: len(s.rules),
	}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable files
		}

		// Skip hidden dirs and common non-source dirs.
		if info.IsDir() {
			name := info.Name()
			if strings.HasPrefix(name, ".") || name == "node_modules" || name == "vendor" || name == "__pycache__" || name == "venv" || name == ".venv" {
				return filepath.SkipDir
			}
			return nil
		}

		// Check file extension.
		ext := filepath.Ext(path)
		if !s.hasExtension(ext) {
			return nil
		}

		findings, err := s.ScanFile(path)
		if err != nil {
			return nil // skip unreadable files
		}

		result.FilesScanned++
		result.Findings = append(result.Findings, findings...)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("scan directory failed: %w", err)
	}

	return result, nil
}

// ScanFile scans a single file against all rules.
func (s *Scanner) ScanFile(filePath string) ([]rules.Finding, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read file failed: %w", err)
	}

	var findings []rules.Finding
	for _, rule := range s.rules {
		ruleFindings := rule.Check(filePath, content)
		findings = append(findings, ruleFindings...)
	}

	return findings, nil
}

func (s *Scanner) hasExtension(ext string) bool {
	for _, e := range s.extensions {
		if e == ext {
			return true
		}
	}
	return false
}

// Summary returns a human-readable summary of the scan.
func (r *ScanResult) Summary() string {
	if len(r.Findings) == 0 {
		return fmt.Sprintf("✅ No issues found (%d files scanned, %d rules)", r.FilesScanned, r.RulesRun)
	}

	counts := make(map[rules.Severity]int)
	for _, f := range r.Findings {
		counts[f.Severity]++
	}

	return fmt.Sprintf("⚠️  %d issues found (%d critical, %d high, %d medium, %d low) across %d files",
		len(r.Findings),
		counts[rules.SeverityCritical],
		counts[rules.SeverityHigh],
		counts[rules.SeverityMedium],
		counts[rules.SeverityLow],
		r.FilesScanned,
	)
}
