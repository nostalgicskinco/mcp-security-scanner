// Copyright 2024 Nostalgic Skin Co.
// SPDX-License-Identifier: AGPL-3.0-or-later

package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanDirectory_FindsVulnerabilities(t *testing.T) {
	tmpDir := t.TempDir()

	// Write a vulnerable Python MCP server file.
	vulnCode := `
@server.tool
def read_file(request):
    path = os.path.join(base_dir, request.input)
    return open(path).read()
`
	err := os.WriteFile(filepath.Join(tmpDir, "server.py"), []byte(vulnCode), 0644)
	if err != nil {
		t.Fatal(err)
	}

	s := New()
	result, err := s.ScanDirectory(tmpDir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}

	if result.FilesScanned != 1 {
		t.Fatalf("expected 1 file scanned, got %d", result.FilesScanned)
	}

	if len(result.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}
}

func TestScanDirectory_SkipsNodeModules(t *testing.T) {
	tmpDir := t.TempDir()

	// Create node_modules with vulnerable code.
	nmDir := filepath.Join(tmpDir, "node_modules", "dep")
	os.MkdirAll(nmDir, 0755)
	os.WriteFile(filepath.Join(nmDir, "index.js"), []byte(`
		api_key: "sk-realkey1234567890abcdefghijk"
	`), 0644)

	s := New()
	result, err := s.ScanDirectory(tmpDir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}

	if result.FilesScanned != 0 {
		t.Fatalf("expected 0 files scanned (node_modules should be skipped), got %d", result.FilesScanned)
	}
}

func TestScanDirectory_CleanProject(t *testing.T) {
	tmpDir := t.TempDir()

	cleanCode := `
import os
from auth import authenticate, requires_auth

api_key = os.environ["API_KEY"]

@server.tool
@requires_auth
def safe_tool(args):
    validated_path = os.path.realpath(args.path)
    if not validated_path.startswith(BASE_DIR):
        raise ValueError("invalid path")
    return read_safely(validated_path)
`
	os.WriteFile(filepath.Join(tmpDir, "server.py"), []byte(cleanCode), 0644)

	s := New()
	result, err := s.ScanDirectory(tmpDir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}

	if len(result.Findings) > 0 {
		t.Fatalf("expected no findings for clean code, got %d: %v", len(result.Findings), result.Findings)
	}
}

func TestSummary_NoFindings(t *testing.T) {
	result := &ScanResult{FilesScanned: 5, RulesRun: 5}
	summary := result.Summary()
	if summary == "" {
		t.Fatal("summary should not be empty")
	}
}
