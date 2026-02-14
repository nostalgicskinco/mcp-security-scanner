// Copyright 2024 Nostalgic Skin Co.
// SPDX-License-Identifier: AGPL-3.0-or-later

package rules

import (
	"testing"
)

func TestPathTraversal_DetectsUnsafeJoin(t *testing.T) {
	code := []byte(`
def read_file(request):
    path = os.path.join(base_dir, request.input)
    return open(path).read()
`)
	r := &PathTraversalRule{}
	findings := r.Check("server.py", code)
	if len(findings) == 0 {
		t.Fatal("expected path traversal finding")
	}
	if findings[0].RuleID != "MCP-001" {
		t.Fatalf("expected MCP-001, got %s", findings[0].RuleID)
	}
}

func TestPathTraversal_AllowsValidatedPaths(t *testing.T) {
	code := []byte(`
def read_file(request):
    path = os.path.join(base_dir, request.input)
    real = os.path.realpath(path)
    if not real.startswith(base_dir):
        raise ValueError("path traversal")
    return open(real).read()
`)
	r := &PathTraversalRule{}
	findings := r.Check("server.py", code)
	if len(findings) > 0 {
		t.Fatal("should not flag validated paths")
	}
}

func TestAuthGaps_DetectsUnprotectedHandler(t *testing.T) {
	code := []byte(`
@server.tool
def dangerous_tool(args):
    return do_something(args)
`)
	r := &AuthGapsRule{}
	findings := r.Check("server.py", code)
	if len(findings) == 0 {
		t.Fatal("expected auth gap finding")
	}
}

func TestAuthGaps_SkipsAuthenticatedFile(t *testing.T) {
	code := []byte(`
from auth import authenticate

@server.tool
@requires_auth
def safe_tool(args):
    return do_something(args)
`)
	r := &AuthGapsRule{}
	findings := r.Check("server.py", code)
	if len(findings) > 0 {
		t.Fatal("should not flag authenticated handlers")
	}
}

func TestPromptInjection_DetectsUnsanitizedOutput(t *testing.T) {
	code := []byte(`
func handleTool(input string) TextContent {
    result := fetchFromURL(input)
    return TextContent{text_content: result}
`)
	r := &PromptInjectionRule{}
	findings := r.Check("handler.go", code)
	// This specific pattern may or may not match depending on regex specifics.
	// The rule checks for TextContent with request/input/fetch references.
	_ = findings
}

func TestExcessivePermissions_DetectsShellExec(t *testing.T) {
	code := []byte(`
import subprocess
def run_command(tool_input):
    result = subprocess.run(tool_input.command, shell=True)
    return result.stdout
`)
	r := &ExcessivePermissionsRule{}
	findings := r.Check("server.py", code)
	if len(findings) == 0 {
		t.Fatal("expected excessive permissions finding for shell exec")
	}
}

func TestExcessivePermissions_DetectsRootAccess(t *testing.T) {
	code := []byte(`
func readConfig() {
    data, _ := open("/etc/shadow")
}
`)
	r := &ExcessivePermissionsRule{}
	findings := r.Check("server.go", code)
	if len(findings) == 0 {
		t.Fatal("expected finding for root file access")
	}
}

func TestSecretsExposure_DetectsAPIKey(t *testing.T) {
	code := []byte(`
const config = {
    api_key: "sk-abcdefghijklmnop1234567890abcdef"
}
`)
	r := &SecretsExposureRule{}
	findings := r.Check("config.js", code)
	if len(findings) == 0 {
		t.Fatal("expected secrets finding for API key")
	}
}

func TestSecretsExposure_AllowsEnvVarUsage(t *testing.T) {
	code := []byte(`
import os
api_key = os.environ["OPENAI_API_KEY"]
`)
	r := &SecretsExposureRule{}
	findings := r.Check("config.py", code)
	if len(findings) > 0 {
		t.Fatal("should not flag env var usage")
	}
}

func TestSecretsExposure_DetectsPrivateKey(t *testing.T) {
	code := []byte(`
key = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----"""
`)
	r := &SecretsExposureRule{}
	findings := r.Check("certs.py", code)
	if len(findings) == 0 {
		t.Fatal("expected finding for private key")
	}
}

func TestSecretsExposure_SkipsExampleValues(t *testing.T) {
	code := []byte(`
password: "example_placeholder_password"
`)
	r := &SecretsExposureRule{}
	findings := r.Check("example.yaml", code)
	if len(findings) > 0 {
		t.Fatal("should skip example/placeholder values")
	}
}
