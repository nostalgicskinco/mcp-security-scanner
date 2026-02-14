# MCP Security Scanner

**Semgrep for MCP servers — protocol-aware security checks for the AI agent ecosystem.**

A security scanner purpose-built for Model Context Protocol (MCP) servers. Detects path traversal, authentication gaps, prompt injection surfaces, excessive permissions, and hardcoded secrets with protocol-aware rules that generic SAST tools miss.

## Why This Exists

MCP adoption is accelerating (OpenAI Agents SDK, Anthropic Claude, and hundreds of community servers), but **real security vulnerabilities exist in production MCP servers**. GitHub advisories document concrete issues like missing path validation when servers are started with `--repository` flags.

OWASP identifies "Insecure Plugin Design" and "Excessive Agency" as top LLM risks. Generic SAST tools miss the protocol-specific patterns that make MCP servers vulnerable.

**This scanner fills that gap.**

## Security Rules

| Rule ID | Name | Severity | What It Detects |
|---------|------|----------|-----------------|
| MCP-001 | Path Traversal | Critical | Unvalidated file paths from tool inputs |
| MCP-002 | Auth Gaps | High | MCP handlers without authentication |
| MCP-003 | Prompt Injection | High | Unsanitized data in tool outputs → LLM |
| MCP-004 | Excessive Permissions | Medium | Overly broad FS/network/shell access |
| MCP-005 | Hardcoded Secrets | Critical | API keys, tokens, private keys in code |

## Quick Start

```bash
# Install
go install github.com/nostalgicskinco/mcp-security-scanner/cmd/mcpscan@latest

# Scan a directory
mcpscan /path/to/mcp-server

# Output as SARIF (for GitHub Code Scanning)
mcpscan -format sarif -output results.sarif /path/to/mcp-server

# Output as JSON
mcpscan -format json /path/to/mcp-server
```

## GitHub Action

Add MCP security scanning to your CI pipeline:

```yaml
name: MCP Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.24'
      - run: go install github.com/nostalgicskinco/mcp-security-scanner/cmd/mcpscan@latest
      - run: mcpscan -format sarif -output results.sarif . || true
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## Output Formats

### Text (default)
```
⚠️  3 issues found (1 critical, 1 high, 1 medium) across 2 files

[1] MCP-001 (critical) — Potential path traversal vulnerability
    File: server.py:12
    User-controlled input used in file path without validation.
    Fix: Validate and sanitize all file paths...
```

### SARIF
Standard SARIF v2.1.0 for GitHub Code Scanning integration. Findings appear directly in pull request annotations.

### JSON
Machine-readable output for custom integrations and dashboards.

## How It Works

The scanner applies protocol-aware regex rules across source files, checking for MCP-specific vulnerability patterns. Unlike generic SAST tools, it understands:

- MCP tool handler decorators and patterns (`@server.tool`, `handle_tool`, `CallToolResult`)
- MCP resource access patterns (`read_resource`, `ResourceTemplate`)
- The unique attack surface of tool outputs being fed back to LLMs
- Common MCP server startup patterns and their security implications

## Roadmap

- [ ] Dynamic analysis mode (runtime MCP protocol testing)
- [ ] AST-based analysis for reduced false positives
- [ ] Custom rule definitions (YAML-based)
- [ ] MCP server manifest/capabilities validation
- [ ] Integration with MCP registries for automated scanning
- [ ] VS Code extension for inline warnings
- [ ] Severity customization and rule suppression

## License

Dual-licensed: **AGPL-3.0** ([LICENSE](LICENSE)) + **Commercial** ([COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md))

## Part of the GenAI Infrastructure Standards Portfolio

| Project | Description |
|---------|-------------|
| [Prompt Vault Processor](https://github.com/nostalgicskinco/prompt-vault-processor) | Content offload + encryption for GenAI traces |
| **[MCP Security Scanner](https://github.com/nostalgicskinco/mcp-security-scanner)** | Security scanning for MCP servers |
| [GenAI Safe Processor](https://github.com/nostalgicskinco/opentelemetry-collector-processor-genai) | Privacy-by-default redaction + cost metrics |
| [GenAI Semantic Normalizer](https://github.com/nostalgicskinco/genai-semantic-normalizer) | One schema to query all LLM traces |
