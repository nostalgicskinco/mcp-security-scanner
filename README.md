# MCP Security Scanner

**Find vulnerabilities in AI agent tool definitions.** Scans MCP tools for injection risks, credential leaks, dangerous patterns, path traversal, and missing input validation.

## Checks

| Check | Risk | Detects |
|---|---|---|
| Dangerous tools | Critical | execute_command, eval, rm, drop_table |
| Command injection | Critical | Shell metacharacters, backticks, $() |
| SQL injection | High | UNION SELECT, DROP, comment injection |
| Credential leaks | Critical | API keys, tokens, passwords in inputs |
| Path traversal | High | ../, /etc/passwd, Windows system paths |
| Missing validation | Low | Unbounded strings without constraints |

## Usage

```bash
pip install -e ".[dev]"
mcp-scan scan tools.json
mcp-scan scan tools.json --format json
```

## Part of the AIR Platform

[AIR Blackbox Gateway](https://github.com/nostalgicskinco/air-blackbox-gateway) ecosystem.

## License

Apache-2.0
