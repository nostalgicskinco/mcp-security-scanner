"""Built-in security rules."""
from __future__ import annotations
import re
from pkg.models.scan import Finding, FindingCategory, RiskLevel, ScanTarget

# Dangerous tool name patterns
DANGEROUS_TOOLS = {"execute_command", "run_shell", "eval", "exec", "system", "subprocess", "rm", "delete", "drop_table", "truncate"}

# SQL injection patterns
SQL_PATTERNS = [re.compile(p, re.I) for p in [r"(?:union\s+select|;\s*drop\s|;\s*delete\s|;\s*update\s|or\s+1\s*=\s*1)", r"(?:--\s|/\*|\*/|xp_cmdshell)"]]

# Command injection patterns
CMD_PATTERNS = [re.compile(p) for p in [r"[;&|`$]\s*(?:rm|cat|curl|wget|nc|ncat|bash|sh|python|perl|ruby)", r"\$\(.*\)", r"`.*`"]]

# Credential patterns
CRED_PATTERNS = [re.compile(p, re.I) for p in [r"(?:api[_-]?key|secret|token|password|credential|auth)[\"']?\s*[:=]\s*[\"']?[a-zA-Z0-9+/=_-]{8,}", r"sk-[a-zA-Z0-9]{20,}", r"ghp_[a-zA-Z0-9]{36}", r"AKIA[0-9A-Z]{16}"]]

# Path traversal
PATH_PATTERNS = [re.compile(p) for p in [r"\.\./", r"\.\.\\", r"/etc/(?:passwd|shadow)", r"C:\\Windows\\System32"]]

def check_dangerous_tool(target: ScanTarget) -> list[Finding]:
    findings = []
    if target.tool_name.lower() in DANGEROUS_TOOLS:
        findings.append(Finding(category=FindingCategory.DANGEROUS_PATTERN, risk_level=RiskLevel.CRITICAL, title=f"Dangerous tool: {target.tool_name}", description=f"Tool '{target.tool_name}' is inherently dangerous and should be sandboxed or removed.", tool_name=target.tool_name, recommendation="Remove or sandbox this tool, or require human approval for every call."))
    return findings

def check_injection(target: ScanTarget) -> list[Finding]:
    findings = []
    for sample in target.sample_inputs:
        text = str(sample)
        for pat in SQL_PATTERNS:
            if pat.search(text):
                findings.append(Finding(category=FindingCategory.INJECTION, risk_level=RiskLevel.HIGH, title=f"SQL injection in {target.tool_name}", tool_name=target.tool_name, evidence=text[:200], recommendation="Parameterize queries and validate inputs."))
                break
        for pat in CMD_PATTERNS:
            if pat.search(text):
                findings.append(Finding(category=FindingCategory.INJECTION, risk_level=RiskLevel.CRITICAL, title=f"Command injection in {target.tool_name}", tool_name=target.tool_name, evidence=text[:200], recommendation="Never pass user input to shell commands."))
                break
    return findings

def check_credentials(target: ScanTarget) -> list[Finding]:
    findings = []
    for sample in target.sample_inputs:
        text = str(sample)
        for pat in CRED_PATTERNS:
            if pat.search(text):
                findings.append(Finding(category=FindingCategory.CREDENTIAL_LEAK, risk_level=RiskLevel.CRITICAL, title=f"Credential exposure in {target.tool_name}", tool_name=target.tool_name, evidence="[REDACTED]", recommendation="Never pass credentials in tool inputs."))
                break
    return findings

def check_path_traversal(target: ScanTarget) -> list[Finding]:
    findings = []
    for sample in target.sample_inputs:
        text = str(sample)
        for pat in PATH_PATTERNS:
            if pat.search(text):
                findings.append(Finding(category=FindingCategory.INJECTION, risk_level=RiskLevel.HIGH, title=f"Path traversal in {target.tool_name}", tool_name=target.tool_name, evidence=text[:200], recommendation="Validate and sanitize file paths."))
                break
    return findings

def check_missing_validation(target: ScanTarget) -> list[Finding]:
    findings = []
    schema = target.tool_input_schema
    properties = schema.get("properties", {})
    for prop_name, prop_def in properties.items():
        if prop_def.get("type") == "string" and "maxLength" not in prop_def and "pattern" not in prop_def and "enum" not in prop_def:
            findings.append(Finding(category=FindingCategory.MISSING_VALIDATION, risk_level=RiskLevel.LOW, title=f"Unbounded string: {target.tool_name}.{prop_name}", tool_name=target.tool_name, recommendation=f"Add maxLength or pattern constraint to '{prop_name}'."))
    return findings

ALL_CHECKS = [check_dangerous_tool, check_injection, check_credentials, check_path_traversal, check_missing_validation]
