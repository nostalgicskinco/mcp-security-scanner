"""Security scan models."""
from __future__ import annotations
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field

class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class FindingCategory(str, Enum):
    INJECTION = "injection"
    DATA_EXPOSURE = "data_exposure"
    EXCESSIVE_PERMISSION = "excessive_permission"
    DANGEROUS_PATTERN = "dangerous_pattern"
    MISSING_VALIDATION = "missing_validation"
    CREDENTIAL_LEAK = "credential_leak"

class Finding(BaseModel):
    id: str = ""
    category: FindingCategory
    risk_level: RiskLevel
    title: str
    description: str = ""
    tool_name: str = ""
    evidence: str = ""
    recommendation: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)

class ScanTarget(BaseModel):
    tool_name: str
    tool_description: str = ""
    tool_input_schema: dict[str, Any] = Field(default_factory=dict)
    sample_inputs: list[dict[str, Any]] = Field(default_factory=list)


class ScanResult(BaseModel):
    target_count: int = 0
    finding_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    findings: list[Finding] = Field(default_factory=list)
    passed: bool = True

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        self.finding_count += 1
        if finding.risk_level == RiskLevel.CRITICAL:
            self.critical_count += 1
            self.passed = False
        elif finding.risk_level == RiskLevel.HIGH:
            self.high_count += 1
            self.passed = False
        elif finding.risk_level == RiskLevel.MEDIUM:
            self.medium_count += 1
        elif finding.risk_level == RiskLevel.LOW:
            self.low_count += 1
