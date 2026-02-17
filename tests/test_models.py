"""Tests for scan models."""
from pkg.models.scan import *

class TestModels:
    def test_finding(self):
        f = Finding(category=FindingCategory.INJECTION, risk_level=RiskLevel.HIGH, title="test")
        assert f.risk_level == RiskLevel.HIGH

    def test_scan_result_tracking(self):
        r = ScanResult()
        r.add_finding(Finding(category=FindingCategory.INJECTION, risk_level=RiskLevel.CRITICAL, title="crit"))
        assert r.passed is False
        assert r.critical_count == 1

    def test_passed_with_low_findings(self):
        r = ScanResult()
        r.add_finding(Finding(category=FindingCategory.MISSING_VALIDATION, risk_level=RiskLevel.LOW, title="low"))
        assert r.passed is True
