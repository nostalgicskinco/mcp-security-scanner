"""Tests for security analyzer."""
from pkg.scanner.analyzer import SecurityAnalyzer

analyzer = SecurityAnalyzer()

class TestAnalyzer:
    def test_safe_tool(self, safe_target):
        result = analyzer.scan_single(safe_target)
        assert result.critical_count == 0
        assert result.high_count == 0

    def test_dangerous_tool(self, dangerous_target):
        result = analyzer.scan_single(dangerous_target)
        assert result.critical_count >= 1
        assert not result.passed

    def test_injection_detected(self, injection_target):
        result = analyzer.scan_single(injection_target)
        assert any(f.category.value == "injection" for f in result.findings)

    def test_credential_detected(self, credential_target):
        result = analyzer.scan_single(credential_target)
        assert any(f.category.value == "credential_leak" for f in result.findings)

    def test_batch_scan(self, safe_target, dangerous_target):
        result = analyzer.scan([safe_target, dangerous_target])
        assert result.target_count == 2
        assert result.finding_count >= 1
