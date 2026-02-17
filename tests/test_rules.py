"""Tests for built-in security rules."""
from pkg.rules.builtin import *
from pkg.models.scan import ScanTarget

class TestRules:
    def test_path_traversal(self):
        target = ScanTarget(tool_name="read_file", sample_inputs=[{"path": "../../../etc/passwd"}])
        findings = check_path_traversal(target)
        assert len(findings) >= 1

    def test_missing_validation(self):
        target = ScanTarget(tool_name="write", tool_input_schema={"properties": {"content": {"type": "string"}}})
        findings = check_missing_validation(target)
        assert len(findings) >= 1

    def test_no_false_positive_validation(self):
        target = ScanTarget(tool_name="search", tool_input_schema={"properties": {"q": {"type": "string", "maxLength": 100}}})
        findings = check_missing_validation(target)
        assert len(findings) == 0
