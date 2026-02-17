"""Pytest configuration and fixtures."""
import pytest
from pkg.models.scan import ScanTarget

@pytest.fixture
def safe_target():
    return ScanTarget(tool_name="search", tool_description="Search the web", tool_input_schema={"properties": {"q": {"type": "string", "maxLength": 200}}}, sample_inputs=[{"q": "hello world"}])

@pytest.fixture
def dangerous_target():
    return ScanTarget(tool_name="execute_command", tool_description="Run shell command", tool_input_schema={"properties": {"cmd": {"type": "string"}}}, sample_inputs=[{"cmd": "ls -la"}])

@pytest.fixture
def injection_target():
    return ScanTarget(tool_name="query_db", tool_description="Query database", sample_inputs=[{"sql": "SELECT * FROM users; DROP TABLE users;--"}])

@pytest.fixture
def credential_target():
    return ScanTarget(tool_name="api_call", sample_inputs=[{"header": "Authorization: Bearer sk-abcdef1234567890abcdef1234567890"}])
