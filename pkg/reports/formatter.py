"""Report formatter for security scan results."""
from __future__ import annotations
import json
from pkg.models.scan import ScanResult

class ScanReporter:
    def to_summary(self, result: ScanResult) -> str:
        status = "PASS" if result.passed else "FAIL"
        return f"Scan: {status} | Targets: {result.target_count} | Findings: {result.finding_count} (C:{result.critical_count} H:{result.high_count} M:{result.medium_count} L:{result.low_count})"

    def to_detail(self, result: ScanResult) -> str:
        lines = [self.to_summary(result), "---"]
        for f in result.findings:
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(f.risk_level.value, "?")
            lines.append(f"{icon} [{f.risk_level.value.upper()}] {f.title}")
            if f.recommendation:
                lines.append(f"   → {f.recommendation}")
        return "\n".join(lines)

    def to_json(self, result: ScanResult) -> str:
        return json.dumps(result.model_dump(mode="json"), indent=2)
