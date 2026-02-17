"""Security analyzer — runs all checks against targets."""
from __future__ import annotations
from pkg.models.scan import ScanResult, ScanTarget
from pkg.rules.builtin import ALL_CHECKS

class SecurityAnalyzer:
    def __init__(self, checks=None) -> None:
        self.checks = checks or ALL_CHECKS

    def scan(self, targets: list[ScanTarget]) -> ScanResult:
        result = ScanResult(target_count=len(targets))
        for target in targets:
            for check in self.checks:
                findings = check(target)
                for finding in findings:
                    if not finding.id:
                        finding.id = f"F-{result.finding_count + 1:04d}"
                    result.add_finding(finding)
        return result

    def scan_single(self, target: ScanTarget) -> ScanResult:
        return self.scan([target])
