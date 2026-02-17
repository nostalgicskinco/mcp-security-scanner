"""Security scanner CLI."""
import json
import click
from rich.console import Console
from pkg.scanner.analyzer import SecurityAnalyzer
from pkg.models.scan import ScanTarget
from pkg.reports.formatter import ScanReporter

console = Console()
analyzer = SecurityAnalyzer()
reporter = ScanReporter()

@click.group()
def cli():
    """MCP Security Scanner — find vulnerabilities in agent tool definitions."""
    pass

@cli.command()
@click.argument("tool_file")
@click.option("--format", "fmt", type=click.Choice(["summary", "detail", "json"]), default="detail")
def scan(tool_file: str, fmt: str):
    """Scan a tool definition file (JSON)."""
    with open(tool_file) as f:
        data = json.load(f)
    targets = [ScanTarget(**t) for t in (data if isinstance(data, list) else [data])]
    result = analyzer.scan(targets)
    if fmt == "summary": console.print(reporter.to_summary(result))
    elif fmt == "json": console.print(reporter.to_json(result))
    else: console.print(reporter.to_detail(result))
    raise SystemExit(0 if result.passed else 1)

if __name__ == "__main__":
    cli()
