"""
Reporter module for the bug bounty reconnaissance toolkit.

Provides formatted output of scan findings to console (with colors via rich),
JSON files, and structured reports. Supports multiple output formats and
severity-based coloring.
"""

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, field, asdict

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.syntax import Syntax
from rich import box

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import OUTPUT_DIR


# Severity levels and their colors
SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "green",
    "debug": "dim white",
}

SEVERITY_ICONS = {
    "critical": "[!]",
    "high": "[!]",
    "medium": "[*]",
    "low": "[+]",
    "info": "[i]",
    "debug": "[-]",
}


@dataclass
class Finding:
    """Represents a single security finding."""
    title: str
    severity: str  # critical, high, medium, low, info
    url: str = ""
    description: str = ""
    evidence: str = ""
    request: str = ""
    response: str = ""
    remediation: str = ""
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return asdict(self)


@dataclass
class ScanReport:
    """Represents a complete scan report."""
    scan_id: str
    target: str
    scan_type: str
    start_time: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    end_time: Optional[str] = None
    duration: float = 0.0
    findings: List[Finding] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "scan_type": self.scan_type,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": self.duration,
            "total_findings": len(self.findings),
            "severity_counts": self.severity_counts,
            "findings": [f.to_dict() for f in self.findings],
            "stats": self.stats,
            "errors": self.errors,
        }

    @property
    def severity_counts(self) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.findings:
            severity = finding.severity.lower()
            if severity in counts:
                counts[severity] += 1
        return counts


class Reporter:
    """
    Reporter for outputting scan findings.

    Supports console output with rich formatting, JSON file output,
    and structured reporting with severity-based coloring.
    """

    def __init__(
        self,
        output_dir: Optional[str] = None,
        verbose: bool = True,
        color: bool = True,
        quiet: bool = False,
    ):
        self.output_dir = Path(output_dir) if output_dir else OUTPUT_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.verbose = verbose
        self.quiet = quiet
        self.console = Console(force_terminal=color, highlight=True)
        self._findings: List[Finding] = []
        self._reports: Dict[str, ScanReport] = {}

    def finding(
        self,
        title: str,
        severity: str = "info",
        url: str = "",
        description: str = "",
        evidence: str = "",
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        print_to_console: bool = True,
    ) -> Finding:
        """
        Record and display a finding.

        Args:
            title: Finding title
            severity: Severity level (critical, high, medium, low, info)
            url: Affected URL
            description: Detailed description
            evidence: Evidence/proof
            tags: Tags for categorization
            metadata: Additional metadata
            print_to_console: Whether to print to console

        Returns:
            The created Finding object
        """
        f = Finding(
            title=title,
            severity=severity.lower(),
            url=url,
            description=description,
            evidence=evidence,
            tags=tags or [],
            metadata=metadata or {},
        )
        self._findings.append(f)

        if print_to_console and not self.quiet:
            self._print_finding(f)

        return f

    def _print_finding(self, finding: Finding):
        """Print a finding to the console with colors."""
        color = SEVERITY_COLORS.get(finding.severity, "white")
        icon = SEVERITY_ICONS.get(finding.severity, "[?]")

        # Main finding line
        self.console.print(
            f"  {icon} [{color}]{finding.severity.upper()}[/{color}] "
            f"- {finding.title}",
        )

        if finding.url and self.verbose:
            self.console.print(f"      URL: [cyan]{finding.url}[/cyan]")

        if finding.evidence and self.verbose:
            evidence_short = finding.evidence[:200]
            if len(finding.evidence) > 200:
                evidence_short += "..."
            self.console.print(f"      Evidence: [dim]{evidence_short}[/dim]")

    def info(self, message: str):
        """Print an info message."""
        if not self.quiet:
            self.console.print(f"  [green][i][/green] {message}")

    def warning(self, message: str):
        """Print a warning message."""
        if not self.quiet:
            self.console.print(f"  [yellow][!][/yellow] {message}")

    def error(self, message: str):
        """Print an error message."""
        self.console.print(f"  [red][✗][/red] {message}")

    def success(self, message: str):
        """Print a success message."""
        if not self.quiet:
            self.console.print(f"  [green][✓][/green] {message}")

    def status(self, message: str):
        """Print a status message."""
        if not self.quiet and self.verbose:
            self.console.print(f"  [dim][-][/dim] {message}")

    def banner(self, title: str, subtitle: str = ""):
        """Print a banner/header."""
        if self.quiet:
            return
        text = Text(title, style="bold cyan")
        if subtitle:
            panel = Panel(text, subtitle=subtitle, box=box.DOUBLE_EDGE)
        else:
            panel = Panel(text, box=box.DOUBLE_EDGE)
        self.console.print(panel)

    def table(
        self,
        title: str,
        columns: List[str],
        rows: List[List[str]],
        show_lines: bool = False,
    ):
        """
        Print a formatted table.

        Args:
            title: Table title
            columns: Column headers
            rows: Table rows (list of lists)
            show_lines: Whether to show row separator lines
        """
        if self.quiet:
            return

        table = Table(title=title, box=box.ROUNDED, show_lines=show_lines)
        for col in columns:
            table.add_column(col, style="cyan")

        for row in rows:
            table.add_row(*[str(cell) for cell in row])

        self.console.print(table)

    def summary(self, report: Optional[ScanReport] = None):
        """Print a summary of findings."""
        if self.quiet:
            return

        findings = report.findings if report else self._findings
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            severity = f.severity.lower()
            if severity in counts:
                counts[severity] += 1

        self.console.print()
        self.console.print("  [bold]═══ Scan Summary ═══[/bold]")
        self.console.print(f"  Total findings: [bold]{len(findings)}[/bold]")
        for sev, count in counts.items():
            if count > 0:
                color = SEVERITY_COLORS[sev]
                self.console.print(f"    [{color}]{sev.upper()}: {count}[/{color}]")
        self.console.print()

    def save_json(
        self,
        filename: Optional[str] = None,
        report: Optional[ScanReport] = None,
    ) -> str:
        """
        Save findings/report to a JSON file.

        Args:
            filename: Output filename (auto-generated if not provided)
            report: ScanReport to save (uses accumulated findings if not provided)

        Returns:
            Path to the saved file
        """
        if filename is None:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_results_{timestamp}.json"

        filepath = self.output_dir / filename

        if report:
            data = report.to_dict()
        else:
            data = {
                "timestamp": datetime.utcnow().isoformat(),
                "total_findings": len(self._findings),
                "findings": [f.to_dict() for f in self._findings],
            }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        if not self.quiet:
            self.console.print(f"  [green][✓][/green] Results saved to: [cyan]{filepath}[/cyan]")

        return str(filepath)

    def save_report(self, report: ScanReport, filename: Optional[str] = None) -> str:
        """
        Save a complete scan report.

        Args:
            report: The ScanReport to save
            filename: Output filename

        Returns:
            Path to the saved file
        """
        if filename is None:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{report.scan_type}_{timestamp}.json"

        return self.save_json(filename=filename, report=report)

    def create_report(
        self,
        scan_id: str,
        target: str,
        scan_type: str,
    ) -> ScanReport:
        """
        Create a new scan report.

        Args:
            scan_id: Unique scan identifier
            target: Scan target
            scan_type: Type of scan performed

        Returns:
            New ScanReport object
        """
        report = ScanReport(
            scan_id=scan_id,
            target=target,
            scan_type=scan_type,
        )
        self._reports[scan_id] = report
        return report

    def finalize_report(self, report: ScanReport) -> ScanReport:
        """
        Finalize a report (set end time, calculate duration).

        Args:
            report: The report to finalize

        Returns:
            The finalized report
        """
        report.end_time = datetime.utcnow().isoformat()
        if report.start_time:
            start = datetime.fromisoformat(report.start_time)
            end = datetime.fromisoformat(report.end_time)
            report.duration = (end - start).total_seconds()
        return report

    def get_findings(self) -> List[Dict[str, Any]]:
        """Get all findings as a list of dictionaries."""
        return [f.to_dict() for f in self._findings]

    def clear(self):
        """Clear all accumulated findings."""
        self._findings.clear()

    @property
    def finding_count(self) -> int:
        """Get the number of accumulated findings."""
        return len(self._findings)
