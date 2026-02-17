"""PolicyShield doctor — configuration health check and scoring."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Check:
    """A single health check result."""

    name: str
    passed: bool
    points: int  # Points awarded if passed
    message: str
    recommendation: str = ""


@dataclass
class DoctorReport:
    """Full doctor report."""

    checks: list[Check] = field(default_factory=list)
    score: int = 0
    max_score: int = 0
    grade: str = ""

    def add(self, check: Check) -> None:
        self.checks.append(check)
        self.max_score += check.points
        if check.passed:
            self.score += check.points

    def finalize(self) -> None:
        pct = (self.score / self.max_score * 100) if self.max_score > 0 else 0
        if pct >= 90:
            self.grade = "A"
        elif pct >= 75:
            self.grade = "B"
        elif pct >= 50:
            self.grade = "C"
        elif pct >= 25:
            self.grade = "D"
        else:
            self.grade = "F"


def run_doctor(
    config_path: Path | None = None,
    rules_path: Path | None = None,
) -> DoctorReport:
    """Run all health checks and return a DoctorReport.

    Args:
        config_path: Path to policyshield.yaml. Auto-detected if None.
        rules_path: Path to rules YAML file. Auto-detected if None.
    """
    import yaml

    report = DoctorReport()

    # Auto-detect paths
    if config_path is None:
        config_path = Path("policyshield.yaml")
    if rules_path is None:
        rules_path = Path("policies/rules.yaml")

    # --- Check 1: Config file exists ---
    config: dict[str, Any] = {}
    if config_path.exists():
        try:
            config = yaml.safe_load(config_path.read_text()) or {}
            report.add(Check("Config file", True, 10, f"✓ {config_path} is valid"))
        except Exception as e:
            report.add(
                Check(
                    "Config file",
                    False,
                    10,
                    f"✗ {config_path} has errors: {e}",
                    f"Fix the YAML syntax in {config_path}",
                )
            )
    else:
        report.add(Check("Config file", False, 10, f"✗ {config_path} not found", "Run: policyshield init"))

    # --- Check 2: Rules file exists and parses ---
    rules: list[dict] = []
    if rules_path.exists():
        try:
            data = yaml.safe_load(rules_path.read_text()) or {}
            rules = data.get("rules", [])
            if rules:
                report.add(Check("Rules file", True, 10, f"✓ {rules_path}: {len(rules)} rules"))
            else:
                report.add(
                    Check(
                        "Rules file",
                        False,
                        10,
                        f"✗ {rules_path} has 0 rules",
                        "Add rules or use: policyshield init --preset secure",
                    )
                )
        except Exception as e:
            report.add(
                Check(
                    "Rules file",
                    False,
                    10,
                    f"✗ {rules_path} has errors: {e}",
                    f"Run: policyshield validate {rules_path}",
                )
            )
    else:
        report.add(Check("Rules file", False, 10, f"✗ {rules_path} not found", "Run: policyshield init"))

    # --- Check 3: default_verdict ---
    rules_data: dict[str, Any] = {}
    if rules_path.exists():
        try:
            rules_data = yaml.safe_load(rules_path.read_text()) or {}
        except Exception:
            pass
    default_v = rules_data.get("default_verdict", "allow")
    if default_v == "block":
        report.add(Check("Default verdict", True, 15, "✓ default_verdict: block (secure)"))
    else:
        report.add(
            Check(
                "Default verdict",
                False,
                15,
                f"⚠ default_verdict: {default_v}",
                "Set default_verdict: block in rules.yaml for deny-by-default",
            )
        )

    # --- Check 4: fail_open ---
    fail_open = config.get("fail_open", True)
    if not fail_open:
        report.add(Check("Fail mode", True, 10, "✓ fail_open: false (fail-closed)"))
    else:
        report.add(
            Check(
                "Fail mode",
                False,
                10,
                "⚠ fail_open: true (errors won't block tools)",
                "Set fail_open: false in policyshield.yaml",
            )
        )

    # --- Check 5: Builtin detectors ---
    detectors = config.get("sanitizer", {}).get("builtin_detectors", [])
    all_detectors = {"path_traversal", "shell_injection", "sql_injection", "ssrf", "url_schemes"}
    enabled = set(detectors) & all_detectors
    if len(enabled) == len(all_detectors):
        report.add(Check("Builtin detectors", True, 15, f"✓ All {len(all_detectors)} detectors enabled"))
    elif enabled:
        report.add(
            Check(
                "Builtin detectors",
                False,
                15,
                f"⚠ {len(enabled)}/{len(all_detectors)} detectors enabled",
                f"Enable missing: {', '.join(all_detectors - enabled)}",
            )
        )
    else:
        report.add(
            Check(
                "Builtin detectors",
                False,
                15,
                "✗ No builtin detectors enabled",
                "Add sanitizer.builtin_detectors in policyshield.yaml",
            )
        )

    # --- Check 6: PII protection ---
    has_redact = any(r.get("then") == "redact" for r in rules)
    if has_redact:
        report.add(Check("PII protection", True, 10, "✓ PII redaction rules present"))
    else:
        report.add(
            Check(
                "PII protection",
                False,
                10,
                "⚠ No PII redaction rules",
                "Add a rule with 'then: redact' for outgoing tools",
            )
        )

    # --- Check 7: Exec/shell protection ---
    has_exec_block = any(
        r.get("then") == "block" and _tool_matches(r.get("when", {}), {"exec", "shell", "run_command", "system"})
        for r in rules
    )
    if has_exec_block:
        report.add(Check("Exec protection", True, 10, "✓ Shell/exec blocking rules present"))
    else:
        report.add(
            Check(
                "Exec protection", False, 10, "⚠ No exec/shell blocking rules", "Add a block rule for exec/shell tools"
            )
        )

    # --- Check 8: Rate limiting ---
    has_rate = any("session" in r.get("when", {}) for r in rules)
    if has_rate:
        report.add(Check("Rate limiting", True, 5, "✓ Rate limiting rules present"))
    else:
        report.add(
            Check(
                "Rate limiting",
                False,
                5,
                "⚠ No rate limiting rules",
                "Add session-based rate limits for high-volume tools",
            )
        )

    # --- Check 9: Approval flows ---
    has_approve = any(r.get("then") == "approve" for r in rules)
    if has_approve:
        report.add(Check("Approval flows", True, 10, "✓ Human-in-the-loop approval rules present"))
    else:
        report.add(
            Check("Approval flows", False, 10, "⚠ No approval rules", "Add 'then: approve' for sensitive operations")
        )

    # --- Check 10: Tracing ---
    trace = config.get("trace", {})
    if trace.get("enabled", False):
        report.add(Check("Tracing", True, 5, "✓ Tracing enabled"))
    else:
        report.add(Check("Tracing", False, 5, "⚠ Tracing disabled", "Enable trace.enabled in policyshield.yaml"))

    report.finalize()
    return report


def _tool_matches(when: dict, tools: set[str]) -> bool:
    """Check if a rule's 'when' clause matches any of the given tool names."""
    tool = when.get("tool", "")
    if isinstance(tool, list):
        return bool(set(tool) & tools)
    return tool in tools


def format_report(report: DoctorReport) -> str:
    """Format a DoctorReport for CLI output."""
    lines = [
        "╔═══════════════════════════════════════════╗",
        "║       PolicyShield Doctor Report          ║",
        "╚═══════════════════════════════════════════╝",
        "",
    ]

    for check in report.checks:
        lines.append(f"  {check.message}")
        if not check.passed and check.recommendation:
            lines.append(f"    → {check.recommendation}")

    lines.append("")
    lines.append(f"  Score: {report.score}/{report.max_score} — Grade: {report.grade}")

    if report.grade in ("A",):
        lines.append("  🛡️  Excellent security posture!")
    elif report.grade in ("B",):
        lines.append("  👍 Good, a few improvements possible")
    elif report.grade in ("C",):
        lines.append("  ⚠️  Fair — review recommendations above")
    else:
        lines.append("  🚨 Needs improvement — follow recommendations above")

    return "\n".join(lines)
