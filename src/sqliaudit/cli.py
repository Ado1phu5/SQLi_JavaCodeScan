"""Command-line interface for the SQL injection auditor."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterable

from .scanner import Finding, scan_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sqliaudit",
        description="Scan Java source files for SQL injection risks",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=Path.cwd(),
        help="File or directory to scan",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Choose report output format",
    )
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Return non-zero exit code when findings are present",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=None,
        help="Optional limit when scanning extremely large directories",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    target = Path(args.target)
    findings = scan_path(target)

    if args.max_files is not None and target.is_dir():
        findings = findings[: args.max_files]

    if args.format == "json":
        print(json.dumps([finding.to_dict() for finding in findings], indent=2))
    else:
        _print_table(findings)
    if args.fail_on_findings and findings:
        return 1
    return 0


def _print_table(findings: Iterable[Finding]) -> None:
    findings = list(findings)
    if not findings:
        print("No SQL injection risks detected.")
        return
    file_width = max(len(Path(f.file).as_posix()) for f in findings)
    header = f"{'File'.ljust(file_width)}  Line  Rule  Sev  Message"
    print(header)
    print("-" * len(header))
    for finding in findings:
        file_name = Path(finding.file).as_posix().ljust(file_width)
        line = str(finding.line).rjust(4)
        severity = finding.severity[:4].ljust(4)
        print(f"{file_name}  {line}  {finding.rule_id:<6}  {severity} {finding.message}")
        print(f"    {finding.code}")


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
