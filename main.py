#!/usr/bin/env python3
"""CLI entry point for the phishing detector.

Usage examples
--------------
Analyse a raw email file::

    python main.py email path/to/email.eml

Analyse a URL directly::

    python main.py url https://suspicious-site.example.com/login

Read from stdin::

    cat email.eml | python main.py email -

Output as JSON (useful for piping into SIEM tools)::

    python main.py email path/to/email.eml --json
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from phishing_detector.engine import analyse_email, analyse_url_only
from phishing_detector.models import AnalysisResult, RiskLevel

# ANSI colour codes (disabled on non-TTY / Windows without ANSI support)
_COLOURS = {
    RiskLevel.HIGH: "\033[91m",    # bright red
    RiskLevel.MEDIUM: "\033[93m",  # bright yellow
    RiskLevel.LOW: "\033[96m",     # bright cyan
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
}


def _colourise(text: str, risk: Optional[RiskLevel] = None) -> str:
    """Wrap text in ANSI colour codes if stdout is a TTY."""
    if not sys.stdout.isatty():
        return text
    colour = _COLOURS.get(risk, "") if risk else ""
    return f"{colour}{text}{_COLOURS['RESET']}"


def _print_result(result: AnalysisResult, use_json: bool) -> None:
    """Print an AnalysisResult either as human-readable text or JSON."""
    if use_json:
        output = {
            "overall_risk": result.overall_risk.value,
            "score": result.score,
            "summary": result.summary,
            "findings": [
                {
                    "category": f.category,
                    "rule": f.rule,
                    "risk": f.risk.value,
                    "description": f.description,
                    "evidence": f.evidence,
                }
                for f in result.findings
            ],
        }
        print(json.dumps(output, indent=2))
        return

    # Human-readable output
    print()
    print(_colourise(f"{'='*60}", None))
    risk_label = _colourise(result.overall_risk.value, result.overall_risk)
    print(f"  {_colourise('PHISHING DETECTOR REPORT', None)}")
    print(f"  Risk Level : {risk_label}")
    print(f"  Score      : {result.score}/100")
    print(f"  Summary    : {result.summary}")
    print(_colourise(f"{'='*60}", None))

    if not result.findings:
        print("  No indicators found.")
    else:
        print(f"\n  Found {len(result.findings)} indicator(s):\n")
        for i, finding in enumerate(result.findings, 1):
            risk_str = _colourise(f"[{finding.risk.value:6}]", finding.risk)
            print(f"  {i:2}. {risk_str} [{finding.category}] {finding.rule}")
            print(f"      {finding.description}")
            if finding.evidence:
                truncated = finding.evidence[:120] + ("..." if len(finding.evidence) > 120 else "")
                print(f"      Evidence: {truncated}")
            print()
    print()


def _cmd_email(args: argparse.Namespace) -> int:
    """Handle the 'email' subcommand."""
    if args.path == "-":
        raw_email = sys.stdin.read()
    else:
        try:
            with open(args.path, "r", encoding="utf-8", errors="replace") as fh:
                raw_email = fh.read()
        except FileNotFoundError:
            print(f"Error: file not found: {args.path}", file=sys.stderr)
            return 1

    result = analyse_email(raw_email)
    _print_result(result, args.json)
    # Exit code 0 = LOW/no risk; 1 = MEDIUM; 2 = HIGH
    return {"LOW": 0, "MEDIUM": 1, "HIGH": 2}.get(result.overall_risk.value, 0)


def _cmd_url(args: argparse.Namespace) -> int:
    """Handle the 'url' subcommand."""
    result = analyse_url_only(args.url)
    _print_result(result, args.json)
    return {"LOW": 0, "MEDIUM": 1, "HIGH": 2}.get(result.overall_risk.value, 0)


def build_parser() -> argparse.ArgumentParser:
    """Build and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="phishing-detector",
        description="Analyse emails and URLs for phishing indicators.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exit codes: 0=LOW, 1=MEDIUM, 2=HIGH risk",
    )
    parser.add_argument(
        "--json", action="store_true", help="Output results as JSON (useful for SIEM piping)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # email subcommand
    email_parser = subparsers.add_parser("email", help="Analyse a raw email file")
    email_parser.add_argument(
        "path", help="Path to raw email file (.eml), or '-' to read from stdin"
    )
    email_parser.add_argument(
        "--json", action="store_true", help="Output as JSON"
    )

    # url subcommand
    url_parser = subparsers.add_parser("url", help="Analyse a single URL")
    url_parser.add_argument("url", help="URL to analyse")
    url_parser.add_argument(
        "--json", action="store_true", help="Output as JSON"
    )

    return parser


def main() -> None:
    """Main entry point."""
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "email":
        sys.exit(_cmd_email(args))
    elif args.command == "url":
        sys.exit(_cmd_url(args))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
