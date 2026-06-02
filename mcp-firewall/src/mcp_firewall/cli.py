"""Command-line interface (build spec Section 13).

Subcommands:
  * scan-server --command python --args servers/poisoned_server.py
        runs scan_server, prints a readable report, exits 1 if verdict=="block".
  * scan-text --text "..."
        scans a single string and prints a ScanResult.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from .detector import Detector, build_result
from .firewall import scan_server
from .ml_detector import MLDetector
from .models import ScanResult

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _ensure_utf8_stdout() -> None:
    """Best-effort: print UTF-8 so scanned text never triggers a console
    UnicodeEncodeError on a legacy code page (e.g. Windows cp1252)."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="backslashreplace")
            except (ValueError, OSError):
                pass


def _print_report(result: ScanResult) -> None:
    print(f"VERDICT: {result.verdict.upper()}")
    print(f"scanned_items: {result.scanned_items}")
    if result.skipped_tools:
        print(
            "skipped (require args, not auto-called): "
            + ", ".join(result.skipped_tools)
        )
    print(f"findings: {len(result.findings)}")
    print("-" * 70)

    findings = sorted(
        result.findings, key=lambda f: _SEV_ORDER.get(f.severity, 99)
    )
    for i, f in enumerate(findings, 1):
        print(f"[{i}] {f.severity.upper()}  {f.channel}  source={f.source}")
        print(f"    detector:    {f.detector}  (score={f.score:.2f})")
        print(f"    message:     {f.message}")
        print(f"    matched:     {f.matched_text}")
        print(f"    remediation: {f.remediation}")
        print()

    if not findings:
        print("No findings.")


def _build_detector(model_dir: str | None, ml_threshold: float) -> Detector:
    return Detector(ml=MLDetector(model_dir=model_dir), ml_threshold=ml_threshold)


def _cmd_scan_server(ns: argparse.Namespace) -> int:
    detector = _build_detector(ns.model_dir, ns.ml_threshold)
    result = asyncio.run(
        scan_server(
            command=ns.command,
            args=ns.args,
            detector=detector,
            call_safe_tools=not ns.no_call,
        )
    )
    _print_report(result)
    # Exit 1 when blocked (enables CI gating); else 0.
    return 1 if result.verdict == "block" else 0


def _cmd_scan_text(ns: argparse.Namespace) -> int:
    detector = _build_detector(ns.model_dir, ns.ml_threshold)
    findings = detector.scan_text(ns.text, ns.channel, ns.source)
    result = build_result(findings, scanned_items=1)
    if ns.json:
        print(result.model_dump_json(indent=2))
    else:
        _print_report(result)
    return 1 if result.verdict == "block" else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-firewall",
        description="MCP Tool-Response Firewall — scan MCP servers/text for "
        "prompt-injection and tool poisoning.",
    )
    parser.add_argument(
        "--model-dir",
        default="./model",
        help="Directory of a fine-tuned DistilBERT model (optional).",
    )
    parser.add_argument(
        "--ml-threshold",
        type=float,
        default=0.5,
        help="Confidence threshold for the ML detector (default 0.5).",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_srv = sub.add_parser(
        "scan-server", help="Connect to an MCP server and scan it."
    )
    p_srv.add_argument(
        "--command", required=True, help="Executable to launch the server."
    )
    p_srv.add_argument(
        "--args",
        nargs="*",
        default=[],
        help="Arguments passed to the server command.",
    )
    p_srv.add_argument(
        "--no-call",
        action="store_true",
        help="Do not auto-call no-arg tools (descriptions only).",
    )
    p_srv.set_defaults(func=_cmd_scan_server)

    p_txt = sub.add_parser("scan-text", help="Scan a single text string.")
    p_txt.add_argument("--text", required=True, help="Text to scan.")
    p_txt.add_argument(
        "--channel",
        default="response",
        choices=["description", "response", "schema"],
        help="Channel label for the text (default response).",
    )
    p_txt.add_argument(
        "--source", default="manual", help="Source label (default manual)."
    )
    p_txt.add_argument(
        "--json", action="store_true", help="Print the ScanResult as JSON."
    )
    p_txt.set_defaults(func=_cmd_scan_text)

    return parser


def main(argv: list[str] | None = None) -> int:
    _ensure_utf8_stdout()
    parser = build_parser()
    ns = parser.parse_args(argv)
    return ns.func(ns)


if __name__ == "__main__":
    sys.exit(main())
