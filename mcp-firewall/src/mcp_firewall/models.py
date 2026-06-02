"""Pydantic data model for findings and scan results (build spec Section 6)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["low", "medium", "high", "critical"]
Channel = Literal["description", "response", "schema"]
Verdict = Literal["pass", "warn", "block"]


class Finding(BaseModel):
    """A single detection emitted by a rule or the ML detector."""

    channel: Channel
    source: str  # tool name (or "<server>")
    detector: str  # e.g. "rule:R1_shell_sink" or "ml"
    severity: Severity
    score: float  # rules = 1.0; ml = model confidence 0..1
    matched_text: str  # the flagged span (truncated to ~200 chars)
    message: str  # what was found and why it's risky
    remediation: str


class ScanResult(BaseModel):
    """Aggregate verdict over all scanned items."""

    verdict: Verdict
    findings: list[Finding] = Field(default_factory=list)
    scanned_items: int = 0
    skipped_tools: list[str] = Field(default_factory=list)
