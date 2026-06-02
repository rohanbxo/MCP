"""Detector orchestration (build spec Section 9).

Combines the deterministic rule engine with the optional ML detector and
produces ``Finding`` lists / ``ScanResult`` objects. ``decide_verdict`` is a
pure, unit-testable function implementing the Section 6 verdict logic.
"""

from __future__ import annotations

from .ml_detector import MLDetector
from .models import Channel, Finding, ScanResult, Verdict
from .rules import run_rules


def decide_verdict(findings: list[Finding]) -> Verdict:
    """Pure verdict logic (build spec Section 6).

    any critical/high -> "block"; else any medium -> "warn"; else "pass".
    """
    severities = {f.severity for f in findings}
    if severities & {"critical", "high"}:
        return "block"
    if "medium" in severities:
        return "warn"
    return "pass"


def build_result(
    findings: list[Finding],
    scanned_items: int,
    skipped_tools: list[str] | None = None,
) -> ScanResult:
    """Assemble a ScanResult with the derived verdict."""
    return ScanResult(
        verdict=decide_verdict(findings),
        findings=findings,
        scanned_items=scanned_items,
        skipped_tools=skipped_tools or [],
    )


class Detector:
    """Runs rules + (optional) ML over a single text/channel/source."""

    def __init__(self, ml: MLDetector | None = None, ml_threshold: float = 0.5) -> None:
        # If no detector is supplied, create one — it self-disables when no
        # model is present, so this is always safe.
        self.ml = ml if ml is not None else MLDetector()
        self.ml_threshold = ml_threshold

    @property
    def ml_available(self) -> bool:
        return self.ml.available

    def scan_text(self, text: str | None, channel: Channel, source: str) -> list[Finding]:
        """Rule findings plus, if the ML model fires above threshold, one ML finding."""
        findings: list[Finding] = list(run_rules(text, channel, source))

        if text and self.ml.available:
            label, confidence = self.ml.score(text)
            if label == "injection" and confidence >= self.ml_threshold:
                findings.append(
                    Finding(
                        channel=channel,
                        source=source,
                        detector="ml",
                        severity="high",
                        score=confidence,
                        matched_text=(text.strip()[:200]),
                        message=(
                            "ML classifier flagged this text as a prompt-injection "
                            f"attempt (confidence {confidence:.2f})."
                        ),
                        remediation=(
                            "Review the flagged description/response. Treat tool "
                            "output as untrusted data; do not let it issue "
                            "instructions to the model."
                        ),
                    )
                )
        return findings
