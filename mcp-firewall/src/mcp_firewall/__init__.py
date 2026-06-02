"""MCP Tool-Response Firewall.

Connects to an MCP server as a client, inspects tool *descriptions* at connect
time and tool *responses* at call time, and returns a verdict (pass/warn/block)
with detailed findings. Detection uses a deterministic rule engine plus an
optional fine-tuned DistilBERT classifier.
"""

from .models import Channel, Finding, ScanResult, Severity, Verdict
from .detector import Detector, build_result, decide_verdict
from .ml_detector import MLDetector

__version__ = "0.1.0"

__all__ = [
    "Channel",
    "Finding",
    "ScanResult",
    "Severity",
    "Verdict",
    "Detector",
    "MLDetector",
    "build_result",
    "decide_verdict",
    "__version__",
]
