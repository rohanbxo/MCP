"""FastAPI scan service (build spec Section 12).

  * GET  /health -> {"status":"ok","ml_available":bool}
  * POST /scan   -> body {text, channel?, source?} -> ScanResult JSON

One shared Detector is instantiated at startup. No MCP connection is needed for
the /scan endpoint — it scans the provided text directly.

Run:  uvicorn mcp_firewall.api:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import os

from fastapi import FastAPI
from pydantic import BaseModel

from .detector import Detector, build_result
from .ml_detector import MLDetector
from .models import Channel, ScanResult

app = FastAPI(
    title="MCP Tool-Response Firewall",
    description="Scan text (tool descriptions / responses) for prompt-injection "
    "and tool poisoning.",
    version="0.1.0",
)

# One shared Detector for the process. Model dir overridable via env.
_MODEL_DIR = os.environ.get("MCP_FIREWALL_MODEL_DIR", "./model")
_ML_THRESHOLD = float(os.environ.get("MCP_FIREWALL_ML_THRESHOLD", "0.5"))
detector = Detector(
    ml=MLDetector(model_dir=_MODEL_DIR), ml_threshold=_ML_THRESHOLD
)


class ScanRequest(BaseModel):
    text: str
    channel: Channel = "response"
    source: str = "manual"


class HealthResponse(BaseModel):
    status: str
    ml_available: bool


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok", ml_available=detector.ml_available)


@app.post("/scan", response_model=ScanResult)
def scan(req: ScanRequest) -> ScanResult:
    findings = detector.scan_text(req.text, req.channel, req.source)
    return build_result(findings, scanned_items=1)
