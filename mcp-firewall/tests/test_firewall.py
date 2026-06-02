"""Firewall integration tests against the real local stdio servers.

Build spec Section 15.2:
  * scanning clean_server.py    -> verdict == "pass"
  * scanning poisoned_server.py -> verdict == "block", with findings on BOTH
    the "description" and "response" channels.

These use the real MCP stdio transport (no network). Marked async.
"""

from __future__ import annotations

import os
import sys

import pytest

from mcp_firewall.detector import Detector
from mcp_firewall.firewall import scan_server
from mcp_firewall.ml_detector import MLDetector

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLEAN = os.path.join(REPO_ROOT, "servers", "clean_server.py")
POISONED = os.path.join(REPO_ROOT, "servers", "poisoned_server.py")


@pytest.fixture
def detector(tmp_path):
    # Force ML off (no model) so tests are deterministic and dependency-free.
    return Detector(ml=MLDetector(model_dir=str(tmp_path / "no-model")))


def _state(tmp_path):
    return str(tmp_path / "state.json")


@pytest.mark.asyncio
async def test_clean_server_passes(detector, tmp_path):
    result = await scan_server(
        command=sys.executable,
        args=[CLEAN],
        detector=detector,
        state_path=_state(tmp_path),
    )
    assert result.verdict == "pass", result.findings
    assert result.scanned_items > 0


@pytest.mark.asyncio
async def test_poisoned_server_blocks_on_both_channels(detector, tmp_path):
    result = await scan_server(
        command=sys.executable,
        args=[POISONED],
        detector=detector,
        state_path=_state(tmp_path),
    )
    assert result.verdict == "block", result.findings

    channels = {f.channel for f in result.findings}
    assert "description" in channels, "expected a description-channel finding"
    assert "response" in channels, "expected a response-channel finding"

    detectors = {f.detector for f in result.findings}
    # The weather description should trip the override-phrase rule.
    assert "rule:R3_override_phrase" in detectors


@pytest.mark.asyncio
async def test_poisoned_server_skips_arg_requiring_tools(detector, tmp_path):
    result = await scan_server(
        command=sys.executable,
        args=[POISONED],
        detector=detector,
        state_path=_state(tmp_path),
    )
    # `weather` (needs city) and `lookup` (needs record_id) require args and
    # must be recorded as skipped, never auto-called with invented values.
    assert "weather" in result.skipped_tools
    assert "lookup" in result.skipped_tools
