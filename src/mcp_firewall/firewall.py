"""MCP client-wrapper firewall (build spec Section 10).

Connects to an MCP server over stdio using the official SDK, scans tool
*descriptions* at connect time and tool *responses* at call time, runs the R5
schema-drift check, and aggregates everything into a ScanResult.

This is a client wrapper — NOT a transport-level MITM proxy.
"""

from __future__ import annotations

import logging

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from .detector import Detector, build_result
from .models import Finding, ScanResult
from .rules import STATE_FILE, check_schema_drift, manifest_hash

logger = logging.getLogger("mcp_firewall.firewall")


def _required_params(input_schema: dict | None) -> list[str]:
    """Return the list of required parameters from a tool's JSON Schema."""
    if not isinstance(input_schema, dict):
        return []
    required = input_schema.get("required", [])
    return list(required) if isinstance(required, (list, tuple)) else []


def _extract_text(result) -> str:
    """Join the text from a CallToolResult's content blocks (guarded)."""
    parts: list[str] = []
    for block in getattr(result, "content", None) or []:
        text = getattr(block, "text", None)
        if text:
            parts.append(text)
    return "\n".join(parts)


async def scan_server(
    command: str,
    args: list[str],
    detector: Detector,
    call_safe_tools: bool = True,
    state_path: str = STATE_FILE,
    server_key: str | None = None,
) -> ScanResult:
    """Scan an MCP server reachable via ``command``/``args``.

    Steps (build spec Section 10):
      1. Connect via stdio_client + ClientSession.
      2. list_tools(); scan each tool.description (channel="description").
      3. Compute manifest hash -> R5 schema-drift check.
      4. If call_safe_tools: for each tool with no required params, call it with
         {} and scan the returned text (channel="response"). Skip tools needing
         args and record their names.
      5. Aggregate -> build_result.
    """
    findings: list[Finding] = []
    scanned_items = 0
    skipped_tools: list[str] = []
    key = server_key or " ".join([command, *args])

    params = StdioServerParameters(command=command, args=args, env=None)

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            tools = list(listed.tools)

            manifest: list[tuple[str, str | None, dict]] = []

            for tool in tools:
                name = tool.name
                desc = tool.description
                schema = tool.inputSchema or {}
                manifest.append((name, desc, schema))

                # (2) scan the description channel
                findings.extend(detector.scan_text(desc, "description", name))
                scanned_items += 1

            # (3) schema-drift check over the full manifest
            findings.extend(
                check_schema_drift(key, manifest_hash(manifest), state_path)
            )

            # (4) auto-call only no-required-arg tools and scan their responses
            if call_safe_tools:
                for tool in tools:
                    name = tool.name
                    if _required_params(tool.inputSchema):
                        skipped_tools.append(name)
                        logger.info(
                            "Skipping auto-call of %r (requires args: %s).",
                            name,
                            _required_params(tool.inputSchema),
                        )
                        continue
                    try:
                        result = await session.call_tool(name, arguments={})
                        text = _extract_text(result)
                        findings.extend(
                            detector.scan_text(text, "response", name)
                        )
                        scanned_items += 1
                    except Exception as exc:
                        # A failing tool call is recorded, never fatal.
                        logger.warning("Tool %r call failed: %s", name, exc)
                        findings.append(
                            Finding(
                                channel="response",
                                source=name,
                                detector="firewall:call_error",
                                severity="low",
                                score=0.0,
                                matched_text=str(exc)[:200],
                                message=(
                                    f"Auto-call of tool {name!r} raised an error; "
                                    "response could not be scanned."
                                ),
                                remediation=(
                                    "Investigate the tool error before trusting "
                                    "this server; the response was not inspected."
                                ),
                            )
                        )

    if skipped_tools:
        logger.info(
            "Skipped auto-calling tools that require arguments: %s",
            ", ".join(skipped_tools),
        )
    return build_result(findings, scanned_items, skipped_tools)
