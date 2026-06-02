"""Benign control MCP server (build spec Section 11).

Honest tool descriptions, benign responses, no required-arg tricks. Scanning
this server with the firewall MUST yield verdict == "pass".

Run standalone:  python servers/clean_server.py
"""

from __future__ import annotations

from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("clean-server")


@mcp.tool()
def get_time() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two integers and return the sum."""
    return a + b


@mcp.tool()
def greet(name: str = "world") -> str:
    """Return a friendly greeting for the given name."""
    return f"Hello, {name}!"


if __name__ == "__main__":
    mcp.run()  # stdio transport by default
