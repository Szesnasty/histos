"""Talk to the MCP server, and turn what it says into something Histos can read.

`tools/list` returns MCP `Tool` objects. `histos import --kind mcp` reads the wire
shape — `{"name", "description", "inputSchema"}` — so this module is the twenty
lines that bridge the two, and everything downstream is the library's ordinary
import, drift and gate machinery with nothing special about MCP in it.

`Client(server)` is the SDK's **in-memory** transport: the client and the server
speak the real protocol over a pair of in-process streams, with no subprocess and
no socket. The message shapes are genuine; the network is not there. The README
says so out loud, because "over a real MCP connection" would otherwise be read as
a claim about the wire.
"""

from __future__ import annotations

import asyncio
from typing import Any

from mcp import Client
from mcp.server.mcpserver import MCPServer

LOCATOR = "mcp://docuvault"


async def _fetch(server: MCPServer) -> list[dict[str, Any]]:
    async with Client(server) as client:
        listing = await client.list_tools()
        return [
            {"name": tool.name, "description": tool.description, "inputSchema": tool.input_schema}
            for tool in listing.tools
        ]


def tools_list(server: MCPServer) -> dict[str, Any]:
    """A `tools/list` response, exactly as `histos import --kind mcp` expects it."""
    return {"tools": asyncio.run(_fetch(server))}


async def _call(server: MCPServer, name: str, args: dict[str, Any]) -> Any:
    async with Client(server) as client:
        result = await client.call_tool(name, args)
        return [getattr(block, "text", str(block)) for block in result.content]


def call(server: MCPServer, name: str, args: dict[str, Any]) -> Any:
    """Issue `tools/call`. `run.py gate` wraps this, so a denied call never reaches here."""
    return asyncio.run(_call(server, name, args))
