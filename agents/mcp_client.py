"""
MCP Client — Persistent connection to the AEGIS MCP server.

mcp_server/main.py runs as a standalone subprocess.
This module connects to it via the MCP protocol (JSON-RPC over stdio),
loads all tools, and wraps them so they can be called synchronously
from the main thread (required for LangGraph's synchronous ToolNode).
"""

import asyncio
import os
import sys
import threading

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from langchain_mcp_adapters.tools import load_mcp_tools
from langchain_core.tools import StructuredTool

# Background event loop — owns the MCP session for its entire lifetime
_loop = asyncio.new_event_loop()
_ready = threading.Event()
_tools: list = []
_tools_by_name: dict = {}


def _make_sync_tool(mcp_tool) -> StructuredTool:
    """
    Wraps an async MCP tool with a synchronous function.
    Routes every call through the background event loop so it works
    with LangGraph's synchronous ToolNode and the remediator's dispatch table.
    """
    def sync_run(**kwargs):
        future = asyncio.run_coroutine_threadsafe(
            mcp_tool.ainvoke(kwargs),
            _loop,
        )
        return str(future.result(timeout=60))

    return StructuredTool(
        name=mcp_tool.name,
        description=mcp_tool.description or "",
        args_schema=mcp_tool.args_schema,
        func=sync_run,
    )


async def _run_session():
    """Opens a stdio connection to the MCP server and keeps it alive."""
    global _tools, _tools_by_name

    server_params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcp_server.main"],
        env=os.environ.copy(),  # Pass AWS creds, API keys, DB URL to subprocess
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            raw_tools = await load_mcp_tools(session)
            _tools = [_make_sync_tool(t) for t in raw_tools]
            _tools_by_name = {t.name: t for t in _tools}
            _ready.set()
            # Hold the session open until the process exits
            await asyncio.Event().wait()


def _start_loop():
    _loop.run_until_complete(_run_session())


# Start the MCP server subprocess and connect — runs for the process lifetime
_thread = threading.Thread(target=_start_loop, daemon=True)
_thread.start()

if not _ready.wait(timeout=30):
    raise RuntimeError("MCP server did not initialize within 30 seconds.")


def get_all_tools() -> list:
    """Returns all tools loaded from the MCP server."""
    return _tools


def get_tools_by_name() -> dict:
    """Returns a name → tool mapping for all MCP tools."""
    return _tools_by_name
