"""Offensive tool registry, `.bin/` binary adapters, BeEF C2, and OOB manager."""
from tools.registry import (
    register_tool,
    resolve_binary,
    exec_binary,
    get_tool,
    run_tool,
    list_tools,
    tools_for_role,
    inventory_report,
)

__all__ = [
    "register_tool",
    "resolve_binary",
    "exec_binary",
    "get_tool",
    "run_tool",
    "list_tools",
    "tools_for_role",
    "inventory_report",
]
