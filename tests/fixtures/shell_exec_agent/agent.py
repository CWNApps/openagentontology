"""shell_exec_agent -- golden fixture: an agent with raw command execution and zero governance.

One declared tool runs an arbitrary command via subprocess. There is no governance manifest
and no policy, and 'exec' names no canonical reason and matches no crosswalk verb heuristic,
so the honest scan result is UNGOVERNED with the capability left unmapped (matched_via='none').
The pipeline parses this file as text (AST only) -- it is never imported or executed.
"""
import subprocess


def tool(fn):
    """Minimal stand-in for a framework @tool decorator (the ingester reads names only)."""
    return fn


@tool
def exec(cmd):
    """Execute an arbitrary command (argv list) and return its standard output."""
    return subprocess.run(cmd, capture_output=True, text=True).stdout
