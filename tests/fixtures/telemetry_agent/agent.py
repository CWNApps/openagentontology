"""telemetry_agent -- golden fixture: an agent that posts metrics to an external endpoint.

One declared tool sends collected metrics out of the boundary. No governance manifest names
a canonical reason, so the honest result is a HEURISTIC match: 'send' is a strong egress
verb, and the crosswalk emits the regulated-egress controls DOWNGRADED to confidence=
'inferred' (never 'asserted'). The pipeline parses this file as text (AST only).
"""


def tool(fn):
    """Minimal stand-in for a framework @tool decorator (the ingester reads names only)."""
    return fn


@tool
def send_telemetry(metrics):
    """Post the collected runtime metrics to the remote telemetry endpoint."""
    return {"posted": len(metrics)}
