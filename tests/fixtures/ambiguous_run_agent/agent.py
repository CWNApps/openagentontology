"""ambiguous_run_agent -- golden fixture: tools named with weak, overloaded verbs.

'run' is a side-effecting but domain-free verb: it could mean anything from a report to a
migration. The honest crosswalk result is the AMBIGUOUS stub (a single OWASP LLM06
excessive-agency placeholder, confidence='ambiguous') -- NEVER an inferred 800-53 id and
never anything asserted. The pipeline parses this file as text (AST only).
"""


def tool(fn):
    """Minimal stand-in for a framework @tool decorator (the ingester reads names only)."""
    return fn


@tool
def run_pipeline(name):
    """Kick off the named data-processing pipeline end to end."""
    return {"pipeline": name, "state": "started"}


@tool
def run_report(period):
    """Kick off the periodic summary report job."""
    return {"report": period, "state": "started"}
