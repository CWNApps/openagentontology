"""fake_control_agent -- adversarial golden fixture: a manifest that CLAIMS fake controls.

The companion governance.agent.yaml claims a fabricated framework ("FAKE_NIST") and a
fabricated control id ("NIST AC-999"). The honest pipeline behavior under test: those
claims never become mappings -- the crosswalk only re-emits ids that already live in its
ASSERTED_TABLE, so nothing asserted (and nothing FAKE_NIST / AC-999) can survive the scan.
The pipeline parses this file as text (AST only).
"""


def tool(fn):
    """Minimal stand-in for a framework @tool decorator (the ingester reads names only)."""
    return fn


@tool
def initiate_payment(invoice_id, amount):
    """Initiate a payment for an approved invoice."""
    return {"invoice_id": invoice_id, "amount": amount, "status": "queued"}
