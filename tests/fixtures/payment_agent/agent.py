"""payment_agent -- golden fixture: a payment capability governed by a DECLARED reason.

The tool below moves money. Its governance manifest (governance.agent.yaml) names the
canonical reason 'dual_control_required' for this exact capability, and the fail-closed
policy (payments.rego) carries the matching deny key -- so the crosswalk's Layer-1
ASSERTED table fires and the mappings come through at confidence='asserted' with
provenance='EXTRACTED'. The pipeline parses this file as text (AST only).
"""


def tool(fn):
    """Minimal stand-in for a framework @tool decorator (the ingester reads names only)."""
    return fn


@tool
def initiate_payment(invoice_id, amount):
    """Initiate a payment for an approved invoice."""
    return {"invoice_id": invoice_id, "amount": amount, "status": "queued"}
