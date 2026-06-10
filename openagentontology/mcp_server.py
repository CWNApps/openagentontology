"""mcp_server.py -- OpenAgentOntology as a Model Context Protocol server.

Exposes the read-only, deterministic OAO pipeline as MCP tools so any agent or IDE
(Claude Desktop, Cursor, Claude Code) can govern an agent inline:

  oao_scan_agent(path)           governance summary + the ungoverned actions for a local agent
  oao_map_action(label, reason)  the framework controls that answer for one action label
  oao_verify_receipt(receipt)    offline cryptographic verification of an OAO receipt
  oao_explain()                  tiers / weights / frameworks, so a caller can read a score

Zero execution surface: the underlying package only parses AST + text, it never runs the
agent. No network. scan reads LOCAL paths only (no clone, no fetch) so the tool can never be
turned into an SSRF or arbitrary-checkout primitive. Every list handed back is capped so a
huge agent cannot blow the caller's context window.

Run (stdio transport):  python -m openagentontology.mcp_server
Install the optional dep: pip install "openagentontology[mcp]"
"""
from __future__ import annotations

from pathlib import Path

from .crosswalk import ALLOWED_FRAMEWORKS, map_action
from .pipeline import run_pipeline
from .receipt import verify_receipt
from .schema import TIERS
from .trust_profile import _BANDS, _WEIGHTS

# Cap list sizes returned to a model so a large agent cannot flood the context window.
_LIST_CAP = 60


def _confidences(action_map) -> list:
    return sorted({m.confidence for m in action_map.mappings})


def scan_agent(path: str, max_items: int = _LIST_CAP) -> dict:
    """Scan a LOCAL agent file or directory and return a compact governance summary.

    Never executes the agent (AST + text parse only). Returns the 0-100 score, the trust
    tier, per-action governance, and the ungoverned actions to fix first. `path` must be a
    local file or directory -- the tool never clones or fetches over the network.
    """
    p = Path(path).expanduser()
    if not p.exists():
        return {"error": f"path not found: {path}"}
    cap = max(1, min(int(max_items), 500))
    res = run_pipeline(str(p), make_receipt=False)

    governed, ungoverned = [], []
    for am in res.ontology.action_maps:
        if am.matched_via == "none" or not am.mappings:
            ungoverned.append(am.label)
            continue
        governed.append({
            "action": am.label,
            "matched_via": am.matched_via,
            "controls": [f"{m.fw} {m.id}" for m in am.mappings][:6],
            "confidence": _confidences(am),
        })

    return {
        "source": res.source,
        "score": res.score,
        "tier": res.tier,
        "validates": res.ok,
        "counts": {
            "nodes": len(res.ontology.nodes),
            "actions": len(res.ontology.action_maps),
            "governed": len(governed),
            "ungoverned": len(ungoverned),
        },
        "asserted_controls": list(res.refs),
        "ungoverned_actions": ungoverned[:cap],
        "governed_actions": governed[:cap],
        "rationale": list(res.profile.rationale),
        "note": res.ontology.note,
    }


def map_action_controls(label: str, source_reason: str = "") -> dict:
    """Map ONE action label to the governance controls that answer for it.

    source_reason is an optional canonical OPA deny reason (e.g. 'dual_control_required').
    When it matches the canonical table the result is ASSERTED; otherwise the label verb
    heuristic runs and any result is INFERRED -- a heuristic is never auto-asserted.
    """
    am = map_action(label, source_reason=source_reason or None)
    return {
        "action": label,
        "matched_via": am.matched_via,
        "mappings": [
            {"framework": m.fw, "id": m.id, "name": m.name,
             "confidence": m.confidence, "basis": m.basis}
            for m in am.mappings
        ],
    }


def verify(receipt: dict) -> dict:
    """Verify an OAO receipt offline: recompute the evidence hash and check the signature."""
    if not isinstance(receipt, dict):
        return {"ok": False, "reason": "receipt must be a JSON object"}
    return verify_receipt(receipt)


def explain() -> dict:
    """Return how to read a score: tiers, axis weights, frameworks, and the crosswalk layers."""
    return {
        "tiers": {name: f">= {floor}" for name, floor in _BANDS},
        "tier_order": list(TIERS),
        "axis_weights": dict(_WEIGHTS),
        "frameworks": sorted(ALLOWED_FRAMEWORKS),
        "layers": [
            "ASSERTED -- exact, source-named control (auditable)",
            "INFERRED -- heuristic verb match (confirm against control text; never auto-asserted)",
            "UNGOVERNED -- no control answers (fix these first)",
        ],
        "mantra": "No Receipt. No Trust.",
    }


def build_server():
    """Wire the pure tool functions into a FastMCP server.

    `mcp` is imported lazily so the core package keeps zero runtime dependency on it; install
    the [mcp] extra only when you actually want to run the server.
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # pragma: no cover - only hit without the optional extra
        raise SystemExit(
            'The OAO MCP server needs the optional dependency. Install it with:\n'
            '    pip install "openagentontology[mcp]"'
        ) from exc

    server = FastMCP("openagentontology")
    server.tool(name="oao_scan_agent")(scan_agent)
    server.tool(name="oao_map_action")(map_action_controls)
    server.tool(name="oao_verify_receipt")(verify)
    server.tool(name="oao_explain")(explain)
    return server


def main() -> None:
    build_server().run()


if __name__ == "__main__":
    main()
