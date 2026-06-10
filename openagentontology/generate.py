"""generate.py — assemble an OntologyDoc from an IngestResult.

Pure transform. Takes the normalized facts/rels an ingest adapter extracted and:
  - carries each extracted Node through (provenance preserved),
  - keeps only edges whose endpoints both exist (no dangling edges leave generate),
  - runs the crosswalk on every Capability / Decision / Gate node, passing the
    source-named reason (ing.reasons[node_id]) so Layer-1 ASSERTED fires when the
    source named a reason and Layer-2 heuristics fire otherwise,
  - collects the distinct ASSERTED frameworks into doc.frameworks,
  - stamps doc.note with the verbatim CONFIRM_NOTE.

The crosswalk hangs off the UAO-typed Decision/Gate/Capability nodes, so the public
schema derives from the universal root rather than a flat list — exactly as the YAML
lineage rule mandates.

This module imports schema + crosswalk only. It does NOT import ingest (it consumes the
IngestResult interface, which ingest.py owns and produces). That keeps the build fan-out
parallel: generate depends on the IngestResult SHAPE, not on the adapter code.
"""
from __future__ import annotations

from .crosswalk import CONFIRM_NOTE, map_action
from .schema import ActionMap, Edge, Node, OntologyDoc

# The node types whose actions the crosswalk governs (side-effecting / decision points).
_GOVERNED_TYPES = ("Capability", "Decision", "Gate")


def _ingest_to_doc_parts(ing):
    """Pull the (source, kind, facts, rels, reasons) off an IngestResult duck-typed:
    works for the dataclass or any object/dict exposing those attributes/keys."""
    def g(name, default):
        if isinstance(ing, dict):
            return ing.get(name, default)
        return getattr(ing, name, default)
    return (g("source", ""), g("kind", "unknown"),
            list(g("facts", [])), list(g("rels", [])), dict(g("reasons", {})))


def generate(ing) -> OntologyDoc:
    """Build an OntologyDoc from an IngestResult. Deterministic, no I/O."""
    source, kind, facts, rels, reasons = _ingest_to_doc_parts(ing)

    # 1) carry nodes through; index by id for edge validation + crosswalk dispatch.
    nodes = []
    by_id = {}
    for f in facts:
        node = f if isinstance(f, Node) else _coerce_node(f)
        if node is None or node.id in by_id:
            continue
        by_id[node.id] = node
        nodes.append(node)

    # 2) keep only edges whose endpoints both resolve (drop dangling at the source).
    edges = []
    seen_edges = set()
    for r in rels:
        edge = r if isinstance(r, Edge) else _coerce_edge(r)
        if edge is None:
            continue
        if edge.src not in by_id or edge.dst not in by_id:
            continue
        key = (edge.src, edge.rel, edge.dst)
        if key in seen_edges:
            continue
        seen_edges.add(key)
        edges.append(edge)

    # 3) crosswalk governed nodes (Capability/Decision/Gate) AND any discovered
    #    side-effecting Task that is NOT a mirror of an already-governed Capability.
    #    A verb-named function (exec / run / delete_* / send_*) lands as a Task; if nothing
    #    else governs it, it must STILL be crosswalked — otherwise the most dangerous surface
    #    of a real agent stays ungoverned-and-invisible. OpenAPI/MCP specs emit a
    #    capability+operation PAIR for one action, so we skip the mirrored Task (same action
    #    label as a Capability) to avoid double-counting.
    cap_actions = {(n.props.get("action") or n.name or n.id)
                   for n in nodes if n.type == "Capability"}
    action_maps = []
    for node in nodes:
        label = node.props.get("action") or node.name or node.id
        if node.type not in _GOVERNED_TYPES:
            if node.type != "Task" or label in cap_actions:
                continue
        am = map_action(label, reasons.get(node.id))
        # re-key the ActionMap to the node id so validate/score can join back.
        action_maps.append(ActionMap(subject_id=node.id, label=am.label,
                                     mappings=am.mappings, matched_via=am.matched_via))

    # 4) distinct ASSERTED frameworks (the breadth signal the trust profile rewards).
    frameworks = []
    for am in action_maps:
        for m in am.mappings:
            if m.confidence == "asserted" and m.fw not in frameworks:
                frameworks.append(m.fw)

    return OntologyDoc(source=source, source_kind=kind, nodes=nodes, edges=edges,
                       action_maps=action_maps, frameworks=frameworks, note=CONFIRM_NOTE)


# ── tolerant coercion (so an adapter may emit plain dicts if it prefers) ──────
def _coerce_node(f) -> Node | None:
    if not isinstance(f, dict):
        return None
    nid = f.get("id")
    if not nid:
        return None
    return Node(id=nid, type=f.get("type", "Resource"), name=f.get("name", nid),
                props=dict(f.get("props", {})), provenance=f.get("provenance", "EXTRACTED"))


def _coerce_edge(r) -> Edge | None:
    if not isinstance(r, dict):
        return None
    src, rel, dst = r.get("src"), r.get("rel"), r.get("dst")
    if not (src and rel and dst):
        return None
    return Edge(src=src, rel=rel, dst=dst, provenance=r.get("provenance", "EXTRACTED"))
