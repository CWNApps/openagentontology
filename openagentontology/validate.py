"""validate.py — structural + provenance + crosswalk-rigor validator (fail-closed).

Mirrors firewall_ontology_eval's mapping-RIGOR gate: the ontology fails closed if any
guardrail maps to a fabricated/unsourced control, or if a mapping would break the
cross-language receipt verifier. Returns (ok, [Finding]); ok = no error-level findings.

ERROR (fail-closed — voids trust, pol.must_do.143):
  E_FRAMEWORK   any Mapping.fw not in crosswalk.ALLOWED_FRAMEWORKS (fabrication guard)
  E_ASSERTED    any confidence=='asserted' Mapping missing fw / id / name / basis
  E_NODE_TYPE   any node.type not in NODE_TYPES
  E_DANGLING    any edge endpoint id absent from the node set
  E_EDGE_REL    any edge.rel not in LINK_TYPES
  E_NONASCII    any non-ASCII char in any mapping field, basis, or the note (receipt safety)
  E_EMPTY       the ontology has 0 nodes
  E_FAKE_ID     a confidence=='asserted' mapping whose (fw,id) pair is not in ASSERTED_TABLE
                (a typo / bad edit that smuggled an id past Layer 1 fails closed here)

WARN (does not block; the trust profile reads these):
  W_UNGOVERNED  a Decision/Gate/Capability whose ActionMap.matched_via == 'none'
  W_AMBIGUOUS   an AMBIGUOUS mapping is present (held together by a guess)

Pure function. Imports schema + crosswalk only.
"""
from __future__ import annotations

from .crosswalk import ALLOWED_FRAMEWORKS, ASSERTED_TABLE
from .schema import Finding, LINK_TYPES, NODE_TYPES


def _ascii_ok(s) -> bool:
    if not isinstance(s, str):
        return True
    try:
        s.encode("ascii")
        return True
    except UnicodeEncodeError:
        return False


# (fw, id) pairs that legitimately carry an 'asserted' confidence — the only ids allowed to.
_ASSERTED_PAIRS = {(m.fw, m.id) for ms in ASSERTED_TABLE.values() for m in ms
                   if m.confidence == "asserted"}


def validate(doc) -> tuple:
    """Return (ok, findings). ok is False iff any error-level finding is present."""
    findings = []

    def err(code, msg):
        findings.append(Finding("error", code, msg))

    def warn(code, msg):
        findings.append(Finding("warn", code, msg))

    # E_EMPTY -----------------------------------------------------------------
    if not doc.nodes:
        err("E_EMPTY", "ontology has 0 nodes")

    # node ids + type check ---------------------------------------------------
    node_ids = set()
    for n in doc.nodes:
        node_ids.add(n.id)
        if n.type not in NODE_TYPES:
            err("E_NODE_TYPE", f"node '{n.id}' has type '{n.type}' not in NODE_TYPES")
        if not _ascii_ok(n.name) or not _ascii_ok(n.id):
            err("E_NONASCII", f"node '{n.id}' carries non-ASCII text")

    # edge checks -------------------------------------------------------------
    for e in doc.edges:
        if e.rel not in LINK_TYPES:
            err("E_EDGE_REL", f"edge {e.src}-{e.rel}->{e.dst} uses rel '{e.rel}' not in LINK_TYPES")
        if e.src not in node_ids:
            err("E_DANGLING", f"edge src '{e.src}' is not a node")
        if e.dst not in node_ids:
            err("E_DANGLING", f"edge dst '{e.dst}' is not a node")

    # note ASCII --------------------------------------------------------------
    if not _ascii_ok(doc.note):
        err("E_NONASCII", "doc.note carries non-ASCII text")

    # mapping rigor -----------------------------------------------------------
    ambiguous_seen = False
    for am in doc.action_maps:
        if am.matched_via == "none":
            warn("W_UNGOVERNED", f"action '{am.subject_id}' has no mapped control (ungoverned)")
        for m in am.mappings:
            if m.fw not in ALLOWED_FRAMEWORKS:
                err("E_FRAMEWORK", f"mapping fw '{m.fw}' on '{am.subject_id}' is outside ALLOWED_FRAMEWORKS")
            for fld in ("fw", "id", "name", "basis", "confidence", "provenance"):
                if not _ascii_ok(getattr(m, fld)):
                    err("E_NONASCII", f"mapping field '{fld}' on '{am.subject_id}' carries non-ASCII text")
            if m.confidence == "asserted":
                if not (m.fw and m.id and m.name and m.basis):
                    err("E_ASSERTED", f"asserted mapping on '{am.subject_id}' missing fw/id/name/basis")
                if (m.fw, m.id) not in _ASSERTED_PAIRS:
                    err("E_FAKE_ID", f"asserted mapping ({m.fw} {m.id}) on '{am.subject_id}' is not in ASSERTED_TABLE")
            if m.provenance == "AMBIGUOUS" or m.confidence == "ambiguous":
                ambiguous_seen = True

    if ambiguous_seen:
        warn("W_AMBIGUOUS", "one or more controls resolved only to an ambiguous heuristic stub")

    ok = not any(f.level == "error" for f in findings)
    return ok, findings
