"""trust_profile.py — score an OntologyDoc into a Trust Profile (tier + 0..100 score).

This is the honest, deterministic rubric behind the badge. It reads ONLY what the
crosswalk already produced (asserted vs heuristic-only mappings, ungoverned actions,
framework breadth) — it never re-runs the crosswalk and never invents a control. A high
score means the tool actually FOUND well-established controls covering the agent's
high-risk actions, not that the agent is "good".

WHY THESE AXES (each maps to a real governance question a buyer asks):
  coverage   — of the side-effecting / decision points (Capability / Decision / Gate),
               what fraction resolved to at least one ASSERTED control? This is the core
               signal: an ungoverned wire/export/deploy is the whole risk.
  rigor      — of the governed actions, what fraction are backed by an ASSERTED mapping
               (not just a heuristic INFERRED/AMBIGUOUS stub)? Penalizes guesswork so a
               badge can never be inflated by weak verb matches.
  breadth    — how many distinct ASSERTED frameworks the ontology touches (NIST 800-53 /
               EU AI Act / OWASP LLM / ...). Caps at a sane ceiling so breadth can't paper
               over thin coverage.
  structure  — is the graph actually wired (edges present, no dangling, nodes typed)? A
               flat node list with no relationships is a weaker artifact than a connected one.

SCORE = weighted sum of the four subscores (each 0..100), rounded to an int 0..100.
TIER from the operator's locked apocalypse-drill bands:
  SOVEREIGN >= 90 | HARDENED >= 75 | DEVELOPING >= 50 | UNGOVERNED < 50.

An ontology with ZERO governed actions (nothing the crosswalk could map — no Capability/
Decision/Gate and no side-effecting action function such as exec/run/delete_*/send_*) cannot
earn a governed tier: coverage and rigor are defined as 0, so it floors at UNGOVERNED. That is
the honest answer — there is nothing to govern, so there is nothing proven.

Pure function. Imports schema + crosswalk only. No I/O, no network, ASCII rationale.
"""
from __future__ import annotations

from .crosswalk import ALLOWED_FRAMEWORKS
from .schema import TIERS, TrustProfile

# Axis weights (sum == 1.0). Coverage dominates — an ungoverned high-risk action is the
# entire failure mode the badge exists to catch.
_WEIGHTS = {"coverage": 0.45, "rigor": 0.25, "breadth": 0.15, "structure": 0.15}

# Breadth ceiling: touching this many distinct ASSERTED frameworks earns full breadth.
# Set below len(ALLOWED_FRAMEWORKS) so a realistic 4-framework ontology can still max it.
_BREADTH_CEILING = 4

# Tier band floors (operator-locked apocalypse-drill bands).
_BANDS = (("SOVEREIGN", 90), ("HARDENED", 75), ("DEVELOPING", 50), ("UNGOVERNED", 0))


def _tier_for(score: int) -> str:
    for name, floor in _BANDS:
        if score >= floor:
            return name
    return "UNGOVERNED"  # unreachable (floor 0) but keeps the contract explicit


def _has_asserted(action_map) -> bool:
    return any(m.confidence == "asserted" for m in action_map.mappings)


def _has_any_mapping(action_map) -> bool:
    return bool(action_map.mappings)


def score(doc) -> TrustProfile:
    """Score an OntologyDoc -> TrustProfile(tier, score, subscores, rationale).

    Deterministic: identical docs always yield an identical profile (safe to put the
    score inside the signed receipt evidence). rationale is a tuple of ASCII lines.
    """
    nodes = list(doc.nodes)
    # generate() already chose the governed set: every Capability/Decision/Gate PLUS any
    # non-mirror side-effecting Task (a verb-named action fn like exec/run that nothing else
    # governs). Score over exactly those action_maps so the rubric matches the inventory the
    # CLI and receipt report — one definition of "governed", never a self-contradiction.
    action_maps = list(doc.action_maps)
    total_governed = len(action_maps)

    # ── coverage: governed actions with >=1 ASSERTED control ──────────────────
    asserted_covered = sum(1 for am in action_maps if _has_asserted(am))
    coverage = round(100 * asserted_covered / total_governed) if total_governed else 0

    # ── rigor: of governed actions that mapped to ANYTHING, how many are asserted ─
    any_mapped = sum(1 for am in action_maps if _has_any_mapping(am))
    rigor = round(100 * asserted_covered / any_mapped) if any_mapped else 0

    # ── breadth: distinct ASSERTED frameworks present (doc.frameworks already filters) ─
    fw_count = len([f for f in doc.frameworks if f in ALLOWED_FRAMEWORKS])
    breadth = round(100 * min(fw_count, _BREADTH_CEILING) / _BREADTH_CEILING)

    # ── structure: typed + connected graph (edges present, all endpoints resolve) ─
    structure = _structure_score(doc, nodes)

    subscores = {"coverage": coverage, "rigor": rigor,
                 "breadth": breadth, "structure": structure}
    total = round(sum(_WEIGHTS[k] * subscores[k] for k in _WEIGHTS))
    total = max(0, min(100, total))
    tier = _tier_for(total)

    ungoverned = total_governed - any_mapped
    heuristic_only = any_mapped - asserted_covered
    rationale = _rationale(tier, total, total_governed, asserted_covered,
                           heuristic_only, ungoverned, fw_count, doc.frameworks)

    return TrustProfile(tier=tier, score=total, subscores=subscores, rationale=rationale)


def _structure_score(doc, nodes) -> int:
    """0..100. A connected, fully-typed graph scores high; a bag of nodes scores low.

    Components (each contributes a fixed share, so the math is auditable):
      40  every node carries a recognized type (the validator also enforces this hard)
      40  the graph has at least one edge AND every edge endpoint resolves to a node
      20  more than one node exists (a single-node ontology is barely a graph)
    """
    if not nodes:
        return 0
    node_ids = {n.id for n in nodes}
    from .schema import NODE_TYPES  # local import keeps module import-time minimal
    typed = all(n.type in NODE_TYPES for n in nodes)
    edges = list(doc.edges)
    connected = bool(edges) and all(e.src in node_ids and e.dst in node_ids for e in edges)
    s = 0
    if typed:
        s += 40
    if connected:
        s += 40
    if len(nodes) > 1:
        s += 20
    return s


def _rationale(tier, total, governed, asserted, heuristic_only, ungoverned,
               fw_count, frameworks) -> tuple:
    """Plain-ASCII lines explaining the score. Reused in the badge title attr + receipt."""
    lines = [f"Trust Profile: {tier} ({total}/100)."]
    if governed == 0:
        lines.append("No governed actions detected (no tool, decision, gate, or "
                     "side-effecting action) -- nothing to govern means nothing proven.")
        return tuple(lines)
    lines.append(f"{asserted}/{governed} high-risk actions covered by an asserted control.")
    if heuristic_only:
        lines.append(f"{heuristic_only} action(s) backed only by a heuristic mapping -- "
                     "confirm against published control text.")
    if ungoverned:
        lines.append(f"{ungoverned} action(s) UNGOVERNED -- no control matched (review these first).")
    if fw_count:
        fw_list = ", ".join(f for f in frameworks if f in ALLOWED_FRAMEWORKS)
        lines.append(f"Touches {fw_count} asserted framework(s): {fw_list}.")
    return tuple(lines)
