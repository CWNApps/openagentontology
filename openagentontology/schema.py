"""schema.py — the public ontology schema, DERIVED_FROM universal_agentic_ontology.yaml.

Single source of truth for SHAPES. Every other module imports its dataclasses + enums
from here and nothing else of substance. No business logic lives here beyond construction
and to_dict() serialization helpers.

The node/link/action vocabulary is a static-ingest-observable SUBSET of the Universal
Agentic Ontology (UAO) root (graph/ontology/universal_agentic_ontology.yaml). We keep the
UAO types/links a TEXT/AST parse can actually observe and drop the ones that only exist at
runtime (e.g. NOTARIZED_BY, PRODUCES an Outcome). The public schema DERIVES_FROM the UAO
root exactly as the YAML lineage rule mandates.

ASCII discipline (pol.must_do.143): every string that can flow into the signed receipt
evidence MUST stay ASCII so a browser JS verifier reproduces the Python sha256. The
dataclasses do not enforce this themselves (that is validate.py's job) but every helper
here keeps key ordering deterministic so _canon() is stable.
"""
from __future__ import annotations

from dataclasses import dataclass, field

VERSION: str = "0.1.0"

# ── enums (all str-tuples so JSON / the receipt stay ASCII and order-stable) ──

# How a fact or a mapping was derived.
#   EXTRACTED  — explicit in the source (a Rego deny key, a speckit guardrail, a tool name)
#   INFERRED   — a heuristic matched a strong, single-domain verb in the action label
#   AMBIGUOUS  — a heuristic matched only a weak / overloaded / side-effecting verb
PROVENANCE = ("EXTRACTED", "INFERRED", "AMBIGUOUS")

# Confidence on a single framework-control mapping.
#   asserted  — well-established exact-fit control (reused verbatim from CWN's canonical control map)
#   advisory  — plausible but the GRC team must confirm (reused verbatim, e.g. MITRE technique)
#   inferred  — produced by a strong heuristic verb hit (downgraded from an asserted template)
#   ambiguous — produced by a weak heuristic hit (at most an OWASP LLM06 stub, never a 53 id)
CONFIDENCE = ("asserted", "advisory", "inferred", "ambiguous")

# Trust Profile tiers — the apocalypse-drill bands the operator already locked.
TIERS = ("SOVEREIGN", "HARDENED", "DEVELOPING", "UNGOVERNED")

# Node types — the static-observable subset of the UAO `types:` block.
NODE_TYPES = (
    "Actor", "Agent", "Capability", "Tool", "Task", "Workflow",
    "Decision", "Policy", "Gate", "Evidence", "Outcome", "Resource", "Domain",
)

# Link types — the static-observable subset of the UAO `links:` block.
LINK_TYPES = (
    "OWNS", "DELEGATES_TO", "HAS_CAPABILITY", "USES", "EXECUTES", "PART_OF",
    "PRODUCES", "MAKES", "GOVERNED_BY", "SUPPORTED_BY", "ENFORCES", "GATED_BY",
    "OPERATES_ON",
)

# Action types — the UAO `actions:` names an FDE agent can exercise.
ACTION_TYPES = (
    "provision_agent", "assign_capability", "execute_task", "make_decision",
    "enforce_gate", "deploy_workflow", "derive_ontology",
)

# How a crosswalk lookup resolved.
MATCHED_VIA = ("asserted_table", "heuristic", "none")

# Finding severity. error => fail-closed (validate.ok == False).
FINDING_LEVELS = ("error", "warn")


# ── frozen value objects (shapes only) ───────────────────────────────────────
@dataclass(frozen=True)
class Node:
    """A UAO-typed entity extracted from the source. `type` MUST be in NODE_TYPES."""
    id: str
    type: str
    name: str
    props: dict = field(default_factory=dict)
    provenance: str = "EXTRACTED"

    def to_dict(self) -> dict:
        return {"id": self.id, "type": self.type, "name": self.name,
                "props": dict(self.props), "provenance": self.provenance}


@dataclass(frozen=True)
class Edge:
    """A UAO link between two node ids. `rel` MUST be in LINK_TYPES."""
    src: str
    rel: str
    dst: str
    provenance: str = "EXTRACTED"

    def to_dict(self) -> dict:
        return {"src": self.src, "rel": self.rel, "dst": self.dst,
                "provenance": self.provenance}


@dataclass(frozen=True)
class Mapping:
    """One framework-control mapping. Mirrors the canonical mapping + provenance.

    fw         — a framework name in crosswalk.ALLOWED_FRAMEWORKS (fabrication guard)
    id         — the control id, present in the ASSERTED_TABLE / HEURISTICS (never invented)
    name       — the human control name
    basis      — the sourced rationale (ASCII; inside signed evidence)
    confidence — a value in CONFIDENCE
    provenance — a value in PROVENANCE
    """
    fw: str
    id: str
    name: str
    basis: str
    confidence: str
    provenance: str

    def to_dict(self) -> dict:
        return {"fw": self.fw, "id": self.id, "name": self.name,
                "basis": self.basis, "confidence": self.confidence,
                "provenance": self.provenance}


@dataclass(frozen=True)
class ActionMap:
    """The crosswalk result for one Capability / Decision / Gate.

    matched_via in MATCHED_VIA. mappings is a tuple of Mapping (possibly empty).
    """
    subject_id: str
    label: str
    mappings: tuple = ()
    matched_via: str = "none"

    def to_dict(self) -> dict:
        return {"subject_id": self.subject_id, "label": self.label,
                "matched_via": self.matched_via,
                "mappings": [m.to_dict() for m in self.mappings]}


@dataclass(frozen=True)
class Finding:
    """A validator result. level in FINDING_LEVELS; error => fail-closed."""
    level: str
    code: str
    msg: str

    def to_dict(self) -> dict:
        return {"level": self.level, "code": self.code, "msg": self.msg}


@dataclass(frozen=True)
class TrustProfile:
    """Scored trust posture. score 0..100, tier in TIERS."""
    tier: str
    score: int
    subscores: dict = field(default_factory=dict)
    rationale: tuple = ()

    def to_dict(self) -> dict:
        return {"tier": self.tier, "score": self.score,
                "subscores": dict(self.subscores), "rationale": list(self.rationale)}


@dataclass
class OntologyDoc:
    """The assembled ontology. Mutable during generate(); read-only thereafter.

    note carries the verbatim CONFIRM_NOTE. to_dict() is deterministic (sorted) so the
    receipt evidence_hash is reproducible.
    """
    source: str
    source_kind: str
    nodes: list = field(default_factory=list)
    edges: list = field(default_factory=list)
    action_maps: list = field(default_factory=list)
    frameworks: list = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "source_kind": self.source_kind,
            "nodes": sorted((n.to_dict() for n in self.nodes), key=lambda d: d["id"]),
            "edges": sorted((e.to_dict() for e in self.edges),
                            key=lambda d: (d["src"], d["rel"], d["dst"])),
            "action_maps": sorted((a.to_dict() for a in self.action_maps),
                                  key=lambda d: d["subject_id"]),
            "frameworks": sorted(self.frameworks),
            "note": self.note,
        }
