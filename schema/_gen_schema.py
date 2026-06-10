"""_gen_schema.py — emit the published Agent Ontology standard FROM the code.

The standard is generated, never hand-typed, so it can never drift from the implementation
(pol.must_do.143). Run from the repo root:

    PYTHONPATH=. python schema/_gen_schema.py

Writes, into schema/:
  agent-ontology-v0.1.schema.json   JSON Schema for an ontology doc + trust profile + receipt
  crosswalk-v0.1.json               the canonical deny-reasons -> framework controls (the core)
  frameworks-v0.1.json              allowed frameworks, trust tiers, scoring weights
"""
import json

from openagentontology import crosswalk as C
from openagentontology import schema as S
from openagentontology import trust_profile as TP

CANON_URL = "https://cyberwarriornetwork.com/agent-ontology/schema/v0.1"

# The 13 canonical edge relations (Universal Agentic Ontology). Documented vocabulary; the
# crosswalk emits a subset (HAS_CAPABILITY / GATED_BY / EXECUTES / ...).
EDGE_TYPES = [
    "OWNS", "DELEGATES_TO", "HAS_CAPABILITY", "USES", "EXECUTES", "PART_OF",
    "PRODUCES", "MAKES", "GOVERNED_BY", "SUPPORTED_BY", "ENFORCES", "GATED_BY", "OPERATES_ON",
]
INGEST_KINDS = ["rego", "openapi", "mcp", "speckit", "agentdef", "python", "directory", "text"]
CONFIDENCE = ["asserted", "inferred", "advisory", "ambiguous"]
MATCHED_VIA = ["asserted_table", "heuristic", "none"]


def ontology_schema() -> dict:
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "$id": f"{CANON_URL}/agent-ontology.schema.json",
        "title": f"Agent Ontology v{S.VERSION}",
        "description": "A typed, signed map of every action an AI agent can take and the "
                       "governance control that answers for each one.",
        "type": "object",
        "required": ["source", "source_kind", "nodes", "edges", "action_maps"],
        "properties": {
            "source": {"type": "string"},
            "source_kind": {"type": "string", "enum": INGEST_KINDS},
            "nodes": {"type": "array", "items": {"$ref": "#/$defs/node"}},
            "edges": {"type": "array", "items": {"$ref": "#/$defs/edge"}},
            "action_maps": {"type": "array", "items": {"$ref": "#/$defs/action_map"}},
            "frameworks": {"type": "array",
                           "items": {"type": "string", "enum": list(C.ALLOWED_FRAMEWORKS)}},
            "note": {"type": "string"},
        },
        "$defs": {
            "node": {
                "type": "object",
                "required": ["id", "type", "name"],
                "properties": {
                    "id": {"type": "string"},
                    "type": {"type": "string", "enum": list(S.NODE_TYPES)},
                    "name": {"type": "string"},
                    "props": {"type": "object"},
                },
            },
            "edge": {
                "type": "object",
                "required": ["src", "rel", "dst"],
                "properties": {
                    "src": {"type": "string"},
                    "rel": {"type": "string", "enum": EDGE_TYPES},
                    "dst": {"type": "string"},
                },
            },
            "mapping": {
                "type": "object",
                "required": ["fw", "id", "name", "confidence"],
                "properties": {
                    "fw": {"type": "string", "enum": list(C.ALLOWED_FRAMEWORKS)},
                    "id": {"type": "string", "description": "a real control id; never fabricated"},
                    "name": {"type": "string"},
                    "confidence": {"type": "string", "enum": CONFIDENCE},
                    "provenance": {"type": "string"},
                },
            },
            "action_map": {
                "type": "object",
                "required": ["subject_id", "label", "matched_via", "mappings"],
                "properties": {
                    "subject_id": {"type": "string"},
                    "label": {"type": "string"},
                    "matched_via": {"type": "string", "enum": MATCHED_VIA},
                    "mappings": {"type": "array", "items": {"$ref": "#/$defs/mapping"}},
                },
            },
            "trust_profile": {
                "type": "object",
                "required": ["tier", "score", "subscores"],
                "properties": {
                    "tier": {"type": "string", "enum": list(S.TIERS)},
                    "score": {"type": "integer", "minimum": 0, "maximum": 100},
                    "subscores": {
                        "type": "object",
                        "properties": {k: {"type": "integer"} for k in TP._WEIGHTS},
                    },
                    "rationale": {"type": "array", "items": {"type": "string"}},
                },
            },
            "receipt": {
                "type": "object",
                "description": "Ed25519 cert-only receipt; verify offline (see receipt.verify_receipt).",
                "required": ["atom_id", "type", "evidence_hash", "signed_at", "evidence"],
                "properties": {
                    "atom_id": {"type": "string"},
                    "type": {"const": "AgentGovernanceReceipt"},
                    "decision": {"type": "string"},
                    "evidence_hash": {"type": "string", "description": "sha256 over canonical(evidence)"},
                    "signed_at": {"type": "string", "format": "date-time"},
                    "alg": {"type": "string", "enum": ["Ed25519", "none"]},
                    "signature_b64": {"type": "string"},
                    "verify_pubkey_b64": {"type": "string"},
                    "signed": {"type": "boolean"},
                    "evidence": {"type": "object"},
                },
            },
        },
    }


def crosswalk_json() -> dict:
    table = {}
    for reason, mappings in C.ASSERTED_TABLE.items():
        table[reason] = [{"framework": m.fw, "id": m.id, "name": m.name,
                          "confidence": m.confidence, "basis": m.basis} for m in mappings]
    heuristics = [{"pattern": p.pattern, "reason": reason, "strength": strength}
                  for p, reason, strength in C.HEURISTICS]
    return {
        "version": S.VERSION,
        "$schema_url": f"{CANON_URL}/crosswalk.json",
        "description": "Canonical deny-reasons mapped 1:1 to well-established framework controls. "
                       "A source-named reason here is ASSERTED (auditable). The heuristics map a "
                       "verb-named action to a reason when none is declared (INFERRED).",
        "canonical_reasons": list(C.ASSERTED_TABLE.keys()),
        "asserted_table": table,
        "heuristics": heuristics,
        "confirm_note": C.CONFIRM_NOTE,
    }


def frameworks_json() -> dict:
    return {
        "version": S.VERSION,
        "$schema_url": f"{CANON_URL}/frameworks.json",
        "allowed_frameworks": list(C.ALLOWED_FRAMEWORKS),
        "trust_tiers": [{"tier": name, "floor": floor} for name, floor in TP._BANDS],
        "scoring_weights": dict(TP._WEIGHTS),
        "breadth_ceiling": TP._BREADTH_CEILING,
        "node_types": list(S.NODE_TYPES),
        "edge_types": EDGE_TYPES,
        "ingest_kinds": INGEST_KINDS,
    }


def main():
    out = {
        f"schema/agent-ontology-v{S.VERSION}.schema.json": ontology_schema(),
        f"schema/crosswalk-v{S.VERSION}.json": crosswalk_json(),
        f"schema/frameworks-v{S.VERSION}.json": frameworks_json(),
    }
    for path, obj in out.items():
        with open(path, "w", encoding="ascii") as f:
            json.dump(obj, f, indent=2, sort_keys=True, ensure_ascii=True)
            f.write("\n")
        print("wrote", path)
    cj = crosswalk_json()
    print(f"canonical reasons: {len(cj['canonical_reasons'])}  | "
          f"frameworks: {len(C.ALLOWED_FRAMEWORKS)}  | node types: {len(S.NODE_TYPES)}  | "
          f"edge types: {len(EDGE_TYPES)}")


if __name__ == "__main__":
    main()
