"""openagentontology — auto-generate a governance ontology + Trust Profile + signed badge
for ANY repo / MCP server / agent / OpenAPI / Rego / workflow YAML.

Open-core boundary: this OSS produces the LOCAL ontology + badge + self-signed Ed25519
cert-only receipt. CWN's hosted notary/registry (NOT in this repo) does cross-org
verification. No network call anywhere in the core pipeline.

Run with NO install step:
    PYTHONPATH=. python -m openagentontology <path>

Public surface (stable):
    VERSION                              the package version string
    run_pipeline(path, *, make_receipt)  the one composition façade (lazy-imported)
    Node, Edge, Mapping, ActionMap,      the frozen schema dataclasses
    Finding, TrustProfile, OntologyDoc

Deps: stdlib + pyyaml + cryptography ONLY. cryptography is soft (the receipt degrades to
unsigned, clearly flagged, if it is absent) so the tool always runs.

Nothing heavy is imported eagerly: importing the package pulls in only `schema`. The
pipeline stages (ingest/generate/validate/trust_profile/receipt/badge) load on first
access to run_pipeline / PipelineResult via __getattr__, so a consumer that only wants the
dataclasses pays nothing.
"""
from __future__ import annotations

from .schema import (  # lightweight, dependency-free shapes
    VERSION,
    ActionMap,
    Edge,
    Finding,
    Mapping,
    Node,
    OntologyDoc,
    TrustProfile,
)

__version__ = VERSION

__all__ = [
    "VERSION",
    "__version__",
    "run_pipeline",
    "PipelineResult",
    "Node",
    "Edge",
    "Mapping",
    "ActionMap",
    "Finding",
    "TrustProfile",
    "OntologyDoc",
]


def __getattr__(name: str):
    """Lazily expose the pipeline façade without eagerly importing the stage chain."""
    if name in ("run_pipeline", "PipelineResult"):
        from . import pipeline  # local import: pulls the stage chain only on demand
        return getattr(pipeline, name)
    raise AttributeError(f"module 'openagentontology' has no attribute '{name}'")
