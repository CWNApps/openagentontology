"""graph_client.py -- OPT-IN client for the hosted CWN Graph Model Service (OAO-GMS).

The OSS scanner is deterministic and fully offline; that is its trust anchor and nothing
here changes it. This module is the one explicitly network-touching, explicitly optional
bridge: given an action (or a whole scan), the hosted service resolves it through a live
governance knowledge graph -- curated MITRE ATT&CK / NICE work-role structure plus current
CVE signals of the same risk class -- and returns candidate canonical reasons and controls
with a signed semantic resolution receipt.

Honesty contract (same as the rest of the standard):
  - Everything the graph returns is GRAPH_INFERRED. It can NEVER appear as ASSERTED in an
    ontology; only a source-declared canonical reason (or a human-confirmed governance
    record) asserts. This client does not write into ontologies at all -- it returns the
    server's evidence for a human to act on.
  - No call happens unless you construct the client and call it. Nothing in the pipeline
    imports this module.

Usage:
    from openagentontology.graph_client import GraphModelClient
    client = GraphModelClient(api_key="...")           # endpoint defaults to the CWN service
    path = client.resolve_action("exec")               # one action
    packet = client.resolve_scan(ontology_doc_dict)    # a whole scan's evidence packet

Committed example output (so you can see the shape without an API key):
    docs/scans/open-interpreter/graph_resolutions.json
"""
from __future__ import annotations

import json
import urllib.request

_DEFAULT_ENDPOINT = "https://cwn-trust-gate.onrender.com/api/v1/oao"
_TIMEOUT = 30


class GraphModelClient:
    """Minimal stdlib-only client. No dependency added to the package."""

    def __init__(self, api_key: str, endpoint: str = _DEFAULT_ENDPOINT):
        if not api_key:
            raise ValueError("GraphModelClient requires an API key (the hosted layer is authenticated)")
        self._endpoint = endpoint.rstrip("/")
        self._key = api_key

    def _post(self, path: str, payload: dict) -> dict:
        req = urllib.request.Request(
            f"{self._endpoint}{path}",
            data=json.dumps(payload).encode("ascii"),
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {self._key}"},
            method="POST")
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # nosec B310 - https endpoint, caller-supplied key
            return json.loads(resp.read().decode("utf-8"))

    def resolve_action(self, label: str, *, technique: str = "", risk_domain: str = "") -> dict:
        """Resolve ONE action label. Returns a GovernancePath dict: technique anchor, tactics,
        NICE work-role categories, live CVE signals of the same risk class, recommended
        canonical reasons/controls, and a GRAPH_INFERRED confidence -- never ASSERTED."""
        return self._post("/resolve", {"label": label, "technique": technique,
                                       "risk_domain": risk_domain})

    def resolve_scan(self, ontology: dict, *, source_name: str = "") -> dict:
        """Resolve every action in an OAO ontology document. Returns {evidence, receipt}
        where receipt is the service's signed semantic resolution receipt (hybrid
        Ed25519 + post-quantum legs) embedding the graph snapshot fingerprint."""
        return self._post("/resolve-scan", {"ontology": ontology, "source_name": source_name})
