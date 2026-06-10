"""pipeline.py — the one composition facade: a path in, a governed result out.

run_pipeline(path, *, make_receipt=True, key_path=None) wires the stages the rest of the
package owns, in order, with NO new business logic of its own:

    ingest(path)        -> IngestResult            (TEXT/AST only; never executes the source)
    generate(ing)       -> OntologyDoc             (carries nodes, drops dangling edges, crosswalk)
    validate(doc)       -> (ok, [Finding])         (fail-closed rigor gate)
    trust_profile.score(doc) -> TrustProfile       (deterministic tier + score)
    receipt.mint_receipt(doc) -> dict              (Ed25519 cert-only, soft-degrades to unsigned)
    badge.render_badge(...)  -> str                (standalone SVG, honest about low tiers)

The result is a small frozen dataclass so a caller (CLI, the GitHub Action, a test) reads
one object. compact_refs from the crosswalk feed the badge chips so the badge only ever
shows asserted, citable controls.

Pure orchestration. No network. The receipt is the only stage that touches disk (its signing
key); make_receipt=False skips it entirely for a hermetic, offline-only run.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import badge, receipt, trust_profile
from .crosswalk import compact_refs
from .generate import generate
from .ingest import ingest
from .schema import OntologyDoc, TrustProfile
from .validate import validate


@dataclass(frozen=True)
class PipelineResult:
    """Everything one governance scan produces. JSON-safe via to_dict()."""
    source: str
    ontology: OntologyDoc
    ok: bool                       # validation passed (no error-level findings)
    findings: list                 # list[Finding]
    profile: TrustProfile
    badge_svg: str
    refs: list                     # compact asserted control tokens (badge chips)
    receipt: dict = field(default_factory=dict)  # {} when make_receipt=False

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "ok": self.ok,
            "profile": self.profile.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "refs": list(self.refs),
            "ontology": self.ontology.to_dict(),
            "receipt": self.receipt,
        }

    # convenience accessors the CLI / Action read a lot
    @property
    def tier(self) -> str:
        return self.profile.tier

    @property
    def score(self) -> int:
        return self.profile.score

    def errors(self) -> list:
        return [f for f in self.findings if f.level == "error"]

    def warnings(self) -> list:
        return [f for f in self.findings if f.level == "warn"]

    def ungoverned(self) -> list:
        """Action subject_ids the validator flagged as ungoverned (W_UNGOVERNED)."""
        return [f.msg for f in self.findings if f.code == "W_UNGOVERNED"]


def _collect_refs(doc: OntologyDoc, limit: int = 6) -> list:
    """Distinct asserted control tokens across the whole doc, for the badge chip row."""
    out = []
    for am in doc.action_maps:
        for tok in compact_refs(am, asserted_only=True, limit=3):
            if tok not in out:
                out.append(tok)
            if len(out) >= limit:
                return out
    return out


def run_pipeline(path, *, make_receipt: bool = True, key_path: str | None = None) -> PipelineResult:
    """Run the full governance pipeline on a file or directory.

    make_receipt  mint an Ed25519 cert-only receipt over the ontology (default True). When
                  False, .receipt is {} and no disk/key access happens (hermetic offline run).
    key_path      optional override of the signing-key location (passed to receipt.mint_receipt).
    """
    ing = ingest(path)
    doc = generate(ing)
    ok, findings = validate(doc)
    profile = trust_profile.score(doc)
    refs = _collect_refs(doc)

    title = f"OpenAgentOntology -- {profile.tier} {profile.score}/100 -- {doc.source}"
    badge_svg = badge.render_badge(profile.tier, profile.score, refs=refs, title=title)

    rcpt = {}
    if make_receipt:
        # the receipt commits to the validated ontology + the scored tier (decision string).
        rcpt = receipt.mint_receipt(doc, decision=f"GOVERNED:{profile.tier}", key_path=key_path)

    return PipelineResult(
        source=doc.source, ontology=doc, ok=ok, findings=findings,
        profile=profile, badge_svg=badge_svg, refs=refs, receipt=rcpt)
