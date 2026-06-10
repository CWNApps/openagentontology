"""fde.py -- CWN AgentFDE: the autonomous Forward Deployed Engineer.

Point it at any agent, repo, workflow, or policy set and it runs the whole FDE loop a human
would -- minus the three-week engagement:

    scan  ->  triage the gaps  ->  generate the governance (agentdef + Rego)  ->
    re-score to prove the tier jump  ->  notarize  ->  hand off an onboarding report.

    PYTHONPATH=. python -m openagentontology.fde <target> [--out DIR] [--apply] [--json]

It never executes the target's code (AST / text only), makes no network call, and signs the
remediated state with an offline-verifiable receipt. Honest by construction: an action the verb
crosswalk recognizes is remediated at high confidence; an action it doesn't is PROPOSED and
clearly flagged for a human -- the report never claims a control it can't source.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .crosswalk import ASSERTED_TABLE, HEURISTICS
from .pipeline import run_pipeline
from .receipt import mint_receipt
from .schema import ActionMap, OntologyDoc
from .trust_profile import score

# Dangerous verbs the strong-verb heuristic deliberately doesn't claim (no clean 1:1 control),
# but that an FDE should still propose a sane default for so onboarding isn't a blank page.
# Every one of these is surfaced as PROPOSED -- a human confirms before it counts as asserted.
_PROPOSED_FOR_UNMATCHED = {
    "exec": "approval_required",
    "eval": "approval_required",
    "spawn": "approval_required",
    "system": "approval_required",
    "kill": "high_blast_needs_named_approver",
    "sudo": "out_of_scope_domain",
    "root": "out_of_scope_domain",
    "admin": "out_of_scope_domain",
}


@dataclass
class Remediation:
    subject_id: str
    label: str
    reason: str
    confidence: str            # "auto" (verb-inferred) | "proposed" (needs a human nod)


@dataclass
class FDEReport:
    target: str
    before_tier: str
    before_score: int
    after_tier: str
    after_score: int
    n_actions: int
    n_asserted_before: int
    remediations: list = field(default_factory=list)   # list[Remediation]
    still_open: list = field(default_factory=list)      # subject_ids no reason was found for
    frameworks_after: list = field(default_factory=list)
    receipt_atom_id: str = ""


def _verb_reason(label: str) -> str | None:
    """The canonical reason the strong-verb heuristic would infer for a label (or None)."""
    for pattern, reason, strength in HEURISTICS:
        if strength == "strong" and pattern.search(label or ""):
            return reason
    return None


def _proposed_reason(label: str) -> str | None:
    low = (label or "").lower()
    for verb, reason in _PROPOSED_FOR_UNMATCHED.items():
        if verb in low:
            return reason
    return None


def triage(doc) -> tuple[list, list, int]:
    """Split the crosswalked actions into remediations (with a reason) and still-open ids.

    Returns (remediations, still_open_subject_ids, n_already_asserted)."""
    remediations, still_open, asserted = [], [], 0
    for am in doc.action_maps:
        if am.matched_via == "asserted_table":
            asserted += 1
            continue
        label = am.label or am.subject_id
        if am.matched_via == "heuristic":
            reason = _verb_reason(label)
            if reason:
                remediations.append(Remediation(am.subject_id, label, reason, "auto"))
                continue
        # ungoverned, or heuristic with no recoverable strong verb -> propose, else leave open
        reason = _proposed_reason(label)
        if reason:
            remediations.append(Remediation(am.subject_id, label, reason, "proposed"))
        else:
            still_open.append(am.subject_id)
    return remediations, still_open, asserted


def _remediated_doc(doc, remediations) -> OntologyDoc:
    """Build the ontology as it WOULD score once each remediation declares its reason.

    This is not a guess: it substitutes exactly the ASSERTED mappings the crosswalk emits for a
    source-named reason, so the projected tier is the real post-remediation score."""
    by_id = {r.subject_id: r.reason for r in remediations}
    new_ams = []
    for am in doc.action_maps:
        if am.subject_id in by_id:
            new_ams.append(ActionMap(subject_id=am.subject_id, label=am.label,
                                     mappings=tuple(ASSERTED_TABLE[by_id[am.subject_id]]),
                                     matched_via="asserted_table"))
        else:
            new_ams.append(am)
    frameworks = []
    for am in new_ams:
        for m in am.mappings:
            if m.confidence == "asserted" and m.fw not in frameworks:
                frameworks.append(m.fw)
    return OntologyDoc(source=doc.source, source_kind=doc.source_kind, nodes=list(doc.nodes),
                       edges=list(doc.edges), action_maps=new_ams, frameworks=frameworks,
                       note=doc.note)


def generate_agentdef(agent_name: str, remediations) -> str:
    """The agentdef the user drops next to their agent so the scan reads ASSERTED, not inferred."""
    lines = [
        f"# Governance declaration generated by CWN AgentFDE for `{agent_name}`.",
        "# Each capability binds an action to a canonical reason in the Agent Ontology crosswalk.",
        "# 'auto' = the verb crosswalk recognized it (high confidence). 'proposed' = AgentFDE's",
        "# best default for an action the crosswalk could not name -- a human must confirm it.",
        f"name: {agent_name}",
        f"agent: {agent_name}",   # marks this as an agentdef so the scanner reads `reason:`
        "owner: governed-by-cwn-agentfde",
        "capabilities:",
    ]
    for r in remediations:
        tag = "" if r.confidence == "auto" else "   # PROPOSED -- confirm this reason"
        lines.append(f"  - id: {r.subject_id}")
        lines.append(f"    name: {r.label}")
        lines.append(f"    action: {r.label}")
        lines.append(f"    reason: {r.reason}{tag}")
    return "\n".join(lines) + "\n"


def generate_rego(agent_name: str, remediations) -> str:
    """A fail-closed Rego stub whose deny keys are the canonical reasons -> ASSERTED on re-scan."""
    pkg = "cwn." + "".join(c if c.isalnum() else "_" for c in agent_name.lower()).strip("_")
    reasons = []
    for r in remediations:
        if r.reason not in reasons:
            reasons.append(r.reason)
    out = [
        f"# Fail-closed governance firewall generated by CWN AgentFDE for `{agent_name}`.",
        "# Wire this into your runtime: deny unless the named canonical condition holds.",
        f"package {pkg}",
        "",
        "default allow := false",
        "",
        "allow if {",
        "\tnot deny[_]",
        "}",
        "",
    ]
    for reason in reasons:
        out.append(f'# TODO(human): encode the real predicate for "{reason}".')
        out.append(f'deny contains "{reason}" if {{')
        out.append(f'\tinput.reason == "{reason}"')
        out.append("}")
        out.append("")
    return "\n".join(out)


def onboard(target: str, *, out_dir: str | None = None, apply: bool = False,
            make_receipt: bool = True) -> FDEReport:
    """Run the full FDE loop against a target. Returns an FDEReport; writes artifacts to out_dir."""
    result = run_pipeline(target, make_receipt=False)
    doc = result.ontology
    agent_node = next((n for n in doc.nodes if n.type == "Agent"), None)
    agent_name = agent_node.name if agent_node else Path(target).name

    remediations, still_open, asserted_before = triage(doc)
    after = _remediated_doc(doc, remediations)
    after_profile = score(after)

    report = FDEReport(
        target=target,
        before_tier=result.profile.tier, before_score=result.profile.score,
        after_tier=after_profile.tier, after_score=after_profile.score,
        n_actions=len(doc.action_maps), n_asserted_before=asserted_before,
        remediations=remediations, still_open=still_open,
        frameworks_after=list(after.frameworks),
    )

    out = Path(out_dir) if out_dir else (Path(target) / ".cwn-fde")
    out.mkdir(parents=True, exist_ok=True)
    (out / "governance.agent.yaml").write_text(generate_agentdef(agent_name, remediations), encoding="ascii")
    (out / "governance.rego").write_text(generate_rego(agent_name, remediations), encoding="ascii")
    (out / "ONBOARDING.md").write_text(render_report(report), encoding="ascii")
    if make_receipt:
        rec = mint_receipt(after, decision="FDE_REMEDIATION_PROJECTED")
        (out / "receipt.json").write_text(json.dumps(rec, indent=2, sort_keys=True), encoding="ascii")
        report.receipt_atom_id = rec.get("atom_id", "")

    if apply:
        # drop the declaration next to the agent so the very next plain scan reads the new tier
        (Path(target) / "governance.agent.yaml").write_text(
            generate_agentdef(agent_name, remediations), encoding="ascii")
    return report


def render_report(r: FDEReport) -> str:
    auto = [x for x in r.remediations if x.confidence == "auto"]
    proposed = [x for x in r.remediations if x.confidence == "proposed"]
    delta = r.after_score - r.before_score
    lines = [
        f"# CWN AgentFDE -- Onboarding Report",
        "",
        f"**Target:** `{r.target}`",
        "",
        f"## Verdict",
        "",
        f"| | Tier | Score |",
        f"|---|---|---|",
        f"| **Now** | {r.before_tier} | {r.before_score}/100 |",
        f"| **After wiring the generated governance** | {r.after_tier} | {r.after_score}/100  (+{delta}) |",
        "",
        f"Scanned {r.n_actions} governed actions; {r.n_asserted_before} were already asserted. "
        f"AgentFDE wrote a declaration that promotes {len(auto)} more to asserted automatically"
        + (f", and proposes a reason for {len(proposed)} that need your confirmation." if proposed else "."),
        "",
        "## Auto-remediated (the verb crosswalk recognized these)",
        "",
        "| action | declare reason |",
        "|---|---|",
    ]
    lines += [f"| `{x.label}` | `{x.reason}` |" for x in auto] or ["| _(none)_ | |"]
    if proposed:
        lines += ["", "## Proposed -- confirm before relying on these", "",
                  "| action | proposed reason |", "|---|---|"]
        lines += [f"| `{x.label}` | `{x.reason}` |" for x in proposed]
    if r.still_open:
        lines += ["", "## Still open -- pick a canonical reason for each", "",
                  "AgentFDE found no defensible default. Choose one of the 10 canonical reasons "
                  "(see `schema/crosswalk-v0.1.0.json`) or mark the action out of scope:", ""]
        lines += [f"- `{sid}`" for sid in r.still_open]
    lines += [
        "",
        "## Files generated",
        "",
        "- `governance.agent.yaml` -- drop this next to your agent and re-scan; the actions above read **asserted**.",
        "- `governance.rego` -- a fail-closed policy stub; encode each predicate and wire it into your runtime.",
        "- `receipt.json` -- the signed, offline-verifiable receipt of the projected state"
        + (f" (`{r.receipt_atom_id}`)." if r.receipt_atom_id else "."),
        "",
        "## Do this next",
        "",
        "1. Review `governance.agent.yaml` -- confirm every **PROPOSED** reason.",
        "2. Re-scan: `python -m openagentontology <target>` -- confirm the tier moved.",
        "3. Encode the predicates in `governance.rego` and wire it into your agent's decision path.",
        "",
        "*Generated by CWN AgentFDE. No Receipt. No Trust.*",
    ]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="python -m openagentontology.fde",
        description="CWN AgentFDE -- autonomously scan an agent and generate its governance.")
    p.add_argument("target", help="agent / repo / workflow / policy directory to onboard")
    p.add_argument("--out", default=None, help="where to write artifacts (default <target>/.cwn-fde)")
    p.add_argument("--apply", action="store_true",
                   help="also drop governance.agent.yaml next to the target so the next scan reflects it")
    p.add_argument("--json", action="store_true", dest="as_json", help="emit the report as JSON")
    args = p.parse_args(argv)

    if not Path(args.target).exists():
        print(f"error: target does not exist: {args.target}", file=sys.stderr)
        return 2
    r = onboard(args.target, out_dir=args.out, apply=args.apply)

    if args.as_json:
        from dataclasses import asdict
        json.dump(asdict(r), sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(render_report(r))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
