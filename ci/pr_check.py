"""ci/pr_check.py — the PR governance gate the GitHub Action runs.

Runs OpenAgentOntology on the PR HEAD (and, when available, the BASE) and decides whether the
check passes. It is the real logic behind .github/workflows/agent-governance.yml so the gate
is testable, not buried in fragile YAML bash.

What it does (all from the tool's own --json payload -- no new governance logic):
  1. Scan HEAD. If validation failed closed (a fabricated/unsourced control or a structural
     break), FAIL -- pol.must_do.143 voids trust.
  2. Flag every NEW ungoverned HIGH-RISK action (a side-effecting verb -- pay/wire/export/
     delete/deploy/deny/... -- whose ActionMap.matched_via == 'none'). New = present on HEAD
     and not on BASE (by subject_id). With no BASE, all current ones are reported.
  3. Flag every HIGH-RISK action that lost its EU AI Act Article 14 (human-oversight) coverage:
     a human-oversight-relevant action (deny/approve/adverse/wire/deploy/refund/...) that is
     NOT covered by an asserted EU AI Act Art 14 mapping on HEAD. New gaps fail the check.
  4. FAIL if the tier DROPPED versus BASE (SOVEREIGN > HARDENED > DEVELOPING > UNGOVERNED).
  5. Emit a Markdown report (the Action posts it as a PR comment + step summary) and set
     GitHub step outputs (tier/score/passed). Exit 0 pass / 1 fail / 2 usage.

Pure stdlib + the package. No network. Reads two pre-rendered JSON payloads (HEAD required,
BASE optional) so the workflow controls the git checkouts, not this script.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

# side-effecting / high-stakes verbs. An UNGOVERNED action carrying one of these is the exact
# risk the badge exists to catch. ASCII, lowercase, matched against the action label/id.
_HIGH_RISK = re.compile(
    r"(?<![a-z])(pay|payment|wire|transfer|remit|disburse|refund|invoice|"
    r"export|egress|exfil|upload|send|transmit|leak|"
    r"delete|drop|purge|wipe|destroy|truncate|"
    r"deploy|release|ship|rollout|provision|migrate|reconfigure|"
    r"approve|deny|reject|decline|cancel|adverse|terminate|suspend|"
    r"escalate|elevate|impersonate)(?![a-z])", re.I)

# actions for which EU AI Act Article 14 (human oversight) is the relevant obligation.
_OVERSIGHT = re.compile(
    r"(?<![a-z])(deny|reject|decline|cancel|adverse|approve|terminate|suspend|"
    r"wire|transfer|pay|payment|refund|deploy|release)(?![a-z])", re.I)

_TIER_RANK = {"SOVEREIGN": 0, "HARDENED": 1, "DEVELOPING": 2, "UNGOVERNED": 3}


def _load(path: str | None) -> dict | None:
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _action_text(am: dict) -> str:
    return f"{am.get('subject_id', '')} {am.get('label', '')}"


def _is_ungoverned(am: dict) -> bool:
    return am.get("matched_via") == "none" or not am.get("mappings")


def _action_maps(payload: dict) -> list:
    return (payload.get("ontology", {}) or {}).get("action_maps", []) or []


def _ungoverned_high_risk(payload: dict) -> dict:
    """subject_id -> label for every ungoverned high-risk action in a payload."""
    out = {}
    for am in _action_maps(payload):
        if _is_ungoverned(am) and _HIGH_RISK.search(_action_text(am)):
            out[am.get("subject_id", "?")] = am.get("label", am.get("subject_id", "?"))
    return out


def _art14_gaps(payload: dict) -> dict:
    """subject_id -> label for human-oversight-relevant actions that are ENTIRELY ungoverned.

    Honest scope (pol.must_do.143): an action whose verb implies a human-oversight obligation
    (deny / approve / wire / deploy / ...) but which mapped to NO control at all is a real EU
    AI Act Article 14 gap. An action that mapped to an INFERRED oversight control is NOT a gap
    here -- it is governed (confidence-tagged), and flagging it as 'failing Art 14' would be
    slop. The score's `rigor` axis already accounts for inferred-vs-asserted.
    """
    out = {}
    for am in _action_maps(payload):
        if _OVERSIGHT.search(_action_text(am)) and _is_ungoverned(am):
            out[am.get("subject_id", "?")] = am.get("label", am.get("subject_id", "?"))
    return out


def evaluate(head: dict, base: dict | None) -> dict:
    """Pure decision function. Returns the verdict dict the report + exit code read."""
    reasons_to_fail = []

    head_tier = head.get("tier", "UNGOVERNED")
    head_score = head.get("score", 0)
    head_ok = head.get("ok", False)

    # 1) fail-closed validation on HEAD voids trust.
    if not head_ok:
        err_codes = sorted({f["code"] for f in head.get("findings", []) if f.get("level") == "error"})
        reasons_to_fail.append(f"HEAD validation FAILED closed (pol.must_do.143): {', '.join(err_codes)}")

    # 2) NEW ungoverned high-risk actions.
    head_ung = _ungoverned_high_risk(head)
    base_ung = _ungoverned_high_risk(base) if base else {}
    new_ung = {k: v for k, v in head_ung.items() if k not in base_ung}
    if new_ung:
        reasons_to_fail.append(f"{len(new_ung)} NEW ungoverned high-risk action(s)")

    # 3) NEW EU AI Act Art 14 gaps.
    head_gaps = _art14_gaps(head)
    base_gaps = _art14_gaps(base) if base else {}
    new_gaps = {k: v for k, v in head_gaps.items() if k not in base_gaps}
    if new_gaps:
        reasons_to_fail.append(f"{len(new_gaps)} NEW EU AI Act Article 14 oversight gap(s)")

    # 4) tier drop vs base.
    tier_dropped = False
    base_tier = None
    if base:
        base_tier = base.get("tier", "UNGOVERNED")
        if _TIER_RANK.get(head_tier, 3) > _TIER_RANK.get(base_tier, 3):
            tier_dropped = True
            reasons_to_fail.append(f"Trust tier DROPPED: {base_tier} -> {head_tier}")

    return {
        "passed": not reasons_to_fail,
        "head_tier": head_tier, "head_score": head_score, "head_ok": head_ok,
        "base_tier": base_tier, "tier_dropped": tier_dropped,
        "new_ungoverned": new_ung, "new_art14_gaps": new_gaps,
        "all_ungoverned": head_ung, "fail_reasons": reasons_to_fail,
    }


def render_report(v: dict, head: dict) -> str:
    """The Markdown comment the Action posts. Honest, scannable, links the confirm-note."""
    icon = "PASS" if v["passed"] else "FAIL"
    lines = [
        "## OpenAgentOntology -- Agent Governance Check",
        "",
        f"**Result: {icon}**",
        "",
        f"| Trust Profile | {v['head_tier']} {v['head_score']}/100 |",
        "|---|---|",
    ]
    if v["base_tier"]:
        delta = "no change"
        if v["tier_dropped"]:
            delta = f"DROPPED from {v['base_tier']}"
        elif v["base_tier"] != v["head_tier"]:
            delta = f"changed from {v['base_tier']}"
        lines.append(f"| vs base branch | {delta} |")
    sub = (head.get("profile", {}) or {}).get("subscores", {})
    if sub:
        lines.append("| subscores | " + ", ".join(f"{k}={sub[k]}" for k in sorted(sub)) + " |")
    od = head.get("ontology", {}) or {}
    lines.append(f"| inventory | {len(od.get('nodes', []))} nodes, "
                 f"{len(od.get('action_maps', []))} governed actions |")
    lines.append("")

    if v["fail_reasons"]:
        lines.append("### Why this check failed")
        for r in v["fail_reasons"]:
            lines.append(f"- {r}")
        lines.append("")

    if v["new_ungoverned"]:
        lines.append("### NEW ungoverned high-risk actions (govern these before merge)")
        for sid, label in sorted(v["new_ungoverned"].items()):
            lines.append(f"- `{sid}` -- {label}")
        lines.append("")

    if v["new_art14_gaps"]:
        lines.append("### NEW EU AI Act Article 14 (human oversight) gaps")
        for sid, label in sorted(v["new_art14_gaps"].items()):
            lines.append(f"- `{sid}` -- {label} (no asserted human-oversight control)")
        lines.append("")

    rationale = (head.get("profile", {}) or {}).get("rationale", [])
    if rationale:
        lines.append("### Rationale")
        for line in rationale:
            lines.append(f"- {line}")
        lines.append("")

    note = head.get("confirm_note") or od.get("note", "")
    if note:
        lines.append(f"> {note}")
    lines.append("")
    lines.append("<sub>Generated by OpenAgentOntology (Apache-2.0). This emits a LOCAL, "
                 "self-signed receipt; cross-org verification is CWN's hosted notary.</sub>")
    return "\n".join(lines)


def _set_outputs(v: dict) -> None:
    """Write GitHub Actions step outputs (tier/score/passed) when running in CI."""
    out = os.getenv("GITHUB_OUTPUT")
    if not out:
        return
    try:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(f"tier={v['head_tier']}\n")
            fh.write(f"score={v['head_score']}\n")
            fh.write(f"passed={'true' if v['passed'] else 'false'}\n")
    except OSError:
        pass


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="OpenAgentOntology PR governance gate.")
    ap.add_argument("--head", required=True, help="HEAD scan JSON (python -m openagentontology --json)")
    ap.add_argument("--base", default=None, help="BASE scan JSON (optional; enables drop detection)")
    ap.add_argument("--report", default=None, help="write the Markdown report to this file")
    args = ap.parse_args(argv)

    head = _load(args.head)
    if head is None:
        print(f"error: could not read HEAD scan json: {args.head}", file=sys.stderr)
        return 2
    base = _load(args.base)

    verdict = evaluate(head, base)
    report = render_report(verdict, head)

    if args.report:
        Path(args.report).write_text(report, encoding="utf-8")
    print(report)
    _set_outputs(verdict)
    return 0 if verdict["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
