"""cli.py — the command-line face of the pipeline.

    python -m openagentontology <path> [--out DIR] [--json] [--no-receipt]

One target (a file or a directory), one governance scan. The CLI is a THIN driver: it parses
args, calls pipeline.run_pipeline (which owns all the stage logic), writes the four artifacts,
and prints a clean human summary -- it adds NO governance logic of its own.

Artifacts (written to <out>/ where <out> defaults to <target>/.openagentontology):
    ontology.json       the deterministic OntologyDoc (this is the receipt's hashed evidence)
    trust_profile.json  the scored tier + 0..100 score + subscores + rationale
    badge.svg           a standalone, embeddable SVG governance badge
    receipt.json        the Ed25519 cert-only receipt (skipped with --no-receipt)

Exit codes (so a CI gate can branch on them):
    0   pipeline ran and validation passed (ok == True)
    1   pipeline ran but validation FAILED closed (error-level findings present)
    2   bad usage / the target path does not exist / an unexpected error

--json prints a single machine-readable object to stdout (the artifacts are still written,
unless --out is a path the caller controls) and suppresses the human summary. The confirm-note
(crosswalk.CONFIRM_NOTE, carried verbatim on the ontology) is ALWAYS surfaced -- in the human
summary and in the JSON payload -- because every mapping the tool emits is proposed, not
asserted-for-audit (pol.must_do.143).

stdlib only. Imports the package facade (run_pipeline) lazily-friendly; no heavy work at import.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .pipeline import run_pipeline
from .schema import VERSION

_OUT_DIRNAME = ".openagentontology"

# ANSI is opt-in: only when stdout is a real TTY, so piped/redirected output stays clean ASCII.
_TTY = sys.stdout.isatty()


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if _TTY else s


# Tier -> colour for the headline only (never changes the words, just the paint).
_TIER_COLOR = {"SOVEREIGN": "32", "HARDENED": "36", "DEVELOPING": "33", "UNGOVERNED": "31"}


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m openagentontology",
        description="Auto-generate a governance ontology + Trust Profile + signed badge for "
                    "any repo / MCP server / agent / OpenAPI / Rego / workflow YAML.",
        epilog="Open-core: this emits a LOCAL, self-signed receipt. Cross-org verification is "
               "CWN's hosted notary (not in this repo).")
    p.add_argument("path", help="file or directory to scan")
    p.add_argument("--out", metavar="DIR", default=None,
                   help="output directory for the artifacts "
                        "(default: <path>/.openagentontology)")
    p.add_argument("--json", action="store_true", dest="as_json",
                   help="emit one machine-readable JSON object to stdout (suppresses the "
                        "human summary)")
    p.add_argument("--no-receipt", action="store_true", dest="no_receipt",
                   help="skip minting the Ed25519 receipt (hermetic, no disk/key access)")
    p.add_argument("--version", action="version",
                   version=f"openagentontology {VERSION}")
    return p


def _resolve_out_dir(path: Path, out_arg: str | None) -> Path:
    """The artifact directory. --out wins; else <target-or-its-parent>/.openagentontology."""
    if out_arg:
        return Path(out_arg).expanduser().resolve()
    base = path if path.is_dir() else path.parent
    return (base / _OUT_DIRNAME).resolve()


def _write_artifacts(out_dir: Path, result, make_receipt: bool) -> dict:
    """Write the four artifacts. Returns {logical_name -> absolute_path_str} actually written."""
    out_dir.mkdir(parents=True, exist_ok=True)
    written = {}

    def _dump_json(name: str, obj) -> None:
        fp = out_dir / name
        # ASCII-only + sorted so the on-disk ontology.json matches the receipt's hashed evidence.
        fp.write_text(
            json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
            encoding="ascii")
        written[name] = str(fp)

    _dump_json("ontology.json", result.ontology.to_dict())
    _dump_json("trust_profile.json", result.profile.to_dict())

    badge_fp = out_dir / "badge.svg"
    badge_fp.write_text(result.badge_svg, encoding="ascii")
    written["badge.svg"] = str(badge_fp)

    if make_receipt and result.receipt:
        _dump_json("receipt.json", result.receipt)

    return written


# ── human summary ────────────────────────────────────────────────────────────
def _print_summary(result, written: dict, out_dir: Path, note: str) -> None:
    p = print
    tier = result.tier
    color = _TIER_COLOR.get(tier, "0")
    p("")
    p(_c("1", "OpenAgentOntology") + f"  v{VERSION}")
    p(_c("2", f"  source: {result.source}"))
    p("")

    # headline tier + score
    headline = f"  {tier}  {result.score}/100"
    p(_c(f"1;{color}", headline))

    # subscores (the rubric is auditable, so show it)
    subs = result.profile.subscores
    if subs:
        order = ("coverage", "rigor", "breadth", "structure")
        cells = [f"{k}={subs[k]}" for k in order if k in subs]
        cells += [f"{k}={v}" for k, v in subs.items() if k not in order]
        p(_c("2", "  subscores: " + "  ".join(cells)))
    p("")

    # counts
    odoc = result.ontology
    n_governed = len(odoc.action_maps)
    n_asserted = sum(
        1 for am in odoc.action_maps
        if any(m.confidence == "asserted" for m in am.mappings))
    n_ungoverned = len(result.ungoverned())
    p(_c("1", "  inventory"))
    p(f"    nodes            {len(odoc.nodes)}")
    p(f"    edges            {len(odoc.edges)}")
    p(f"    governed actions {n_governed}")
    p(f"    asserted-covered {n_asserted}")
    p(f"    ungoverned       {n_ungoverned}")
    if odoc.frameworks:
        p(f"    frameworks       {', '.join(odoc.frameworks)}")
    p("")

    # top mappings (asserted, citable control tokens that became badge chips)
    if result.refs:
        p(_c("1", "  top mappings (asserted, confirm against published text)"))
        for tok in result.refs:
            p(f"    - {tok}")
        p("")

    # rationale lines from the scorer
    if result.profile.rationale:
        p(_c("1", "  rationale"))
        for line in result.profile.rationale:
            p(f"    {line}")
        p("")

    # validation verdict
    errs = result.errors()
    warns = result.warnings()
    if result.ok:
        p(_c("32", "  VALIDATION: PASS") + _c("2", f"  ({len(warns)} warning(s))"))
    else:
        p(_c("31", f"  VALIDATION: FAIL  ({len(errs)} error(s))"))
        for f in errs:
            p(_c("31", f"    ERROR {f.code}: {f.msg}"))
    if warns:
        for f in warns[:8]:
            p(_c("33", f"    warn  {f.code}: {f.msg}"))
        if len(warns) > 8:
            p(_c("2", f"    ... and {len(warns) - 8} more warning(s)"))
    p("")

    # receipt status
    rcpt = result.receipt or {}
    if rcpt:
        if rcpt.get("signed"):
            p(_c("1", "  receipt") + f"  {rcpt.get('atom_id', '')}  "
              + _c("32", f"Ed25519 signed  sha256:{rcpt.get('evidence_hash', '')[:16]}..."))
        else:
            p(_c("1", "  receipt") + f"  {rcpt.get('atom_id', '')}  "
              + _c("33", f"UNSIGNED (install 'cryptography' to sign)  "
                         f"sha256:{rcpt.get('evidence_hash', '')[:16]}..."))
    else:
        p(_c("2", "  receipt        skipped (--no-receipt)"))
    p("")

    # artifacts written
    p(_c("1", "  artifacts"))
    p(_c("2", f"    {out_dir}"))
    for name in ("ontology.json", "trust_profile.json", "badge.svg", "receipt.json"):
        if name in written:
            p(f"    - {name}")
    p("")

    # the confirm-note is MANDATORY on every run (pol.must_do.143)
    p(_c("33", "  NOTE: " + note))
    p("")


def _json_payload(result, written: dict, note: str) -> dict:
    """The --json machine object — CI-friendly shape.

    Top-level keys (in order of usefulness for a CI gate):
      summary       — tier + score + counts + ungoverned list (quick read)
      profile       — full subscores + rationale (deep read)
      findings      — validator results (error/warn/info)
      ontology      — full nodes/edges/action_maps (the hashed evidence)
      receipt       — Ed25519 cert-only receipt ({} when --no-receipt)
      artifacts     — absolute paths to written files
      version       — semver of the openagentontology package
      confirm_note  — crosswalk.CONFIRM_NOTE (always surfaced, pol.must_do.143)
    """
    ontology = result.ontology.to_dict()
    findings = [f.to_dict() for f in result.findings]

    asserted = sum(1 for am in result.ontology.action_maps if am.matched_via == "asserted_table")
    inferred = sum(1 for am in result.ontology.action_maps if am.matched_via == "heuristic")
    ungoverned_ids = [am.subject_id for am in result.ontology.action_maps if am.matched_via == "none"]

    summary = {
        "tier": result.tier,
        "score": result.score,
        "ok": result.ok,
        "counts": {
            "nodes": len(result.ontology.nodes),
            "edges": len(result.ontology.edges),
            "action_maps": len(result.ontology.action_maps),
            "frameworks": len(result.ontology.frameworks),
            "asserted": asserted,
            "inferred": inferred,
            "ungoverned": len(ungoverned_ids),
        },
        "ungoverned_actions": ungoverned_ids,
        "frameworks": sorted(result.ontology.frameworks),
        "refs": list(result.refs),
    }

    return {
        "version": VERSION,
        "summary": summary,
        "profile": result.profile.to_dict(),
        "findings": findings,
        "ontology": ontology,
        "receipt": result.receipt,
        "artifacts": written,
        "confirm_note": note,
    }


def main(argv=None) -> int:
    """CLI entrypoint. Returns the process exit code (0 ok / 1 validation-failed / 2 usage)."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    path = Path(args.path).expanduser()
    if not path.exists():
        print(f"error: path does not exist: {path}", file=sys.stderr)
        return 2

    make_receipt = not args.no_receipt
    try:
        result = run_pipeline(str(path), make_receipt=make_receipt)
    except Exception as exc:  # noqa: BLE001 - the CLI is the last line; report, don't traceback-dump
        print(f"error: pipeline failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    out_dir = _resolve_out_dir(path, args.out)
    try:
        written = _write_artifacts(out_dir, result, make_receipt)
    except OSError as exc:
        print(f"error: could not write artifacts to {out_dir}: {exc}", file=sys.stderr)
        return 2

    note = result.ontology.note  # crosswalk.CONFIRM_NOTE, carried verbatim

    if args.as_json:
        json.dump(_json_payload(result, written, note), sys.stdout,
                  indent=2, sort_keys=True, ensure_ascii=True)
        sys.stdout.write("\n")
    else:
        _print_summary(result, written, out_dir, note)

    return 0 if result.ok else 1


if __name__ == "__main__":  # pragma: no cover - exercised via __main__.py
    raise SystemExit(main())
