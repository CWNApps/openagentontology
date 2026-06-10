"""sarif.py -- export a governance scan as SARIF 2.1.0 for code-scanning UIs.

to_sarif(result) turns one PipelineResult (or a bare OntologyDoc) into a SARIF log a
CI system already knows how to render: GitHub code scanning, VS Code SARIF viewer,
Azure DevOps. The findings are exactly what the validator and the crosswalk already
established -- this module ADDS no governance logic and invents nothing:

  error / warning   one result per UNGOVERNED side-effecting action (an action the
                    verb-class table marks side-effecting whose crosswalk matched_via
                    is 'none'). Level 'error' when the severity is critical
                    (execution-class verbs), 'warning' otherwise.
  note              one result per AMBIGUOUS action (resolved only to the heuristic
                    LLM06 stub) -- held together by a guess, confirm it.

Rule ids are stable and grep-able: OAO-UNGOVERNED-<RISK_DOMAIN> and
OAO-AMBIGUOUS-<RISK_DOMAIN> (domains from risk_profile.VERB_CLASSES, e.g.
OAO-UNGOVERNED-EXECUTION). Locations carry the scanned source path (the only source
info the ontology stores -- schema.Node keeps no per-file/line data; a node-level
props['source'], if a future adapter records one, is preferred when present). No
line numbers are ever fabricated.

Deterministic: results are sorted by (ruleId, subject id), rules by id, and nothing
time-dependent is embedded -- two exports of the same scan are byte-identical.

Pure function. Imports schema + risk_profile only. No I/O, no network, ASCII output.
"""
from __future__ import annotations

from .risk_profile import classify_action
from .schema import VERSION

SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
_TOOL_NAME = "openagentontology"
_INFO_URI = "https://github.com/CWNApps/openagentontology"
_HELP_URI = "https://agent-ontology.cyberwarriornetwork.com"

# Severities that make an ungoverned action worth a SARIF result at all.
_SIDE_EFFECTING = ("critical", "high", "medium")


def _doc_of(result):
    """Duck-type: a PipelineResult carries .ontology; a bare OntologyDoc is itself."""
    return getattr(result, "ontology", result)


def _uri(node, doc) -> str:
    """The best source URI the ontology actually carries. Forward slashes only."""
    src = ""
    if node is not None and isinstance(node.props, dict):
        src = str(node.props.get("source", "") or "")
    src = src or str(getattr(doc, "source", "") or "")
    return src.replace("\\", "/")


def _location(node, doc, subject_id: str) -> dict:
    loc = {"logicalLocations": [{"name": subject_id, "kind": "function"}]}
    uri = _uri(node, doc)
    if uri:
        loc["physicalLocation"] = {"artifactLocation": {"uri": uri}}
    return loc


def _rule(rule_id: str) -> dict:
    if rule_id.startswith("OAO-UNGOVERNED-"):
        text = ("Side-effecting agent action with no mapped governance control. "
                "Declare a canonical reason or wire a blocking gate.")
    else:
        text = ("Agent action resolved only to an ambiguous heuristic mapping. "
                "Confirm against published control text.")
    return {
        "id": rule_id,
        "name": "".join(p.capitalize() for p in rule_id.split("-")[1:]),
        "shortDescription": {"text": text},
        "helpUri": _HELP_URI,
    }


def to_sarif(result) -> dict:
    """One SARIF 2.1.0 log for one governance scan. See module docstring for the
    result classes; structure validates against the published 2.1.0 schema."""
    doc = _doc_of(result)
    by_id = {n.id: n for n in getattr(doc, "nodes", [])}

    raw = []
    for am in sorted(getattr(doc, "action_maps", []), key=lambda a: a.subject_id):
        domain, severity = classify_action(am.label)
        node = by_id.get(am.subject_id)

        if am.matched_via == "none" and severity in _SIDE_EFFECTING:
            rule_id = f"OAO-UNGOVERNED-{domain.upper()}"
            level = "error" if severity == "critical" else "warning"
            msg = (f"Ungoverned side-effecting action '{am.label}' "
                   f"(domain {domain}, severity {severity}): no framework control "
                   "matched. Declare a canonical reason or wire a blocking gate.")
            raw.append((rule_id, am.subject_id, level, msg, node))
            continue

        if am.matched_via == "heuristic" and am.mappings and all(
                m.confidence == "ambiguous" for m in am.mappings):
            rule_id = f"OAO-AMBIGUOUS-{domain.upper()}"
            msg = (f"Action '{am.label}' resolved only to an ambiguous heuristic "
                   "stub (OWASP LLM06) -- confirm against published control text.")
            raw.append((rule_id, am.subject_id, "note", msg, node))

    raw.sort(key=lambda r: (r[0], r[1]))
    rule_ids = sorted({r[0] for r in raw})
    rule_index = {rid: i for i, rid in enumerate(rule_ids)}

    results = []
    for rule_id, subject_id, level, msg, node in raw:
        results.append({
            "ruleId": rule_id,
            "ruleIndex": rule_index[rule_id],
            "level": level,
            "message": {"text": msg},
            "locations": [_location(node, doc, subject_id)],
        })

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {
                "name": _TOOL_NAME,
                "version": VERSION,
                "informationUri": _INFO_URI,
                "rules": [_rule(rid) for rid in rule_ids],
            }},
            "results": results,
        }],
    }
