"""Regression: side-effecting action functions (verb-named Tasks) must be crosswalked.

This locks in the fix proven against real agents (open-interpreter / gpt-engineer): a
verb-named function such as run / delete_* / send_* / shutdown that carries NO @tool
decorator still lands as a governable action and MUST be mapped -- otherwise the most
dangerous surface of a real agent stays ungoverned-and-invisible.

It also pins the mirror-dedup invariant: an OpenAPI/MCP-style capability+operation PAIR for
one action is NOT double-counted (the operation Task is skipped because it mirrors a
Capability), which is why examples/sample_agent stays at 16 action_maps.
"""
from __future__ import annotations

from openagentontology.generate import generate
from openagentontology.ingest import ingest


def _maps(src_path) -> dict:
    doc = generate(ingest(str(src_path)))
    return {am.subject_id: am for am in doc.action_maps}


def test_verb_named_functions_are_crosswalked(tmp_path):
    src = tmp_path / "agent.py"
    src.write_text(
        "def shutdown():\n    pass\n\n"
        "def send_telemetry():\n    pass\n\n"
        "def _private_helper():\n    pass\n",
        encoding="ascii",
    )
    maps = _maps(src)

    # both side-effecting functions are crosswalked; the private one is never even a node.
    assert "fn_shutdown" in maps, "a side-effecting action function must be crosswalked, not dropped"
    assert "fn_send_telemetry" in maps, "an egress function must be crosswalked"
    assert not any("private" in sid for sid in maps)

    # send_telemetry hits the egress verb heuristic -> INFERRED with real mappings;
    # shutdown matches no heuristic verb -> honestly UNGOVERNED (no fabricated control).
    assert maps["fn_send_telemetry"].matched_via == "heuristic"
    assert maps["fn_send_telemetry"].mappings
    assert maps["fn_shutdown"].matched_via == "none"
    assert maps["fn_shutdown"].mappings == ()


def test_mirrored_operation_is_not_double_counted(sample_dir):
    # examples/sample_agent emits, for each write route, a Capability AND a mirroring
    # operation Task with the same action label. The Task must be skipped so coverage is
    # measured once per action -- the example stays at exactly 16 governed actions.
    maps = _maps(sample_dir)
    assert len(maps) == 16
    # no operation (op_*) Task leaked into the crosswalk as a duplicate of its capability
    assert not any(sid.startswith("op_") for sid in maps)
