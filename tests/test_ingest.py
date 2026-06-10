"""test_ingest.py — the multi-format extractors are correct, safe, and honest.

Covers: Rego deny keys -> EXTRACTED reasons; Python parsed via AST only (never executed);
MCP/OpenAPI/YAML adapters; directory walking; the security + provenance invariants; and the
'reason recorded only when the source named it' rule that keeps Layer-1 ASSERTED honest.
"""
from __future__ import annotations

from openagentontology.crosswalk import ASSERTED_TABLE
from openagentontology.ingest import ingest
from openagentontology.schema import LINK_TYPES, NODE_TYPES, Edge, Node


def _result(path):
    """Get the duck-typed IngestResult regardless of which public name the module exposes."""
    return ingest(path)


def _facts(res):
    return list(getattr(res, "facts"))


def _reasons(res):
    return dict(getattr(res, "reasons"))


# ── duck-typed shape generate() depends on ────────────────────────────────────
def test_ingest_result_exposes_generate_contract(sample_dir):
    res = _result(sample_dir)
    for attr in ("source", "kind", "facts", "rels", "reasons"):
        assert hasattr(res, attr), f"IngestResult missing .{attr} (generate.generate depends on it)"
    assert isinstance(res.source, str) and res.source
    assert all(isinstance(n, Node) for n in res.facts)
    assert all(isinstance(e, Edge) for e in res.rels)
    assert isinstance(res.reasons, dict)


def test_all_facts_are_valid_node_types_and_extracted(sample_dir):
    res = _result(sample_dir)
    assert _facts(res), "the dogfood corpus must extract at least one node"
    for n in _facts(res):
        assert n.type in NODE_TYPES, f"node {n.id} has invalid type {n.type!r}"
        assert n.provenance == "EXTRACTED", f"node {n.id} is not EXTRACTED"
        n.id.encode("ascii")
        n.name.encode("ascii")


def test_all_edges_use_valid_link_types(sample_dir):
    res = _result(sample_dir)
    for e in res.rels:
        assert e.rel in LINK_TYPES, f"edge uses non-UAO rel {e.rel!r}"


# ── Rego: deny keys become EXTRACTED reasons (Layer-1 ASSERTED trigger) ───────
def test_rego_deny_keys_become_source_named_reasons(sample_dir):
    res = _result(sample_dir / "payments.rego")
    reasons = set(_reasons(res).values())
    # the sample policy names exactly these three canonical reasons
    for r in ("dual_control_required", "over_threshold", "beneficiary_unverified"):
        assert r in reasons, f"rego reason {r} not extracted as a source-named reason"
        assert r in ASSERTED_TABLE


def test_recorded_reasons_are_only_canonical(sample_dir):
    # every value in .reasons must be a real canonical reason (or None); never an invented token.
    res = _result(sample_dir)
    for node_id, reason in _reasons(res).items():
        assert reason is None or reason in ASSERTED_TABLE, \
            f"node {node_id} carries non-canonical reason {reason!r}"


# ── Python: AST parse, never executed ─────────────────────────────────────────
def test_python_is_parsed_not_executed(tmp_path):
    # a module that would CRASH or write a file if imported/executed. Ingest must read it as
    # text via AST and still extract the @tool capability without side effects.
    sentinel = tmp_path / "SHOULD_NOT_EXIST.txt"
    code = (
        "from langchain_core.tools import tool\n"
        "import pathlib\n"
        f"pathlib.Path(r'{sentinel}').write_text('executed!')\n"  # side effect IF executed
        "raise RuntimeError('module body ran -- ingest executed the file!')\n"
        "\n"
        "@tool\n"
        "def wire_transfer(amount: float):\n"
        "    'Send a wire_transfer.'\n"
        "    return amount\n"
    )
    f = tmp_path / "evil_agent.py"
    f.write_text(code, encoding="utf-8")

    res = _result(f)  # must NOT raise, must NOT create the sentinel
    assert not sentinel.exists(), "ingest EXECUTED the python file -- security violation"
    cap_ids = [n.id for n in _facts(res) if n.type == "Capability"]
    assert any("wire_transfer" in cid for cid in cap_ids), \
        "the @tool capability was not extracted via AST"


def test_unparseable_python_degrades_without_crashing(tmp_path):
    f = tmp_path / "broken.py"
    f.write_text("from langchain import tool\ndef (:::\n", encoding="utf-8")
    res = _result(f)  # syntax error -> no crash
    assert hasattr(res, "facts")


# ── MCP + OpenAPI adapters ────────────────────────────────────────────────────
def test_mcp_manifest_yields_tools_and_capabilities(sample_dir):
    res = _result(sample_dir / "mcp_server.json")
    names = {n.name for n in _facts(res)}
    assert any("deploy" in n.lower() for n in names), "mcp deploy tool not extracted"
    # the deploy/delete tools are side-effecting capabilities the crosswalk should govern
    cap_actions = {n.props.get("action", n.name) for n in _facts(res) if n.type == "Capability"}
    assert any("deploy" in a.lower() or "delete" in a.lower() for a in cap_actions)


def test_openapi_mutating_ops_become_capabilities(sample_dir):
    res = _result(sample_dir / "openapi.yaml")
    cap_labels = {n.props.get("action", n.name).lower()
                  for n in _facts(res) if n.type == "Capability"}
    assert any("wire" in c for c in cap_labels), "openapi wire_transfer op not a capability"
    assert any("deploy" in c for c in cap_labels), "openapi deploy op not a capability"


# ── directory walk ────────────────────────────────────────────────────────────
def test_directory_walk_merges_all_formats(sample_dir):
    res = _result(sample_dir)
    types = {n.type for n in _facts(res)}
    # a multi-format corpus should surface side-effecting governed types
    assert "Capability" in types or "Decision" in types or "Gate" in types
    assert len(_facts(res)) >= 5, "directory walk under-extracted the corpus"


def test_skips_binary_and_vendored_dirs(tmp_path):
    # a vendored dir + a binary file must be ignored; a real rego must still be read.
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.rego").write_text(
        'package vendored\nreasons contains "over_threshold" if true\n', encoding="utf-8")
    (tmp_path / "blob.bin").write_bytes(b"\x00\x01\x02\x03")
    (tmp_path / "real.rego").write_text(
        'package real\nimport rego.v1\nreasons contains "approval_required" if true\n',
        encoding="utf-8")
    res = _result(tmp_path)
    reasons = set(_reasons(res).values())
    assert "approval_required" in reasons
    assert "over_threshold" not in reasons, "ingest walked into node_modules"


def test_empty_dir_does_not_crash(tmp_path):
    res = _result(tmp_path)
    assert hasattr(res, "facts")  # empty but valid


def test_missing_path_degrades_without_crashing(tmp_path):
    # Documented contract: ingest degrades unreadable/missing inputs to an empty-but-valid
    # result rather than crashing the pipeline (a scan must never blow up on a bad path).
    res = _result(tmp_path / "does_not_exist_anywhere")
    assert hasattr(res, "facts") and hasattr(res, "reasons")
    # nothing meaningful is governed: no source-named reason can be fabricated from a void.
    assert all(r is None or r in ASSERTED_TABLE for r in _reasons(res).values())
