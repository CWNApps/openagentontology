"""ingest.py — multi-format extractors: a source path -> normalized agent facts.

The PERIPHERY input stage. Reads ANY of: an OPA Rego policy, an OpenAPI/Swagger spec, an
MCP server manifest, a CWN speckit YAML, a generic LangChain/CrewAI/custom agent definition
(YAML or JSON), a Python file (SAFE AST pass), or a whole directory; and returns the agent's
observable ACTIONS / CAPABILITIES / DECISIONS / GATES, each tagged EXTRACTED.

TWO public shapes, by design:

  ingest_path(path) -> dict        the flat record the task contracts:
      {"source","source_kind","actions":[],"capabilities":[],"decisions":[],"gates":[],
       "reasons":{}, "provenance":"EXTRACTED"}
    Each list item is a plain dict {"id","name","action","reason"?} — a JSON-safe view a
    caller can inspect/diff/serialize without importing the schema.

  ingest(path) / ingest_result(path) -> IngestResult   the duck-typed object
    generate.generate() consumes: .source/.kind/.facts(list[Node])/.rels(list[Edge])/
    .reasons(dict). `.raw` carries the flat record above.

SECURITY (pol.must_do.143 + SECURITY_STANDARD):
  - Ingested code is NEVER imported or executed. Python is parsed with `ast` only (text in,
    tree out — no eval/exec/compile-to-callable, no __import__). Every other format is parsed
    as DATA (yaml.safe_load / json.loads / regex over text).
  - No network. No secrets read from values — only structural names/paths are kept.
  - A giant file is skipped (memory guard). Unreadable / malformed inputs degrade to an
    empty-but-valid record, never a crash.

PROVENANCE: every fact this module emits is EXTRACTED — literally present in the source.
A `reason` is recorded ONLY when the source NAMES a canonical crosswalk reason verbatim
(Layer-1 ASSERTED). Otherwise the node is left out of `reasons` and the crosswalk falls back
to its label heuristic (Layer-2 INFERRED / AMBIGUOUS). This keeps 'auto-detected != ASSERTED
unless exact' honest at the SOURCE — this module never assigns INFERRED/AMBIGUOUS itself.

Deps: stdlib + pyyaml (soft — YAML formats degrade gracefully if PyYAML is absent).
ASCII discipline: ids/names are folded to ASCII so they flow cleanly into the signed receipt.
"""
from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .crosswalk import ASSERTED_TABLE
from .schema import Edge, Node

try:                                   # pyyaml is a declared dep; stay resilient without it.
    import yaml as _yaml
    _HAS_YAML = True
except Exception:                      # pragma: no cover - only on a yaml-less box
    _yaml = None
    _HAS_YAML = False

# The 10 canonical reasons the source may literally name (Layer-1 ASSERTED trigger).
_CANON_REASONS = frozenset(ASSERTED_TABLE)

# Text files we will open; everything else is skipped (no binaries opened).
_TEXT_SUFFIXES = {".rego", ".py", ".json", ".yaml", ".yml"}
_MAX_BYTES = 2_000_000                 # never slurp a giant file into memory
_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build",
              ".next", ".mypy_cache", ".pytest_cache", "site-packages", ".tox"}


# ── the normalized result generate.generate() consumes ───────────────────────
@dataclass
class IngestResult:
    """What an adapter produces. generate() reads .source/.kind/.facts/.rels/.reasons.

    facts   — list[Node]  (Agent/Capability/Decision/Gate/Task/Tool/Workflow/...)
    rels    — list[Edge]  (UAO links; generate drops any dangling ones defensively)
    reasons — dict[node_id -> canonical_reason]  the source-named OPA reason, present ONLY
              when the source stated a canonical reason verbatim, so the crosswalk's Layer-1
              ASSERTED table fires instead of a heuristic guess.
    raw     — the flat dict ingest_path() returns (kept for display / round-trip).
    """
    source: str
    kind: str
    facts: list = field(default_factory=list)
    rels: list = field(default_factory=list)
    reasons: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict)

    def merge(self, other: "IngestResult") -> None:
        seen = {n.id for n in self.facts}
        for n in other.facts:
            if n.id not in seen:
                self.facts.append(n)
                seen.add(n.id)
        self.rels.extend(other.rels)
        self.reasons.update(other.reasons)


# ── helpers ──────────────────────────────────────────────────────────────────
_SLUG = re.compile(r"[^a-z0-9]+")
_TOKEN = re.compile(r"[a-z][a-z0-9_]{3,60}")


def _slug(s, fallback="x"):
    """ASCII id-safe slug (ids land in the signed receipt -> ASCII only)."""
    s = (s or "").strip().lower()
    s = s.encode("ascii", "ignore").decode("ascii")
    s = _SLUG.sub("_", s).strip("_")
    return s or fallback


def _ascii(s):
    """Best-effort ASCII fold so a stray smart-quote in a docstring can't poison the receipt."""
    return (s or "").encode("ascii", "ignore").decode("ascii")


def _truncate(s, n):
    s = _ascii(s).replace("\n", " ").strip()
    return s if len(s) <= n else s[: n - 3] + "..."


def _read_text(path: Path) -> str:
    try:
        if path.stat().st_size > _MAX_BYTES:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _safe_yaml(text):
    if not _HAS_YAML:
        return None
    try:
        return _yaml.safe_load(text)
    except Exception:
        return None


def _safe_json(text):
    try:
        return json.loads(text)
    except Exception:
        return None


def _data(text, suffix):
    """Parse a data file as JSON or YAML, tolerant of either by extension/content."""
    suffix = (suffix or "").lower()
    if suffix == ".json":
        d = _safe_json(text)
        return d if d is not None else _safe_yaml(text)
    d = _safe_yaml(text)
    return d if d is not None else _safe_json(text)


def _canon_reason(name):
    """Map a raw deny key / guardrail token to a canonical ASSERTED reason if it IS one,
    else None. NEVER invents — only matches the 11 reasons already in ASSERTED_TABLE."""
    if not name:
        return None
    n = str(name).strip()
    if n in _CANON_REASONS:
        return n
    low = n.lower()
    return low if low in _CANON_REASONS else None


def _first_canon_token(blob):
    """First canonical reason token found anywhere in a text blob, else None."""
    for tok in _TOKEN.findall(blob.lower()):
        r = _canon_reason(tok)
        if r:
            return r
    return None


def _empty(source, kind):
    return {"source": _ascii(source), "source_kind": kind, "actions": [], "capabilities": [],
            "decisions": [], "gates": [], "reasons": {}, "provenance": "EXTRACTED"}


def _add(rec, bucket, nid, name, action, reason=None):
    """Append one de-duped item to a flat bucket; mirror its reason into rec['reasons']."""
    if not nid or any(it["id"] == nid for it in rec[bucket]):
        return
    item = {"id": nid, "name": _truncate(name, 120), "action": _ascii(action) or nid}
    if reason:
        item["reason"] = reason
        rec["reasons"][nid] = reason
    elif bucket == "gates":
        rec["reasons"].setdefault(nid, None)   # a gate with no canonical reason -> heuristic
    rec[bucket].append(item)


# ── format detection ──────────────────────────────────────────────────────────
def detect_kind(path: Path, text: str | None = None) -> str:
    """Best-effort source-kind label. Extension first, then a cheap content sniff."""
    suf = path.suffix.lower()
    if suf == ".rego":
        return "rego"
    if suf == ".py":
        return "python"
    if text is None:
        text = _read_text(path)
    name = path.name.lower()
    data = _data(text, suf) if suf in (".yaml", ".yml", ".json") else None
    if isinstance(data, dict):
        if "openapi" in data or "swagger" in data or "paths" in data:
            return "openapi"
        # speckit / eval shape: a CWN speckit (speckit_id/smoke_tests/acceptance) OR a CWN
        # eval (eval_id + a `tests` block of named assertions). Both are test-bearing specs the
        # speckit adapter governs; an eval_id alone disambiguates it from a generic agentdef.
        if ("speckit_id" in data or "smoke_tests" in data or "acceptance" in data
                or "eval_id" in data or ("tests" in data and isinstance(data.get("tests"), dict))):
            return "speckit"
        # An agent definition can ALSO carry a `tools` list — so the agentdef-shaped keys
        # win over a bare `tools` (only a true manifest: mcpServers, or tools-and-nothing-else).
        _AGENTDEF_KEYS = ("agent", "tasks", "steps", "decisions", "gates", "guardrails",
                          "skills", "workflow", "plan", "policies", "constraints", "checks")
        if data.get("mcpServers") is not None:
            return "mcp"
        if any(k in data for k in _AGENTDEF_KEYS):
            return "agentdef"
        if "tools" in data or "capabilities" in data:
            return "mcp"
        return "agentdef"
    if suf in (".yaml", ".yml", ".json"):
        return "agentdef"
    return "text"


# ── adapter: OPA Rego (TEXT only — never evaluated) ──────────────────────────
# deny_reason := "x" / reasons contains "x" / msg := "x" string literals, plus the
# allow_*/deny/violation rule heads. A canonical literal drives Layer-1 ASSERTED; a
# non-canonical one still becomes a Gate whose reason LABEL feeds the Layer-2 heuristic.
_REGO_PKG = re.compile(r"(?m)^\s*package\s+([A-Za-z0-9_.]+)")
_REGO_LIT = re.compile(r'(?:reason|reasons|msg|message|code|deny_reason)\s+'
                       r'(?:contains\s+)?[:=]*\s*"([a-z][a-z0-9_]{2,80})"')
_REGO_DENY_KEY = re.compile(r'(?m)^\s*(?:deny|violation|warn)\b[^\n]*?"([a-z][a-z0-9_]{2,80})"')
_REGO_ALLOW = re.compile(r"(?m)^\s*(?:default\s+)?(allow_[a-z0-9_]+|allow)\b")


def _from_rego(text, source) -> dict:
    rec = _empty(source, "rego")
    pkg_m = _REGO_PKG.search(text)
    pkg = pkg_m.group(1) if pkg_m else Path(source).stem

    keys = []
    for m in list(_REGO_LIT.finditer(text)) + list(_REGO_DENY_KEY.finditer(text)):
        k = m.group(1)
        if k not in keys:
            keys.append(k)
    for key in keys:
        reason = _canon_reason(key)               # canonical -> Layer-1; else label heuristic
        gid = _slug(f"gate_{key}")
        _add(rec, "gates", gid, key, key, reason)

    # allow_* rule names are the policy's positive guards -> Gates too (named by the guard).
    for m in _REGO_ALLOW.finditer(text):
        guard = m.group(1)
        gid = _slug(f"gate_{pkg}_{guard}")
        _add(rec, "gates", gid, f"{pkg}.{guard}", guard, _canon_reason(guard))

    if not rec["gates"]:                           # a policy with no recoverable guard surface
        gid = _slug(f"gate_{pkg}")
        _add(rec, "gates", gid, pkg, pkg, None)
    return rec


# ── adapter: OpenAPI / Swagger (data) ────────────────────────────────────────
_WRITE_METHODS = {"post", "put", "patch", "delete"}
_HTTP_METHODS = _WRITE_METHODS | {"get", "head", "options"}


def _from_openapi(data, source) -> dict:
    """Each path+method is an ACTION; a write method is also a side-effecting Capability."""
    rec = _empty(source, "openapi")
    paths = data.get("paths") if isinstance(data, dict) else None
    if not isinstance(paths, dict):
        return rec
    for route, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, op in methods.items():
            m = method.lower()
            if m not in _HTTP_METHODS:
                continue
            opid = ""
            if isinstance(op, dict):
                opid = op.get("operationId") or op.get("summary") or ""
            label = opid or f"{m} {route}"
            # The crosswalk reads the ACTION label: prefer the operationId (e.g. 'wire_transfer',
            # 'delete_user') over the bare route so a real verb can drive the heuristic.
            action = opid or f"{m} {route}"
            _add(rec, "actions", _slug(f"op_{m}_{route}"), label, action)
            if m in _WRITE_METHODS:                 # writes are the governed capability surface
                _add(rec, "capabilities", _slug(f"cap_{m}_{route}"), label, action)
    return rec


# ── adapter: MCP manifest (data) ─────────────────────────────────────────────
def _from_mcp(data, source) -> dict:
    """Each declared tool is a CAPABILITY. Supports a flat {tools:[...]} manifest, a
    {tools:{name:{...}}} map, a {capabilities:[...]} list, and a {mcpServers:{...}} host config."""
    rec = _empty(source, "mcp")

    def add_tool(name, desc=""):
        if not name:
            return
        _add(rec, "capabilities", _slug(f"cap_{name}"), name, name,
             _first_canon_token(f"{name} {desc}"))

    if isinstance(data, dict):
        tools = data.get("tools")
        if isinstance(tools, list):
            for t in tools:
                if isinstance(t, str):
                    add_tool(t)
                elif isinstance(t, dict):
                    add_tool(t.get("name") or t.get("id"), t.get("description", ""))
        elif isinstance(tools, dict):
            for k, v in tools.items():
                add_tool(k, (v or {}).get("description", "") if isinstance(v, dict) else "")
        caps = data.get("capabilities")
        if isinstance(caps, list):
            for c in caps:
                add_tool(c if isinstance(c, str) else (c.get("name") if isinstance(c, dict) else None),
                         c.get("description", "") if isinstance(c, dict) else "")
        servers = data.get("mcpServers")
        if isinstance(servers, dict):               # host config: each server is a tool surface
            for sname in servers:
                add_tool(sname)
    return rec


# ── adapter: CWN speckit YAML (data) ─────────────────────────────────────────
def _from_speckit(data, source) -> dict:
    """smoke_tests -> CAPABILITIES (each `invoke` is the action); a CWN eval `tests` block
    -> CAPABILITIES (each named check is the action, its description the reason source);
    acceptance -> GATES (the conditions the unit is held to). A test/acceptance line that
    NAMES a canonical reason becomes a source-named Layer-1 reason.

    The crosswalk reads the ACTION label, so each test's action is its full text (id +
    description) -- that lets a description like 'every blocking DENY reason is mapped' or
    'export of regulated data is blocked' drive the heuristic when no canonical reason is
    named verbatim. Honest by construction: no reason is fabricated, only detected."""
    rec = _empty(source, "speckit")
    if not isinstance(data, dict):
        return rec
    spec_id = data.get("speckit_id") or data.get("eval_id") or Path(source).stem

    for st in (data.get("smoke_tests") or []):
        if not isinstance(st, dict):
            continue
        tid = st.get("id") or st.get("description") or "smoke_test"
        action = st.get("invoke") or tid
        reason = _first_canon_token(json.dumps(st, sort_keys=True, default=str))
        _add(rec, "capabilities", _slug(f"cap_{spec_id}_{tid}"), str(tid), str(action), reason)

    # CWN eval `tests`: a dict {test_id: {description, ...}} OR a list of test blocks. Each
    # test is a CAPABILITY the eval exercises. The action label uses ONLY the test ID (not the
    # description) so that meta-language in test descriptions (e.g. "every deny reason is
    # mapped") does not trigger false-positive verb heuristics in the crosswalk. The description
    # IS still searched for canonical reason tokens (Layer-1 ASSERTED detection).
    tests = data.get("tests")
    test_items = []
    if isinstance(tests, dict):
        test_items = list(tests.items())
    elif isinstance(tests, list):
        test_items = [((t.get("id") or t.get("name") or f"test_{i}"), t)
                      for i, t in enumerate(tests) if isinstance(t, dict)]
    for tid, tbody in test_items:
        body = tbody if isinstance(tbody, dict) else {}
        action = str(tid)                              # ID only — keeps meta-language out of heuristic
        reason = _first_canon_token(json.dumps({"id": tid, **body}, sort_keys=True, default=str))
        _add(rec, "capabilities", _slug(f"cap_{spec_id}_{tid}"), str(tid), action, reason)

    for i, acc in enumerate(data.get("acceptance") or []):
        txt = acc if isinstance(acc, str) else json.dumps(acc, default=str)
        reason = _first_canon_token(txt)
        _add(rec, "gates", _slug(f"gate_{spec_id}_{i}"), _truncate(txt, 80), txt, reason)
    return rec


# ── adapter: generic agent definition (LangChain / CrewAI / custom, data) ────
def _from_agentdef(data, source) -> dict:
    """tools/skills -> CAPABILITIES, tasks/steps -> ACTIONS, decisions -> DECISIONS,
    gates/guardrails/policies -> GATES. Tolerant of many key names + list-of-blocks specs."""
    rec = _empty(source, "agentdef")
    if not isinstance(data, (dict, list)):
        return rec
    blocks = data if isinstance(data, list) else [data]

    def names_in(obj, *keys):
        """Yield (name, action, explicit_reason) triples. An item dict may carry an
        explicit `reason` / `action`; a bare string is its own name+action with no reason."""
        for k in keys:
            v = obj.get(k) if isinstance(obj, dict) else None
            if isinstance(v, list):
                for item in v:
                    if isinstance(item, str):
                        yield item, item, None
                    elif isinstance(item, dict):
                        nm = item.get("name") or item.get("id") or item.get("tool") or ""
                        yield nm, (item.get("action") or nm), item.get("reason")
            elif isinstance(v, dict):
                for kk in v:
                    yield kk, kk, None
            elif isinstance(v, str):
                yield v, v, None

    def reason_of(name, explicit):
        """An explicit canonical reason wins; else the name itself may be a canonical reason."""
        return _canon_reason(explicit) or _canon_reason(name)

    for blk in blocks:
        if not isinstance(blk, dict):
            continue
        for nm, act, rsn in names_in(blk, "tools", "skills", "capabilities", "allowed_tools", "functions"):
            _add(rec, "capabilities", _slug(f"cap_{nm}"), nm, act, reason_of(nm, rsn))
        for nm, act, rsn in names_in(blk, "tasks", "steps", "actions", "workflow", "plan"):
            _add(rec, "actions", _slug(f"act_{nm}"), nm, act)
        for nm, act, rsn in names_in(blk, "decisions", "choices"):
            _add(rec, "decisions", _slug(f"dec_{nm}"), nm, act, reason_of(nm, rsn))
        for nm, act, rsn in names_in(blk, "gates", "guardrails", "policies", "checks", "constraints"):
            _add(rec, "gates", _slug(f"gate_{nm}"), nm, act, reason_of(nm, rsn))
    return rec


# ── adapter: Python (SAFE AST pass — never imported / executed) ──────────────
_ACTION_VERBS = (
    "deploy", "delete", "drop", "purge", "destroy", "send", "email", "post", "publish",
    "export", "upload", "transfer", "wire", "pay", "refund", "charge", "approve", "deny",
    "reject", "grant", "revoke", "provision", "deprovision", "execute", "run", "exec",
    "shutdown", "restart", "terminate", "migrate", "rollback", "release", "escalate",
    "impersonate", "disclose", "share", "remit", "disburse",
)
_ACTION_RE = re.compile(r"^(?:" + "|".join(_ACTION_VERBS) + r")(?:_|[A-Z]|$)")
_TOOL_DECOS = {"tool", "tool_node", "function_tool", "kernel_function"}
_DECISION_DECOS = {"decision", "decide"}
_GATE_DECOS = {"gate", "guard", "guardrail", "policy"}


def _from_python(text, source) -> dict:
    """Parse text -> AST (never import/exec). A @tool-decorated def is a CAPABILITY; a def
    whose NAME reads as a side-effecting verb (deploy/delete/send/export/pay/...) is an
    ACTION; @decision/@gate decorators promote a def accordingly. AST ONLY."""
    rec = _empty(source, "python")
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return rec                                 # unparseable -> empty, never crash

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        fn = node.name
        if fn.startswith("_"):
            continue
        decos = {_deco_name(d) for d in node.decorator_list}
        doc = _ascii(ast.get_docstring(node) or "")
        if decos & _TOOL_DECOS:                    # a declared tool is a capability
            _add(rec, "capabilities", _slug(f"cap_{fn}"), fn, fn, _first_canon_token(f"{fn} {doc}"))
        if decos & _DECISION_DECOS:
            _add(rec, "decisions", _slug(f"dec_{fn}"), fn, fn, _first_canon_token(f"{fn} {doc}"))
        if decos & _GATE_DECOS:
            _add(rec, "gates", _slug(f"gate_{fn}"), fn, fn, _first_canon_token(f"{fn} {doc}"))
        if not decos and _ACTION_RE.match(fn):     # a verb-named def is a side-effecting action
            _add(rec, "actions", _slug(f"fn_{fn}"), fn, fn)
    return rec


def _deco_name(d) -> str:
    if isinstance(d, ast.Name):
        return d.id.lower()
    if isinstance(d, ast.Attribute):
        return d.attr.lower()
    if isinstance(d, ast.Call):
        return _deco_name(d.func)
    return ""


# ── single-file dispatch -> flat record ───────────────────────────────────────
def _extract_file(path: Path) -> dict:
    """Read one file, detect its kind, and return its flat extracted record."""
    source = str(path)
    if path.suffix.lower() not in _TEXT_SUFFIXES:
        return _empty(source, "skip")
    text = _read_text(path)
    if not text:
        return _empty(source, "text")
    kind = detect_kind(path, text)
    if kind == "rego":
        return _from_rego(text, source)
    if kind == "python":
        return _from_python(text, source)
    data = _data(text, path.suffix)
    if kind == "openapi":
        return _from_openapi(data, source)
    if kind == "mcp":
        return _from_mcp(data, source)
    if kind == "speckit":
        return _from_speckit(data, source)
    if kind == "agentdef":
        return _from_agentdef(data, source)
    return _empty(source, "text")


def _has_facts(rec) -> bool:
    return any(rec.get(b) for b in ("actions", "capabilities", "decisions", "gates"))


def _merge_record(agg: dict, rec: dict):
    """Fold one file's flat record into a directory aggregate, de-duping ids."""
    for bucket in ("actions", "capabilities", "decisions", "gates"):
        seen = {it["id"] for it in agg[bucket]}
        for it in rec.get(bucket, []):
            if it["id"] not in seen:
                agg[bucket].append(it)
                seen.add(it["id"])
    for nid, reason in rec.get("reasons", {}).items():
        agg["reasons"].setdefault(nid, reason)


def _extract_dir(root: Path) -> dict:
    """Walk a directory (sorted, deterministic), dispatch each supported file, and merge."""
    agg = _empty(str(root), "directory")
    kinds = set()
    for p in sorted(root.rglob("*")):
        if p.is_dir() or any(part in _SKIP_DIRS for part in p.parts):
            continue
        if p.suffix.lower() not in _TEXT_SUFFIXES:
            continue
        rec = _extract_file(p)
        if _has_facts(rec):
            kinds.add(rec["source_kind"])
            _merge_record(agg, rec)
    agg["source_kind"] = next(iter(kinds)) if len(kinds) == 1 else "directory"
    agg["mixed_kinds"] = sorted(kinds)
    return agg


# ── PUBLIC: the flat extracted record ─────────────────────────────────────────
def ingest_path(path) -> dict:
    """Ingest a file OR directory and return the flat extracted record:

        {"source","source_kind","actions","capabilities","decisions","gates",
         "reasons","provenance"}

    Everything is EXTRACTED (present in the source). Never raises on a missing /
    unreadable / malformed path — returns an empty-but-valid record instead.
    """
    p = Path(path)
    if not p.exists():
        return _empty(str(p), "missing")
    if p.is_dir():
        return _extract_dir(p)
    return _extract_file(p)


# ── PUBLIC: the schema-typed IngestResult generate() consumes ─────────────────
# Each flat bucket maps to a UAO node type. A synthesized Agent root ties the buckets together
# via canonical UAO links so the subgraph is connected (generate drops dangling edges, so the
# Agent root is what keeps every governed node reachable and non-dangling).
_BUCKET_NODE_TYPE = {
    "capabilities": "Capability",
    "decisions": "Decision",
    "gates": "Gate",
    "actions": "Task",          # a free action is a Task the agent executes
}
_BUCKET_LINK = {
    "capabilities": "HAS_CAPABILITY",
    "decisions": "MAKES",
    "gates": "GATED_BY",        # UAO: Task GATED_BY Gate — we hang it off the Agent root
    "actions": "EXECUTES",
}


def _record_to_facts(rec: dict):
    """Build (facts[Node], rels[Edge], reasons{}) from a flat record. Adds one Agent root."""
    facts, rels = [], []
    reasons = {k: v for k, v in rec.get("reasons", {}).items() if v}   # drop None placeholders

    stem = Path(rec.get("source", "agent")).stem or "agent"
    agent_id = _slug(f"agent_{stem}", "agent_root")
    facts.append(Node(id=agent_id, type="Agent",
                      name=_ascii(Path(rec.get("source", "agent")).name) or "agent",
                      props={"source_kind": rec.get("source_kind", "unknown")},
                      provenance="EXTRACTED"))

    seen = {agent_id}
    for bucket, ntype in _BUCKET_NODE_TYPE.items():
        rel = _BUCKET_LINK[bucket]
        for it in rec.get(bucket, []):
            nid = it.get("id")
            if not nid or nid in seen:
                continue
            seen.add(nid)
            props = {"action": it.get("action") or it.get("name") or nid}
            if it.get("reason"):
                props["reason"] = it["reason"]
                reasons.setdefault(nid, it["reason"])
            facts.append(Node(id=nid, type=ntype, name=it.get("name") or nid,
                              props=props, provenance="EXTRACTED"))
            rels.append(Edge(src=agent_id, rel=rel, dst=nid, provenance="EXTRACTED"))
    return facts, rels, reasons


def ingest_result(path) -> IngestResult:
    """Ingest a path and return the IngestResult generate.generate() consumes directly.

    The flat record is preserved on `.raw`; `.facts`/`.rels`/`.reasons` are the schema-typed
    view (UAO Node/Edge) with a synthesized Agent root tying the subgraph together.
    """
    rec = ingest_path(path)
    facts, rels, reasons = _record_to_facts(rec)
    return IngestResult(source=rec.get("source", str(path)),
                        kind=rec.get("source_kind", "unknown"),
                        facts=facts, rels=rels, reasons=reasons, raw=rec)


# Back-compat / convenience alias: `ingest()` is the natural verb the pipeline calls.
def ingest(path) -> IngestResult:
    """Alias for ingest_result(path) — the pipeline-facing entrypoint."""
    return ingest_result(path)
