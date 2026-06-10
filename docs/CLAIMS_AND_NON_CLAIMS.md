# Claims and non-claims

What OpenAgentOntology claims, what it deliberately does not claim, and the code or test
that enforces each line. A governance tool that overstates its own guarantees is the exact
failure mode it exists to catch, so this file is part of the standard: if a claim below ever
stops being mechanically true, that is a release-blocking bug.

Every claim cites the module that implements it and the test that pins it. The tests run
with no install step: `PYTHONPATH=. python -m pytest -q` from the repo root.

---

## Claims

### C1. It extracts the static action surface without executing target code

The scanner reads every input as data: Python is parsed with the stdlib `ast` module (text
in, tree out -- no import, no `eval`, no `exec`), Rego is regex-scanned as text, and YAML /
JSON formats go through `yaml.safe_load` / `json.loads`. There is no code path from a
scanned file to execution, and the core pipeline makes no network calls. Implementation:
`openagentontology/ingest.py` (see `_from_python` and the SECURITY note in its module
docstring). Pinned by `tests/test_ingest.py::test_python_is_parsed_not_executed`, which
scans a Python file that would raise and write a sentinel file if executed, then asserts the
sentinel does not exist and the `@tool` capability was still extracted, and by
`tests/test_ingest.py::test_unparseable_python_degrades_without_crashing`.

### C2. It produces a deterministic typed graph and a signed receipt

The same source always yields the same ontology: nodes and edges are UAO-typed
(`openagentontology/schema.py`), `OntologyDoc.to_dict()` sorts every collection, and
`openagentontology/generate.py` is a pure transform with no I/O. The receipt
(`openagentontology/receipt.py`) hashes the canonical JSON of that deterministic evidence
and signs a small body that commits to the hash, so the `evidence_hash` is a pure function
of what was scanned. Pinned by `tests/test_pipeline.py::test_pipeline_is_deterministic`
(two runs produce identical ontology, profile, badge, and evidence hash) and
`tests/test_receipt.py::test_independent_canon_reproduces_evidence_hash` (an independent,
JS-style canonicalizer reproduces the hash byte-for-byte).

### C3. Validation prevents fabricated asserted control ids

`map_action()` in `openagentontology/crosswalk.py` never constructs a framework-id string;
it only re-emits ids that already exist in `ASSERTED_TABLE`. Downstream,
`openagentontology/validate.py` fails closed on `E_FRAMEWORK` (any framework outside
`ALLOWED_FRAMEWORKS`) and `E_FAKE_ID` (any `asserted` mapping whose `(fw, id)` pair is not
in the table), so a typo or a hostile edit cannot smuggle an invented control like `AC-99`
into a valid ontology. Pinned by
`tests/test_crosswalk.py::test_map_action_never_fabricates_a_framework_id` (adversarial
probe labels, including `AC-99` and `fabricate`) and
`tests/test_pipeline.py::test_validator_fails_closed_on_fabricated_framework`.

### C4. Declared mappings are distinguished from heuristic guesses

A mapping is `asserted` only when the source itself names one of the ten canonical reasons
(a Rego deny key, an explicit `reason:` field) -- crosswalk Layer 1, provenance `EXTRACTED`.
Everything detected by verb heuristic is downgraded: a strong single-domain verb yields
`inferred` / `INFERRED`, a weak overloaded verb yields at most a single `ambiguous` OWASP
LLM06 stub. `openagentontology/ingest.py` records a reason only when the source states it
verbatim and never assigns inferred status itself. Pinned by
`tests/test_crosswalk.py::test_strong_heuristic_is_inferred_never_asserted`,
`tests/test_crosswalk.py::test_source_named_reason_yields_asserted_extracted`, and
`tests/test_ingest.py::test_recorded_reasons_are_only_canonical`.

### C5. It identifies the ABSENCE of machine-readable governance declarations

The most valuable output is often the empty row: an action that matches no declared reason
and no heuristic comes back `matched_via: "none"`, the validator emits a `W_UNGOVERNED`
finding, and the coverage axis of the trust profile scores it as the gap it is -- the tool
never force-fits a control to fill the hole. This is how the two real-world scans
(`docs/real-world-scan.md`) surfaced `exec` with nothing answering for it. Pinned by
`tests/test_crosswalk.py::test_no_match_is_empty_and_ungoverned` and
`tests/test_action_crosswalk.py::test_verb_named_functions_are_crosswalked` (the
`shutdown` function is honestly UNGOVERNED rather than mapped to a fabricated control).

### C6. The hosted CWN Graph Model Service provides graph-grounded inferred candidates that stay non-asserted

The CWN Graph Model Service (hosted) is a separate service, not in this repo. It takes a
scan's unresolved or heuristic-only actions and returns graph-grounded candidate
resolutions -- canonical-reason recommendations, control candidates, technique context, and
retrieved (never generated) threat signals. Every candidate is labeled
`GRAPH_INFERRED_HIGH` / `GRAPH_INFERRED_MED` and flagged `human_review_required`; nothing
from the graph is ever ASSERTED, because only a source-declared canonical reason or a
confirmed human governance record can assert, and the OSS validator's `E_FAKE_ID` /
`E_FRAMEWORK` gates reject any asserted id that did not come from `ASSERTED_TABLE`. A
committed example of this output is
`docs/scans/open-interpreter/graph_resolutions.json` (see its `note` field, which states
the non-assertion rule verbatim).

---

## Non-claims

### N1. It does not prove runtime enforcement

The scan is static. An extracted Rego deny key proves the policy is *declared* in the
source, not that the policy bundle is loaded, the decision point is wired, or the gate
actually fires in production. A SOVEREIGN badge means the declarations exist and crosswalk
cleanly; whether the running system honors them is exactly what a static tool cannot see.
This is stated on every artifact: the verbatim `CONFIRM_NOTE` from
`openagentontology/crosswalk.py` rides on every ontology, summary, and receipt
(`tests/test_crosswalk.py::test_confirm_note_is_present_ascii_and_disciplined`).

### N2. It does not prove legal compliance

A mapping to EU AI Act Article 14 or NIST 800-53 AC-5 is a confidence-tagged engineering
crosswalk, not a legal determination. Control text changes, enterprise tailoring differs,
and only your GRC and legal teams can assert compliance for audit. The tool says so on
every run: "Confirm against the current published control text before relying on them for
audit. Enterprise control ids are mapped at onboarding by your GRC team, never
auto-asserted" (`CONFIRM_NOTE`, `openagentontology/crosswalk.py`).

### N3. It does not prove an agent is safe

The Trust Profile scores *governance declaration posture*, not behavior. As the scorer's
own docstring puts it, a high score means the tool actually FOUND well-established controls
covering the agent's high-risk actions, "not that the agent is 'good'"
(`openagentontology/trust_profile.py`). A well-governed agent can still be wrong, biased,
or compromised at runtime; an ungoverned agent can be harmless. The score measures whether
anyone wrote the governance down in machine-readable form.

### N4. It does not see unsupported dynamic tool registration

Extraction covers decorators, verb-named functions, and declarative manifests. Tools
registered at runtime -- a `list_tools()` handler that builds its list dynamically, plugins
fetched over the network, reflection-driven registries -- are invisible to a static pass,
so such agents under-extract. This is documented with a concrete case (the MCP reference
servers) in the "Honest limitations" section of `docs/real-world-scan.md`. A scan of a
dynamically-registering agent is a lower bound on its action surface, never an inventory.

### N5. The ten canonical reasons are not claimed to be complete

`ASSERTED_TABLE` in `openagentontology/crosswalk.py` contains exactly ten canonical
reasons (pinned by `tests/test_crosswalk.py::test_all_canonical_reasons_present`). They
cover the recurring deny semantics of financial, data, and change-control gates, not the
full space of governance intent. An action governed by a reason outside the ten is reported
honestly as ungoverned or heuristic-matched rather than force-fit onto the nearest table
row; extending the table is a versioned spec change, not a runtime guess.

### N6. Two real-world scans are not a population estimate

The scans of `open-interpreter` and `gpt-engineer` (`docs/real-world-scan.md`) are two
reproducible data points chosen for visibility, not a sample. They support the claim "these
two widely-used agents carry no asserted control mappings in their source at the pinned
commits" and nothing broader. No rate, percentage, or industry-wide conclusion about agents
in general is claimed or should be inferred from n=2.

### N7. Projected remediation is not runtime enforcement

CWN AgentFDE (`openagentontology/fde.py`) generates a governance manifest and policy stub,
re-scans the *generated* manifest, and reports the tier jump. That after-state is
PROJECTED: the receipt it mints carries the decision string `FDE_REMEDIATION_PROJECTED`,
and the handoff report says the receipt covers "the projected state". The projection
becomes real only when the generated gates are wired into the runtime and the live system
is re-scanned. Pinned by `tests/test_fde.py::test_fde_receipt_verifies_offline` and the
artifact contract in `tests/test_fde.py::test_fde_onboard_improves_tier_and_emits_artifacts`.

---

*OpenAgentOntology -- https://github.com/CWNApps/openagentontology --
https://agent-ontology.cyberwarriornetwork.com. No Receipt. No Trust.*
