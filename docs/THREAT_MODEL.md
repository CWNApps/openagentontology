# Threat model

What OpenAgentOntology protects, who attacks it, where the trust boundaries sit, and --
verified against the actual `receipt.py` behavior -- exactly what happens when someone
tampers with a receipt. Companion to [CLAIMS_AND_NON_CLAIMS.md](./CLAIMS_AND_NON_CLAIMS.md):
that file says what we claim, this one says what an adversary can and cannot do about it.

Every verification outcome in the tampering table below was produced by running
`openagentontology.receipt.verify_receipt` against the committed receipt
`docs/scans/open-interpreter/receipt.json` with the stated modification applied. Reproduce
any row with the commands in [REPRODUCIBILITY.md](./REPRODUCIBILITY.md).

---

## Protected assets

1. **The evidence** -- the deterministic ontology (nodes, edges, action_maps, frameworks,
   note) plus its summary header. This is what the receipt's `evidence_hash` commits to.
2. **The verdict** -- the trust tier and score, carried in the signed body's `decision`
   string and derivable from the evidence.
3. **The asserted/inferred line** -- the confidence and provenance tags that separate
   source-declared governance from heuristic guesses. Inflating `inferred` to `asserted`
   is the core forgery this tool exists to make detectable.
4. **The signature legs and the signing key** -- Ed25519 always; ML-DSA-65 (FIPS 204) and
   SLH-DSA (FIPS 205) when the post-quantum extra is installed. The private key lives at
   `~/.openagentontology/receipt_ed25519.pem` (or `OAO_RECEIPT_KEY`).
5. **The scan host** -- the machine running the scan must not be compromised by the code
   being scanned.
6. **The canonical crosswalk** -- the integrity of `ASSERTED_TABLE` and
   `ALLOWED_FRAMEWORKS` in `openagentontology/crosswalk.py`, from which every legitimate
   asserted id derives.

## Attacker goals

- **Grade inflation**: edit a committed receipt or scan artifact so an UNGOVERNED agent
  reads as HARDENED or SOVEREIGN.
- **Compliance fabrication**: smuggle an invented control id (an `AC-99`) or an
  auto-asserted mapping into evidence that auditors will rely on.
- **Receipt forgery**: present a tampered receipt that still verifies, or strip its
  signatures and hope the verifier does not notice the downgrade.
- **Scan-host compromise**: craft a malicious repository so that *scanning* it executes
  attacker code.
- **Heuristic gaming**: name actions so the verb heuristics paint a flattering picture, or
  hide the dangerous surface behind dynamic registration.
- **Hosted-layer poisoning**: corrupt the graph-grounded candidates returned by the CWN
  Graph Model Service (hosted) so bad recommendations flow into human decisions.

## Trust boundaries

1. **Target source -> ingest.** The scanned repo is fully untrusted input. It is parsed as
   text, AST, or data only (`openagentontology/ingest.py`); it is never imported, executed,
   or evaluated, oversized files are skipped, and malformed input degrades to an
   empty-but-valid record. Crossing this boundary moves bytes, never control flow.
2. **Pipeline -> receipt.** The deterministic ontology becomes hashed evidence;
   `sha256(canon(evidence))` is committed into a small signed body
   (`openagentontology/receipt.py`). After signing, every byte of evidence is
   tamper-evident.
3. **Receipt -> verifier.** Verification needs only the receipt itself: recompute the hash,
   check each signature leg against the embedded public keys. No network, no database, no
   trusting CWN. The verifier may be on a different host, in a different language.
4. **OSS scanner <-> CWN Graph Model Service (hosted).** The offline scanner never calls
   the service. When the service is used, its output is a *separate*, clearly-labeled
   artifact (e.g. `docs/scans/open-interpreter/graph_resolutions.json`) whose candidates
   are GRAPH_INFERRED and `human_review_required` -- they do not enter the local scan's
   signed evidence and cannot become asserted without a source declaration or a confirmed
   human record.
5. **Key custody.** Whoever holds the signing key can mint receipts as that identity. The
   receipt proves integrity and key custody, not the honesty of the operator who ran the
   scan.

## What OAO prevents

- **Post-hoc evidence editing.** Any change to the evidence -- one node name, one summary
  count, one confidence tag -- breaks `evidence_hash` and verification fails closed.
- **Verdict swapping.** The `decision` string is inside the signed body; changing it
  invalidates every signature leg simultaneously.
- **Fabricated asserted ids inside a valid ontology.** `map_action` cannot construct ids,
  and `validate.py` fails closed (`E_FAKE_ID`, `E_FRAMEWORK`) on any asserted `(fw, id)`
  pair not present in `ASSERTED_TABLE`. A fabrication-tainted ontology earns no badge.
- **Execution of scanned code.** Proven mechanically by
  `tests/test_ingest.py::test_python_is_parsed_not_executed`.
- **Silent downgrade-by-guess.** Heuristic matches are tagged `inferred` or `ambiguous`
  and the badge counts asserted controls only, so verb-gaming cannot inflate the headline.
- **Harvest-now-forge-later.** With the post-quantum legs present, forging a stored receipt
  after a future break of Ed25519 still requires defeating ML-DSA-65 and SLH-DSA over the
  same bytes; a verifier that can check any surviving leg still proves authenticity, and a
  broken leg is reported as tamper.

## What OAO does NOT prevent

- **A dishonest operator scanning doctored source.** Re-minting a fresh receipt over a
  cleaned-up copy of the repo produces a *valid* receipt of the doctored input. The receipt
  binds the evidence to the scan, not the scan to the true upstream; bind it yourself by
  scanning pinned commits and publishing the hash, as in `docs/real-world-scan.md`.
- **Runtime divergence.** A declared gate that is never deployed scans identically to one
  that is enforced. See non-claim N1.
- **Key theft.** An attacker holding your signing key signs as you. Protect the key file;
  rotate by re-minting.
- **Receipt suppression.** Nothing stops an operator from deleting an unflattering receipt.
  Absence of a receipt is the signal: "No Receipt. No Trust."
- **Dynamic registration blind spots.** See the dedicated section below.
- **Signature stripping, if the verifier is careless.** See scenario 3 in the table -- the
  verifier API reports the downgrade honestly, but a consumer that ignores the `signed`
  flag can be fooled.

## Receipt tampering scenarios (verified against receipt.py)

Each scenario was executed against the committed triple-signed receipt
`docs/scans/open-interpreter/receipt.json` on a host with both PQ backends installed.
`verify_receipt` returns `{ok, hash_ok, sig_ok, signed, legs, reason}`.

| # | Scenario | Verified outcome |
|---|----------|------------------|
| 1 | **Evidence edit** -- inflate `evidence.summary.asserted_covered` from 0 to 21 | `ok=False, hash_ok=False`. Fails before any signature is even checked. `reason: "evidence_hash mismatch -- evidence was altered"` |
| 2 | **Body edit** -- change `decision` to `GOVERNED:SOVEREIGN`, leave evidence intact | `ok=False, hash_ok=True`. All three legs fail at once because every leg signed the old body: `legs={ed25519: fail, ml_dsa: fail, slh_dsa: fail}`, `reason: "signature verification FAILED on: ed25519, ml_dsa, slh_dsa"` |
| 3 | **Signature strip** -- blank all three `*_signature_b64` fields | `ok=True, hash_ok=True, sig_ok=False, signed=False`, all legs `absent`, `reason: "hash valid; receipt is UNSIGNED (no signature present)"`. The receipt degrades to an integrity-only artifact and SAYS SO. **Verifier obligation**: any consumer that needs authenticity (not just integrity) MUST require `signed` and `sig_ok` to be true. This reporting is pinned by `tests/test_receipt.py::test_unsigned_receipt_is_hash_valid_but_flagged`. Stripping only SOME legs does not help an attacker: with the Ed25519 leg removed the PQ legs still verify (`legs={ed25519: absent, ml_dsa: ok, slh_dsa: ok}`, `ok=True`) |
| 4 | **Corrupt one leg** -- flip one byte of the ML-DSA-65 signature | `ok=False, hash_ok=True, sig_ok=True` (other legs verify) but the broken leg is reported as tamper, never ignored: `legs={ed25519: ok, ml_dsa: fail, slh_dsa: ok}`, `reason: "signature verification FAILED on: ml_dsa"`. "Any leg verifies" proves authenticity only when NO leg fails |
| 5 | **Wrong public key** -- swap `verify_pubkey_b64` for another valid Ed25519 key | `ok=False`. The Ed25519 leg fails against the substituted key while the untouched PQ legs still verify: `legs={ed25519: fail, ml_dsa: ok, slh_dsa: ok}`, `reason: "signature verification FAILED on: ed25519"` |
| 6 | **Fake control injection** -- insert an `asserted` NIST 800-53 AC-5 mapping into an ungoverned action inside the evidence | `ok=False, hash_ok=False`, `reason: "evidence_hash mismatch -- evidence was altered"`. And even at scan time the same forgery cannot enter a fresh receipt as a *fabricated* id: `validate.py` fails closed with `E_FAKE_ID` on any asserted pair outside `ASSERTED_TABLE` |

Note on key substitution (scenario 5): a sophisticated attacker would re-sign the tampered
body with their own key AND swap in their own public key, producing an internally-consistent
receipt. That receipt verifies -- as the attacker's. Cross-key identity is out of scope for
the cert-only OSS verifier; pin the expected `verify_pubkey_b64` (publish it, as this repo
does in its committed scans) or use a registry that binds keys to identities.

## Dynamic-registration blind spots

Static extraction sees decorators (`@tool`, `@function_tool`, `@tool_node`,
`@kernel_function`), verb-named functions, and declarative manifests. It does NOT see:

- tool lists built at runtime inside a `list_tools()` handler (the MCP reference-server
  pattern -- the concrete under-extraction case documented in
  [real-world-scan.md](./real-world-scan.md));
- plugins or tool definitions fetched over the network after start-up;
- reflection-driven registries that assemble capabilities from configuration or a database;
- capabilities delegated to a sub-agent whose source is not in the scanned tree.

Consequence: a scan is a lower bound on the action surface. An adversary (or just an
inconvenient architecture) can hide side-effecting capability behind any of the above and
the scan will not list it. Mitigations: declare tools statically where possible, ship an
MCP manifest or agent definition next to the code so the surface is declarable, scan the
deployment configuration as well as the source, and treat "this agent registers tools
dynamically" as itself a governance finding requiring human review.

## Hosted-layer (graph model) poisoning considerations

The CWN Graph Model Service (hosted) returns graph-grounded candidate resolutions for
unresolved actions; like any enrichment service, its outputs could in principle be degraded
by poisoned inputs upstream or a compromised channel, so consume them defensively.
Recommendations: treat every candidate as advisory and keep the GRAPH_INFERRED label and
`human_review_required` flag attached end-to-end; never let a graph candidate set
`confidence: asserted` (the OSS validator's `E_FAKE_ID` / `E_FRAMEWORK` gates enforce this
for anything entering signed evidence, and assertion requires a source-declared canonical
reason or a confirmed human governance record); pin and record the service's `gms_version`
and `graph_snapshot_hash` fields so a recommendation can be traced to the exact graph state
that produced it; verify the signed receipt that accompanies the service's output the same
way you verify a scan receipt; and require that threat signals are retrieved from named
sources (e.g. NVD-derived records with CVE ids), never generated, before showing them to a
human. If any of those checks fails, discard the enrichment and fall back to the offline
scan, which is deterministic and self-contained.

---

*OpenAgentOntology -- https://github.com/CWNApps/openagentontology --
https://agent-ontology.cyberwarriornetwork.com. Logs explain. Receipts prove.*
