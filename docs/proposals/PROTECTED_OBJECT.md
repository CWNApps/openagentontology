# Proposal: `ProtectedObject` — object-level access in the Agent Ontology

> Status: **proposal.** Adds an optional, backward-compatible extension. No existing
> type, link, or action changes; ontologies that don't declare `ProtectedObject`
> validate unchanged. Spec: [`granular_access.yaml`](./granular_access.yaml).

## Why

The Agent Ontology answers *"what can this agent **do**, and which control answers for
each action?"* It does not yet answer the question every team deploying a
retrieval assistant (Copilot, Glean, RAG-over-your-docs) is now asking:

> *"My assistant retrieves across everything we own. Can it surface a paragraph the
> person who asked was never cleared to see?"*

That is **RAG oversharing**. The ontology is one type away from modeling it.

## What this adds

| New type | Extends | Role |
|---|---|---|
| `ProtectedObject` | `Resource` | the atomic unit access is decided on — paragraph / record / message body |
| `Principal` | `Actor` | a requester whose **clearance** bounds what it may retrieve |
| `Classification` | — | a **first-class node**: re-classification rewrites the node, not the object |
| `AccessDecision` | `Decision` | the per-object trustee verdict (allow / deny / escalate) — notarized |

New links: `HAS_OBJECT`, `CLASSIFIED_AS`, `CLEARED_FOR`, `REQUESTS`, `GATES_ACCESS`,
`DECIDES`, `NOTARIZED_BY`. New notarized actions: `gate_access`, `reclassify_object`.

Two design choices carry the weight:

1. **Classification is a node, not a tag.** A rule change marks every reachable
   object `stale=true` and re-scores it *in place* — access control becomes
   re-evaluable history, not config you overwrite. (NIST 800-53 AC-3/AC-4; EU AI Act Art 10.)
2. **Trustee-first, not filter-after.** The gate decides the visible set *before*
   retrieval; similarity runs only inside it. The model never reads what the
   requester can't see — the structural fix that "filter the results after RAG"
   cannot provide.

## Evidence it's real

The same methodology already runs in the open: the [Agent Governance Registry](https://agent-ontology.cyberwarriornetwork.com/docs/registry/)
scans real agents for control coverage, with signed, reproducible results. A
reference trustee-first audit applies these types to a synthetic tenant and
produces a signed report: a similarity-only retriever surfaces dozens of
paragraphs above the asker's clearance; trustee-first gating takes that to **zero**,
and each decision mints a receipt. Where an asset's confidentiality horizon is
long (harvest-now-decrypt-later range), the receipt is co-signed with a NIST PQC
algorithm (e.g. ML-DSA-65, FIPS 204) so the record outlives the data.

## Honesty contract

The `Classification.classifier` field records provenance (`keyword`, `embedding:<model>`, …)
so no implementation can claim "semantic classification" unless an embedding model
actually ran. Mappings are evaluated/proposed, not asserted-for-audit, consistent
with the rest of the ontology.

## Compatibility

Purely additive. PQ signing and trustee-first enforcement are an implementation
contract (`binding:` in the spec), not a change to the base ontology.
