# vendor_exit_drill

A sovereignty crosswalk entry documenting the provider-independence verification pattern
implemented by Trust Gate's `ExitDrillService`. This is not a deny-key reason; it is a
periodic evidence-producing drill that verifies the organization can operate without its
current AI provider.

## Definition

The exit drill is a scheduled verification that tests four independence capabilities:

1. **Local inference** -- an Ollama (or equivalent local) model can serve requests when the
   cloud provider is unavailable.
2. **Data export** -- all agent definitions, policy rules, and decision history can be
   exported to a portable format without provider cooperation.
3. **Signing key independence** -- the Ed25519 signing key used for receipts is held locally,
   not in a provider-managed HSM or KMS. The organization can continue minting receipts
   after disconnection.
4. **RAI availability** -- the responsible AI agent fleet can operate in degraded mode
   without cloud-hosted model access.

Each capability is tested, and the drill produces a receipt recording PASS or FAIL per
capability, with an overall PASS only if all four succeed.

## OAO mapping

| OAO construct | Instance | Relationship |
|---|---|---|
| Evidence | `exit_drill_receipt` | the signed receipt recording PASS/FAIL per capability |
| Outcome | `drill_verdict` | PASS (all four capabilities verified) or FAIL (at least one missing) |
| Task | `exit_drill_execution` | the scheduled drill task that exercises each capability |
| Resource | `local_inference`, `export_pipeline`, `signing_key`, `rai_fleet` | the four independence resources tested |

Graph pattern:

```
(Task:exit_drill_execution)-[:PRODUCES]->(Evidence:exit_drill_receipt)
(Evidence)-[:MAKES]->(Outcome:drill_verdict)
(Task)-[:OPERATES_ON]->(Resource:local_inference)
(Task)-[:OPERATES_ON]->(Resource:export_pipeline)
(Task)-[:OPERATES_ON]->(Resource:signing_key)
(Task)-[:OPERATES_ON]->(Resource:rai_fleet)
```

## Included action types

- Scheduled drill executions (daily, weekly, or on-demand).
- Provider failover tests where the primary LLM endpoint is intentionally unreachable.
- Export completeness checks that verify all portable artifacts can be reconstructed from
  local storage.
- Key rotation verifications that confirm the signing key is not provider-locked.

## Excluded action types (the boundary)

- Actual provider migration (switching from one cloud LLM to another in production) is an
  operational task, not a drill. The drill verifies the CAPABILITY to migrate, not the
  migration itself.
- Performance benchmarking of local vs. cloud inference is useful but separate; the drill
  checks availability, not latency.
- Business continuity planning documents are not evidence; the drill produces machine-
  verifiable receipts, not narrative reports.

## Rationale

Vendor independence is a claim that most organizations make but few verify. "We can switch
providers" is meaningless without evidence that the four prerequisites (local inference,
data export, key independence, RAI availability) actually work. The exit drill converts an
assumption into a receipt. This maps to NIST 800-53 CP-2 (contingency planning) and CP-4
(contingency plan testing) because the drill IS the contingency test, and the receipt IS
the evidence that the test ran. It also supports EU AI Act Art 15 (accuracy, robustness,
cybersecurity) by verifying that the system can maintain its safety properties after
provider disconnection.

## Primary controls

| Framework | Control | Name | Confidence |
|---|---|---|---|
| NIST SP 800-53r5 | CP-2 | Contingency Plan | advisory |
| NIST SP 800-53r5 | CP-4 | Contingency Plan Testing | advisory |
| NIST SP 800-53r5 | SA-9 | External System Services | advisory |
| EU AI Act | Art 15 | Accuracy, robustness and cybersecurity | advisory |

All advisory: the exit drill is a sovereignty verification mechanism, not a deny-key gate.
It produces evidence that contingency capabilities exist, supporting the controls listed
above. Asserted confidence would require the drill result to be a named deny-key reason in
a gate policy.

## Implementation reference

- Service: `ExitDrillService` (Trust Gate sovereignty wave 2)
- Drill targets: Ollama reachability, export pipeline completeness, Ed25519 key locality, RAI fleet degraded-mode
- Receipt: `{ drill_id, capabilities: { local_inference, export, signing_key, rai }, overall_verdict, timestamp }`
- Schedule: configurable, default weekly
