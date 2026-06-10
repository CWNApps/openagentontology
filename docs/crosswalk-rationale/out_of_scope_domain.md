# out_of_scope_domain

One of the ten canonical reasons in `ASSERTED_TABLE`
(`openagentontology/crosswalk.py`). A mapping is ASSERTED only when the source names this
reason verbatim; the verb heuristic below yields INFERRED at best.

## Definition

The agent is reaching for a resource, system, or privilege level outside the scope it was
granted. The action verb may be benign in-scope; the violation is the TARGET: an admin
surface, another team's domain, an elevated role. Least privilege enforced at access time.

## Included action types

- Capabilities that touch admin interfaces, privileged APIs, or systems not named in the
  agent's grant.
- Tasks that elevate, escalate, or impersonate: privilege escalation, role assumption,
  sudo/root operations.
- Gates that pin an agent to an allowlist of in-scope resources or domains.
- Heuristic tokens (Layer 2, INFERRED only): `scope`, `domain`, `admin`, `privilege`,
  `elevate`, `escalate`, `impersonate`, `root`, `sudo`.

## Excluded action types (the boundary)

- A transaction too LARGE for the agent's grant is `over_threshold` -- amount of authority,
  not kind of resource.
- Data leaving the controlled boundary is `regulated_egress_blocked` -- where data goes,
  not what the agent may touch.
- Data too sensitive to handle is `classification_above_ceiling`.
- An unverified counterparty is `beneficiary_unverified` -- the other party's identity, not
  the agent's own authority.

## Primary controls (from ASSERTED_TABLE)

| Framework | Control | Name | Confidence |
|---|---|---|---|
| NIST SP 800-53r5 | AC-6 | Least Privilege | asserted |
| NIST SP 800-53r5 | AC-3 | Access Enforcement | asserted |
| OWASP LLM Top 10 (2025) | LLM06 | Excessive Agency | asserted |

## Advisory MITRE mapping

MITRE ATT&CK T1098 (Account Manipulation), advisory: reaching outside authorized scope maps
to account/privilege manipulation. Advisory mappings are informative and never counted
toward coverage or the badge.

## True positive

An infrastructure agent exposes `escalate_privilege(role)` so it can self-grant a broader
IAM role when a task fails. With a declared `reason: out_of_scope_domain` on the gate that
bounds it, the action resolves ASSERTED to AC-6 / AC-3 / LLM06; without the declaration the
verb `escalate` still surfaces it as INFERRED so the surface is never invisible.

## False positive

A marketing agent exposes `register_domain(name)` to buy DNS domains for campaign
microsites. The token `domain` fires the heuristic and proposes least-privilege scope
controls for what is actually a provisioning change (better declared as
`approval_required`). The result is INFERRED, labeled as a guess, and re-declared on
review.

## Test coverage

- Heuristic probe (`escalate_privilege`, never fabricates and never asserts):
  `tests/test_crosswalk.py::test_map_action_never_fabricates_a_framework_id`.
- Table integrity for its mappings (fully sourced, ASCII, asserted/advisory only):
  `tests/test_crosswalk.py::test_every_table_mapping_is_fully_sourced_and_ascii` and
  `tests/test_crosswalk.py::test_table_mappings_are_asserted_or_advisory_only`.
- Membership in the canonical ten:
  `tests/test_crosswalk.py::test_all_canonical_reasons_present`.
