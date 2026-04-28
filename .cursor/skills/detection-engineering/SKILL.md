---
name: detection-engineering
description: Orchestrates the OpenTide detection engineering lifecycle across TVM, DOM, and MDR—scope, sequencing, MR strategy, validation, and quality bars. Use when planning multi-phase detection work, deciding object order, or aligning content changes with CI and review expectations.
---

# Detection engineering (OpenTide lifecycle)

## Goal

Deliver **consistent, reviewable** changes across the OpenTide object graph without mixing unrelated scopes or violating repository guardrails.

## Default sequencing

1. **TVM first** — Threat model and atomic TTPs are the ground truth for what “could happen.”
2. **DOM second** — Express intent: what signals, on which entities, with what methodology and data availability.
3. **MDR last** — Executable or deployable artefacts bound to DOMs (and implicitly TVMs).

**One MR per object type** unless the user explicitly requests a vertical slice — reviewers triage cognitive load that way.

## Planning checklist

- [ ] Confirm **target repository** (content corpus vs harness).
- [ ] Search for **existing objects** to update instead of duplicate.
- [ ] List **UUIDs** that must remain stable on edit.
- [ ] Decide **minimal vertical slice**: which TVMs unblock which DOM signals.
- [ ] Identify **validation**: schema refs, linter, CI output path.

## Quality bar

- **Traceability**: Every DOM ties to evidenced threat material; every MDR ties to DOM intent.
- **Operability**: Data requirements field matches what the SOC can actually land in a log source.
- **Honesty**: Low-confidence detectors are labelled and tuned with tuning guidance, not hidden.

## Skills routing

| Task focus | Skill |
|------------|-------|
| TVM YAML | `opentide-threat-vector` |
| DOM YAML | `opentide-detection-objective` |
| MDR YAML | `opentide-detection-rule` |
| KQL for Sentinel | `kusto-query-language` |
| Sigma portability | `sigma-detection-rules` |
| TI ingest | `threat-intelligence-analysis` |

## Failure modes to avoid

- Creating DOMs **before** stabilising threat atomicity → duplicate signals and confused coverage maps.
- Writing **platform queries** before **signals** exist → orphaned logic.
- Editing **schemas or framework config** in a content repo without explicit approval.
