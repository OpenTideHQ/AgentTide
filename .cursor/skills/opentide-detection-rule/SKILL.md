---
name: opentide-detection-rule
description: Authors and refactors OpenTide Detection Rule (MDR) YAML—descriptions, response metadata, and per-platform configurations linked to DOM signals. Use when writing deployable rules or mapping queries to Sentinel, Splunk, EDR, etc.
---

# OpenTide Detection Rule (MDR)

## Preconditions

1. Load **MDR template** and schema (`mdr::*`).
2. Confirm **DOM** and **signal UUIDs** you implement — avoid orphan rules.

## MDR anatomy (conceptual)

- **`metadata`** — uuid, schema, versioning, TLP — same hygiene as TVM/DOM.
- **`description`** — Operator-facing: what fires, benign cases, tuning knobs.
- **`response`** — `alert_severity`; optional playbook URLs, responders, investigative `procedure` blocks.
- **`configurations`** — Vendor-specific payloads (exact keys depend on tenant **Configurations/systems** — names like `sentinel`, `splunk`, `crowdstrike`, etc. follow project conventions).

## Authoring rules

- **Prefer binding to DOM signals** through the linkage fields your schema version provides (consult live template — do not invent fields).
- **Platform parity** — If only one SIEM exists, still document assumptions for others as comments or phased rollout notes when the user cares.
- **Low-confidence queries** — If detection logic is shaky, keep description honest; use `response.procedure.analysis` / searches to guide hunters.

### Query placement

Executable queries belong in **`configurations.<system>`** (or schema-defined sub-blocks), not in random YAML keys. For Sentinel, pair with **`kusto-query-language`**.

## Validation

- Schema compliance for all non-comment fields.
- UUID uniqueness.
- Severity and response metadata align with organisational standards if stated in repo docs.

## Pair with

- `kusto-query-language` for Microsoft Sentinel / Log Analytics.
- `sigma-detection-rules` when exporting or maintaining portable Sigma alongside MDR.
