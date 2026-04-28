---
name: opentide-detection-objective
description: Authors and refactors OpenTide Detection Objective (DOM) YAML—signals, methodology, entities, data requirements, and links toward TVMs. Use when working under Detection Objectives or when defining what to detect before writing MDRs.
---

# OpenTide Detection Objective (DOM)

## Preconditions

1. Load **`Schemas/Templates`** DOM template and **JSON Schema** (`dom::*`).
2. Identify **parent TVM(s)** in the same repo — search by name/uuid before creating parallel threat models.

## DOM anatomy (conceptual)

- **`metadata`** — Same discipline as TVM: uuid, schema, versioning, TLP, dates.
- **`objective`** — `priority`, `type` (for example Threat), **`description`**.
- **`objective.composition`** — `strategy` and narrative for how detection fits the threat story.
- **`objective.signals`** — The contract for MDR work:
  - `name`, `uuid`, `description`, `severity`, `methodology`
  - **`data`**: `availability`, `requirements` (and optional `logsources` when used)
  - **`entities`**: what the rule watches (users, hosts, identities, etc.)

## Authoring rules

- **One signal = one testable idea** — Split overloaded bundles so MDRs can map cleanly.
- **Data requirements** — State platform-agnostic facts (fields, cadence, retention), not just product names, unless the tenant standardises on them.
- **Coverage honesty** — If log availability is rare, say so in `data.availability` / requirements prose.

## Traceability

- Link TVMs in the fields your schema provides (for example `objective.threats` if present in your template version).
- Preserve signal **UUIDs** when editing unless intentionally superseding with user agreement.

## Pair with

- Prior: `opentide-threat-vector`
- Next: `opentide-detection-rule`
