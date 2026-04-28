---
name: opentide-threat-vector
description: Authors and refactors OpenTide Threat Vector (TVM) YAML aligned to tvm schema templates—terrain, chaining, ATT&CK, metadata, UUIDs. Use when creating or updating files under Threat Vectors or when the user asks about TVM modelling.
---

# OpenTide Threat Vector (TVM)

## Preconditions

1. Load the live **`Schemas/Templates`** TVM template and matching **JSON Schema** from the repo you edit (`tvm::*` ids vary by instance).
2. Confirm folder path conventions — commonly `Objects/Threat Vectors/*.yaml`.

## TVM anatomy (conceptual)

- **`metadata`** — `uuid`, `schema`, `version`, `created`, `modified`, `tlp`, optional authorship/org.
- **`threat`** — Core modelling: **`att&ck`**, **`terrain`** (narrative + technical grounding), **`severity`**, **`leverage`**, **`impact`**, **`viability`**, **`description`**.
- **Optional enrichments** — `chaining`, `cve`, `misp`, `surface`, `actors`, `killchain` — only when evidenced and needed.

## Authoring rules

- **UUID** — New TVMs get a **new** globally unique id; never reuse or guess.
- **`terrain`** — Concise, well-structured, evidence-backed; avoid essay-length block without user request.
- **Chaining** — Use when the repo already contains target vectors or the user will add them in a follow-up MR; avoid dangling references that fail validation.
- **ATT&CK** — List techniques that match described behaviour; prefer precision over spray.

## Validation before finish

- Required fields per schema version are present.
- Schema id in file matches the template family the repository uses.
- Internal references (chaining, related objects) resolve or are commented per local import guidance.

## Pair with

- Prior: `threat-intelligence-analysis`
- Next: `opentide-detection-objective` once TVMs are merged or agreed.
