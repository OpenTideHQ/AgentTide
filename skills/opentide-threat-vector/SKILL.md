---
name: opentide-threat-vector
description: Structures threat intelligence into evidence-backed behavioural atoms and authors OpenTide Threat Vector (TVM) YAML (tvm schemas), including metadata, terrain, chaining, ATT&CK, UUIDs. Use whenever work involves converting CTI into TVMs, creating or refactoring files under Threat Vectors, or when the user provides reports, feeds, or narratives before detection objectives exist.
---

# OpenTide Threat Vector (TVM)

## Why one skill handles both "intel" and "YAML"

Agent skill design works best when each skill matches a **deliverable** with a clear trigger, and sub-steps stay in one progressive flow ([Agent Skills authoring guidance](https://agentskills.io/skill-creation/best-practices)): split "TI analysis only" vs "TVM authoring" and the agent must guess which triggers apply to the same sprint. Threat Vector work is fundamentally **intel → structured hypothesis → validated TVM YAML** — keep upstream triage inside this skill under **Phase A**, then transition to **Phase B**.

---

## Phase A — Intelligence structuring (when non-TVM input exists)

Skip or shorten Phase A only when the user already handed you a definitive TVM brief or edits to an existing file.

### Workflow

1. **Source hygiene** — Producer, publication date, TLP/Risk markings. Treat rumours and unsourced summaries as lowest trust.
2. **Facts versus inference** — Quote or summarise only substantiated statements; label guesses explicitly.
3. **Atomisation** — Split composite reporting into observable procedures (installer ran, DLL loaded, C2 beacon, credential access, persistence). One primary behaviour candidate per bullet for TVM scoping conversations.
4. **ATT&CK mapping** — Map only where behaviour is clear; annotate low-confidence mappings.
5. **Gap checklist** — What is unknown (privilege achieved, tooling version, infra). Open questions block careless TVMs.

### Structured hand-off (paste into rationale / `terrain`)

```markdown
## Intelligence summary
[Brief factual summary, British English]

## Atomised behaviours
| # | Observable | Evidence cite | ATT&CK | Confidence |
|---|-------------|---------------|---------|-------------|
| 1 | ... | ... | ... | high/med/low |

## Gaps before modelling
- ...
```

Guardrails remain: no fabrication of sightings, IOCs, or attribution beyond the evidence supplied.

---

## Phase B — TVM YAML authoring

### Preconditions

1. Load live **`Schemas/Templates`** for TVM and **`Schemas/*.json`** for the tenant's tvm schema revision (for example `tvm::2.1`).
2. Confirm **`Objects/Threat Vectors/`** conventions in the corpus you edit.

### Authoring norms

- **UUID** — Fresh id per new TVM (`uuidgen` or equivalent). Never duplicate or collide.
- **`terrain`** — Concise narrative grounded in Phase A atoms; evidence belongs in **`references`** / structured fields—not unbounded speculative essays.
- **Chaining** — Only reference peer TVMs that exist or will ship in coordinated merges; avoid dangling relationships that fail validation pipelines.
- **ATT&CK** — Align catalogue entries with `threat.att&ck` entries and later DOM coverage narratives.

---

## Interaction with sibling skills

| Next step after TVM | Skill |
|---------------------|-------|
| Define detection intent / signals | `opentide-detection-objective` |
| Implement deployable artefacts | `opentide-detection-rule` + platform skills |

Never edit schemas, Templates, or engine configuration files unless explicitly directed.
