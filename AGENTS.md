# AGENTS.md — Unified agent entrypoint (OpenTide / AgentTide)

This file is the **canonical** instruction set for coding agents working with **OpenTide** (Open Threat Informed Detection Engineering) and related detection-as-code workflows. It is designed to be usable across harnesses that read `AGENTS.md` (including Cursor Agent, Claude Code-style runners, Codex hooks, and other tools that ingest repository-level prompts).

Companion material lives under **`.cursor/skills/`** — each skill is an **AgentSkills-style** bundle (`SKILL.md` + optional references). Prefer loading the relevant skill when the task narrows (for example `kusto-query-language` before writing Sentinel queries).

---

## Repository role: AgentTide vs content repositories

| Context | Your job |
|--------|----------|
| **This repo (AgentTide)** | Maintain and extend the harness: `AGENTS.md`, skills, cross-harness stubs. Follow normal software change hygiene (PRs for substantive harness updates unless doing one-off setup). |
| **An OpenTide content repo** (for example ShareTide, or a private tenant corpus) | Author and validate **YAML objects** only in allowed paths; never alter framework engine code, schemas, or config unless the user explicitly instructs you. |

When in doubt, ask which repository is the **content** target before creating or moving files.

---

## Prime directives (inherited from OpenTide practice)

- **Correctness** — Be exact when decomposing intelligence into modelled OpenTide data and when writing detection logic.
- **Consistency** — Prefer updating several related objects to preserve a coherent model over adding isolated files.
- **Transparency** — Rationalise decisions; make changes discoverable in diffs and summaries.
- **Critical thinking** — Avoid vague conclusions; push back politely when modelling or logic is unsound.
- **Autonomy** — Prefer end-to-end help (from intelligence → objects → validation → PR) when scope allows.

---

## OpenTide framework concepts (minimum viable model)

OpenTide structures the detection engineering lifecycle as **versioned YAML objects** in git. In reference corpora there are three core object types:

### 1. Threat Vectors (TVM)

- **Purpose**: Atomically defined TTPs (low level), derived from intelligence.
- **Chaining**: TVMs may reference one another to represent attack paths.
- **Typical schema id**: `tvm::2.1` (verify in the active repo’s templates).
- **Typical location**: `Objects/Threat Vectors/*.yaml`

### 2. Detection Objectives (DOM)

- **Purpose**: What to detect — signals, methodology, entities, data requirements — linked to threats.
- **Relations**: Flexible 1:N / N:1 between TVMs and DOMs depending on modelling choices.
- **Typical schema id**: `dom::1.0` (verify in the active repo’s templates).
- **Typical location**: `Objects/Detection Objectives/*.yaml`

### 3. Detection Rules (MDR)

- **Purpose**: Deployable detection-as-code linked to DOMs (and indirectly to TVMs).
- **Targets**: Platform-specific blocks (for example Sentinel KQL, Splunk SPL, EDR vendors) live under the object’s `configurations` per tenant setup.
- **Typical schema id**: `mdr::2.1` (verify in the active repo’s templates).
- **Typical location**: `Objects/Detection Rules/*.yaml`

Always **open the live templates and JSON Schemas** in the repository you are editing — field names and required blocks evolve with the framework.

---

## Top-down workflow (default)

1. From **intelligence** → derive or refine **Threat Vectors** (`threat-intelligence-analysis` skill, then `opentide-threat-vector` skill).
2. From **TVMs** → define **Detection Objectives** (`opentide-detection-objective` skill).
3. From **DOMs** → implement **Detection Rules** (`opentide-detection-rule` skill; use `kusto-query-language` or `sigma-detection-rules` as needed).

Per run, **avoid mixing object types** unless the user explicitly wants a vertical slice — the intended review path is usually one merge request per object type.

---

## Guardrails for OpenTide **content** repositories

**Content and structure**

- Do **not** create new top-level folders or restructure the repository unless the user asks.
- Do **not** modify **schemas**, **templates**, or **framework configuration** unless explicitly instructed.
- **Do** validate YAML against the repo’s JSON Schemas before considering work complete.
- **Do** generate **new UUIDs** for new objects (`uuidgen` / equivalent) and never duplicate existing ids.

**Evidence and hallucination**

- Use **provided intelligence and in-repo YAML** as primary sources — not model pretraining — for factual threat claims.
- When intelligence is insufficient, **stop** and propose a plan or questions instead of inventing sightings.

**Authoring style**

- Default to **British English** for prose fields unless the project specifies otherwise.
- Keep TVM `terrain` sections informative but **concise** — avoid unbounded narrative.
- For detection queries: prefer **high-confidence** executable logic; otherwise use **pseudocode** or comments and call out uncertainty.

---

## Skills index (this repository)

| Skill directory | Use when |
|-----------------|----------|
| `threat-intelligence-analysis` | Structuring CTI, triage, TTP extraction, evidence grading before TVM work. |
| `detection-engineering` | Lifecycle orchestration, MR/PR strategy, quality bars across TVM → DOM → MDR. |
| `opentide-threat-vector` | Authoring or refactoring TVM YAML against templates. |
| `opentide-detection-objective` | Authoring or refactoring DOM YAML, signals, data requirements. |
| `opentide-detection-rule` | Authoring or refactoring MDR YAML and platform configurations. |
| `kusto-query-language` | Microsoft Sentinel / Log Analytics queries and performance-minded patterns for MDR. |
| `sigma-detection-rules` | Portable Sigma rules and mapping to DOM/MDR concepts. |

**How to use skills:** At the start of a focused task, read `SKILL.md` for the narrowest skill that applies. Escalate to `detection-engineering` when coordinating multi-object changes.

---

## Cross-harness compatibility

| File | Purpose |
|------|---------|
| `AGENTS.md` (this file) | Canonical rules and framework summary. |
| `CLAUDE.md` | Pointer for tools that assume `CLAUDE.md`; keep it thin. |
| `GEMINI.md` | Pointer for tools that assume `GEMINI.md`; keep it thin. |
| `.cursor/skills/*/SKILL.md` | Cursor AgentSkills-compatible skill bodies. |

Do not duplicate long policy text across pointer files — update **`AGENTS.md`** and keep pointers one paragraph.

---

## Git and review expectations

- **Substantive harness changes** (skills, AGENTS.md, automation): use a **pull request** with a clear description unless the operator requests a direct push (for example initial repository bootstrap).
- **Content repos**: one logical change-set per MR when possible; never batch unrelated object types without user agreement.

---

**Remember:** In content repositories, your goal is a **correct, validated, navigable corpus** of OpenTide objects that teams can deploy and reason about — not voluminous speculative threat fiction.
