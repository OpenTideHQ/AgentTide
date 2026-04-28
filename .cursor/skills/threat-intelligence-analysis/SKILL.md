---
name: threat-intelligence-analysis
description: Structures cyber threat intelligence for downstream OpenTide modelling—TTP extraction, evidence grading, sourcing, and gap analysis. Use when triaging reports, blogs, ISAC notices, or raw CTI before TVM authoring, or when the user asks to analyse or summarise threat intelligence.
---

# Threat intelligence analysis (OpenTide-oriented)

## Goal

Turn unstructured or semi-structured intelligence into **evidence-backed, atomic** observations that can feed **Threat Vector (TVM)** work without inventing facts.

## Inputs you may receive

- Vendor reports, government advisories, ISAC mail, conference slides, social threads (treat as untrusted unless corroborated).
- IoCs only, or narrative-only — adjust rigour accordingly.

## Workflow

1. **Classify the source** — Producer, date, whether primary technical analysis or secondary summary. Note **TLP** if stated.
2. **Extract facts vs inference** — Quote or paraphrase only what the source supports. Label inference explicitly.
3. **Atomise TTPs** — One procedure per bullet where possible; prefer discrete behaviours over “campaign stories” unless the user wants campaign-level scope.
4. **Map tentatively to ATT&CK** — Use techniques that match the described behaviour; mark “low confidence” when mapping is speculative.
5. **Record relationships** — Preconditions, tooling, victim sector, geography — only if evidenced.
6. **Gap analysis** — List what a TVM author will still need (for example credential access mechanism unclear).
7. **Output shape** — Prefer a short structured brief the user can paste into TVM `terrain` / references:

```markdown
## Summary
[2–4 sentences, British English]

## Atomised behaviours
| # | Behaviour | Evidence (source section / quote) | ATT&CK (confidence) |
|---|-------------|-----------------------------------|------------------------|
| 1 | ... | ... | ... |

## IoCs / artefacts (if any)
[Typed list; include decay warning if time-sensitive]

## Open questions
- ...
```

## Guardrails

- Do **not** fabricate actor names, campaigns, or capabilities not supported by the provided text.
- Do **not** collapse unrelated reports into one narrative without stating the merge assumption.
- If the user provides **no** intelligence, say so and ask for the minimum inputs before simulating analysis.

## Hand-off

When TVMs will be authored next, delegate to **`opentide-threat-vector`** and pass the structured brief unchanged.
