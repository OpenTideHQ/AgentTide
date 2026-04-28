---
name: sigma-detection-rules
description: Authors portable Sigma detection rules and maps them to OpenTide DOM signals and MDR artefacts for cross-platform reuse. Use when the user mentions Sigma YAML, portable rules, or converting between Sigma and SIEM-specific languages.
---

# Sigma detection rules (OpenTide-aware)

## Goal

Maintain **portable** detection logic that teams can translate to multiple backends while staying traceable to **DOM signals** and **MDR** deployment records.

## Sigma structure (reminder)

- **`title`**, **`id`**, **`status`**, **`level`**, **`description`**, **`author`**, **`date`**, **`references`**, **`logsource`**, **`detection`**, **`falsepositives`**, **`fields`**, **`tags`** (ATT&CK in `attack.*` form when used).

## Authoring rules

- **Logsource realism** — Category/product must match what organisations can actually collect.
- **Stable selections** — Prefer field names from Sigma’s common schema; document vendor-specific mappings in MDR or a sidecar table.
- **False positives** — Honest list; pair with tuning guidance.
- **Single concern** — Split mega-rules so converters and reviewers can reason per behaviour.

## Mapping to OpenTide

| Sigma | OpenTide |
|-------|----------|
| One detection idea | Often one **DOM signal** |
| Executable across stacks | Complements **MDR** `configurations.*` native blocks |
| `tags` / ATT&CK | Align with TVM **att&ck** and DOM coverage |

When both Sigma and native KQL exist for Sentinel, **describe precedence** in MDR `description` (Sigma as gold master vs native-only).

## Conversion notes

- **To KQL** — Use sanctioned converters or hand-craft — always **re-verify** semantics (aggregations differ).
- **From reports** — Extract atomic behaviours first (`threat-intelligence-analysis`), then Sigma, then SIEM specifics.

## Guardrails

- Never ship Sigma with placeholder `logsource` values that obscure where the rule applies.
- Version Sigma files when breaking selection changes occur — correlate with DOM/MDR version fields.
