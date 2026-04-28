# AgentTide

**AgentTide** hosts the shared **cross-harness** agent corpus for teams building on OpenTide:

- `AGENTS.md` — Canonical policies + workflow routing.
- `CLAUDE.md` / `GEMINI.md` — Thin stubs pointing agents at `AGENTS.md`.
- `.cursor/skills/*/SKILL.md` — Modular skills (YAML frontmatter) covering OpenTide objects (TVM/DOM/MDR), CoreTide-aligned platforms (**Microsoft Sentinel & Defender**, **Splunk**, **CrowdStrike Falcon**, **Carbon Black Cloud**, **SentinelOne**, **HarfangLab**), vendor-neutral **`kusto-query-language`** guidance shared across Microsoft KQL workloads, plus orchestrating **`detection-engineering`** discipline distilled from hardened internal DetectionOps practice (without organisational-specific assumptions).

Licence terms live in **`LICENSE`** (Creative Commons Attribution-ShareAlike 4.0 International).
