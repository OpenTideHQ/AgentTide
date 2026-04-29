<table align="center"><tr><td align="center" width="9999">
<img src="agenttide-logo.png" align="center" width="150" alt="Project icon">

# AgentTide

_The Open Source AI Agent Harness for OpenTide_

</td></tr></table>

## Agent-assisted Detection Engineering

**AgentTide** is the agent harness layer of the OpenTide family. It encodes the operational tribal knowledge required for autonomous coding assistants — Cursor, Claude Code, Codex, and any other tool that ingests `AGENTS.md` — to author, review, and operationalise detection content across the OpenTide framework. Where **CoreTide** is the engine and **ShareTide** is the shared content corpus, AgentTide is the **shared brain** for the agents that work alongside detection engineers.

### Features

- **Unified entrypoint** — a single `AGENTS.md` consumed by all major agent runners, no proprietary filename stubs to maintain
- **[Agent Skills](https://agentskills.io/specification)-compliant skill matrix** — each capability is a self-contained directory with `SKILL.md` + optional `references/`, discoverable via YAML frontmatter
- **OpenTide-native object authoring** — Threat Vectors, Detection Objectives, Detection Rules covered end-to-end
- **Hypothesis discipline** — ABLE framework, scoring, anti-pattern catalogues for hunt → detection conversion
- **Platform-tribal knowledge** — KQL operator hierarchy, Sentinel/Defender ResultType codes, NRT constraints, FileProfile null-handling, Storyline IDs, FQL vs CQL surface boundaries — all the things an LLM gets wrong without being told
- **Cross-harness compatible** — works the same in any tool that reads `AGENTS.md`

### Skill matrix

#### OpenTide content authoring
| Skill | Purpose |
|---|---|
| `opentide-threat-vector` | TVM authoring — intelligence structuring + schema-backed YAML |
| `opentide-detection-objective` | DOM authoring — signals, methodology, data contracts |
| `opentide-detection-rule` | MDR authoring + platform `configurations.*` bridging |

#### Detection engineering practice
| Skill | Purpose |
|---|---|
| `detection-engineering` | Cross-object sequencing, hunt-to-rule conversion, platform pairing, MR scope discipline |
| `threat-hunting` | ABLE framework, hypothesis scoring, archetypes, hunt → OpenTide content bridge |

#### Languages & platforms (CoreTide deployers)
| Skill | Platform |
|---|---|
| `kusto-query-language` | KQL — vendor-neutral language layer (+ Best-Practices, Hypothesis-Anti-Patterns references) |
| `microsoft-sentinel` | Microsoft Sentinel / Log Analytics (+ Anti-Patterns reference) |
| `microsoft-defender-endpoint` | Microsoft Defender for Endpoint Advanced Hunting (+ Anti-Patterns reference) |
| `splunk-spl-processing` | Splunk Enterprise / Enterprise Security |
| `crowdstrike-falcon` | CrowdStrike Falcon Insight + NG-SIEM + Custom IOA/IOC + Fusion + RTR |
| `carbon-black-cloud` | VMware Carbon Black Cloud Enterprise EDR |
| `sentinelone-singularity` | SentinelOne Singularity (NOT Microsoft Sentinel) |
| `harfanglab` | HarfangLab orb (Sigma + RHQL + YARA) |

### Quick start

1. Drop AgentTide into your repository as a sibling of your OpenTide content, or vendor it via submodule / sparse checkout.
2. Ensure your agent reads `AGENTS.md` from the repository root.
3. Skills are discovered automatically by tools that follow the [Agent Skills](https://agentskills.io/specification) spec — no further configuration required.
4. Pair with **[CoreTide](https://github.com/OpenTideHQ/CoreTide)** for the deployment engine and **[ShareTide](https://github.com/OpenTideHQ/ShareTide)** for community-shared content.

### Repository layout

```
AgentTide/
├── AGENTS.md                          # Unified agent entrypoint
├── skills/                            # Agent Skills directory
│   ├── opentide-threat-vector/SKILL.md
│   ├── kusto-query-language/
│   │   ├── SKILL.md
│   │   └── references/
│   │       ├── Best-Practices.md
│   │       └── Hypothesis-Anti-Patterns.md
│   └── ...
├── LICENSE                            # EUPL 1.2
└── README.md
```

### Contributing

Substantive changes to the harness — new skills, refactors, schema-affecting edits — land through reviewed pull requests against `main`. Skill content should be grounded in real production experience, not LLM-generated generalities. See [Agent Skills best practices](https://agentskills.io/skill-creation/best-practices) for authoring guidance, and the existing skills for the expected depth of tribal knowledge.

> If you would like to see a new platform, query language, or workflow covered, open an issue with concrete operational notes — vendor documentation links, real query examples, known gotchas — that we can shape into a skill.

### Licence

Distributed under the [European Union Public Licence v. 1.2](LICENSE) — the same licence used across the OpenTide project.
