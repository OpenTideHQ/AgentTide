<table align="center"><tr><td align="center" width="9999">
<img src="agenttide-logo.png" align="center" width="150" alt="AgentTide logo">

# AgentTide

_Open Source Agent Skills for Detection Engineering_

</td></tr></table>

**AgentTide** is the agent harness layer of the [OpenTide](https://github.com/OpenTideHQ) family. It packages the operational tribal knowledge that detection engineers carry — platform quirks, query-language gotchas, schema conventions, workflow discipline — into portable, version-controlled **[Agent Skills](https://agentskills.io)** that any compatible AI coding agent can load on demand.

Where **[CoreTide](https://github.com/OpenTideHQ/CoreTide)** is the engine and **[ShareTide](https://github.com/OpenTideHQ/ShareTide)** is the shared content corpus, AgentTide is the **shared brain** for the agents that work alongside you.

---

## What are Agent Skills?

[Agent Skills](https://agentskills.io) are an open standard for giving AI coding agents specialised knowledge. A skill is simply a folder containing a `SKILL.md` file with YAML frontmatter (`name`, `description`) and Markdown instructions, plus optional `references/`, `scripts/`, and `assets/` subdirectories.

```
kusto-query-language/
├── SKILL.md                        # Core instructions (loaded when activated)
└── references/
    ├── Best-Practices.md           # Loaded on demand
    └── Hypothesis-Anti-Patterns.md
```

**How they work:**

1. **Discovery** — at startup, the agent reads only the `name` and `description` of each skill (~100 tokens each). This is cheap and always-on.
2. **Activation** — when a task matches a skill's description, the agent loads the full `SKILL.md` body into context.
3. **Execution** — the agent follows the instructions, loading reference files or running scripts only when needed.

This means you can have dozens of skills available without bloating the agent's context window — it only loads what it needs, when it needs it.

> **Why not just paste documentation into the prompt?** Skills are version-controlled, shareable across teams, and work identically across every compatible agent product. Write once, use everywhere.

---

## What's in AgentTide?

### 27 skills across four categories

| Category | Skills | What they cover |
|----------|--------|-----------------|
| **OpenTide content authoring** | 3 | TVM, DOM, MDR object lifecycle — from intelligence intake to schema-valid YAML |
| **Detection engineering practice** | 3 | Hunt-to-rule conversion, ABLE hypothesis framework, ATT&CK v19 mapping |
| **Languages & platforms** | 14 | KQL, SPL, FQL/CQL, DVQL, Sigma/RHQL — plus platform-specific tribal knowledge for Sentinel, Defender for Endpoint, Splunk, CrowdStrike Falcon, Carbon Black Cloud, SentinelOne, HarfangLab, Entra ID, Okta, AWS, Azure, GCP, and Windows Event Logs |
| **Defensive internals** | 7 | Windows/Linux/macOS internals, Active Directory, identity providers, network protocols, email & collaboration |

See the [full skills index in AGENTS.md](AGENTS.md#skills-index-agenttideskills) for the authoritative list with descriptions.

### Unified `AGENTS.md`

A single `AGENTS.md` file at the repository root provides cross-cutting instructions consumed by all agent runners — prime directives, OpenTide framework essentials, workflow guidelines, guardrails, and the skills index. No proprietary filename stubs to maintain.

---

## Installation

AgentTide skills work with any tool that supports the [Agent Skills specification](https://agentskills.io/specification). Below are setup instructions for the most common harnesses.

### Step 1 — Get the skills into your project

Choose one of the following methods:

#### Git submodule (recommended)

```bash
git submodule add https://github.com/OpenTideHQ/AgentTide.git AgentTide
```

This keeps AgentTide pinned to a specific commit and updatable with `git submodule update --remote`.

#### Sparse checkout (skills only)

If you only want the `skills/` directory without the rest of the repository:

```bash
git clone --filter=blob:none --sparse https://github.com/OpenTideHQ/AgentTide.git
cd AgentTide
git sparse-checkout set skills
```

#### Manual copy

Download or clone the repository and copy the `skills/` directory (and optionally `AGENTS.md`) into your project.

---

### Step 2 — Configure your agent

<details>
<summary><strong>VS Code / GitHub Copilot</strong></summary>

VS Code discovers skills automatically from any `skills/` directory in your workspace. If you added AgentTide as a submodule or copied the `skills/` folder, they are available immediately.

To also use the `AGENTS.md` as custom instructions, add it to your workspace settings:

```jsonc
// .vscode/settings.json
{
  "github.copilot.chat.codeGeneration.instructions": [
    { "file": "AgentTide/AGENTS.md" }
  ]
}
```

📖 [VS Code Agent Skills documentation](https://code.visualstudio.com/docs/copilot/customization/agent-skills)

</details>

<details>
<summary><strong>Cursor</strong></summary>

Cursor discovers skills from `skills/` directories in your project root. If AgentTide is a submodule at `AgentTide/`, Cursor will find `AgentTide/skills/` automatically.

To also load the `AGENTS.md` as project-level rules, add it to your `.cursor/rules/` directory or reference it in your Cursor settings.

📖 [Cursor Skills documentation](https://cursor.com/docs/context/skills)

</details>

<details>
<summary><strong>Claude Code</strong></summary>

Claude Code reads `AGENTS.md` from the repository root automatically. For skills, it discovers `SKILL.md` files in `skills/` directories.

If AgentTide is a submodule, symlink or copy the `AGENTS.md` to your project root:

```bash
# Option A: symlink
ln -s AgentTide/AGENTS.md AGENTS.md

# Option B: reference in CLAUDE.md
echo "Read AgentTide/AGENTS.md for detection engineering instructions." >> CLAUDE.md
```

📖 [Claude Code Skills documentation](https://code.claude.com/docs/en/skills)

</details>

<details>
<summary><strong>OpenAI Codex</strong></summary>

Codex reads `AGENTS.md` from the repository root and discovers skills in `skills/` directories.

If AgentTide is a submodule, symlink the key files:

```bash
ln -s AgentTide/AGENTS.md AGENTS.md
ln -s AgentTide/skills skills
```

📖 [Codex Skills documentation](https://developers.openai.com/codex/skills/)

</details>

<details>
<summary><strong>Gemini CLI</strong></summary>

Gemini CLI discovers skills from `skills/` directories in your project.

```bash
# If AgentTide is a submodule, symlink the skills directory
ln -s AgentTide/skills skills
```

📖 [Gemini CLI Skills documentation](https://geminicli.com/docs/cli/skills/)

</details>

<details>
<summary><strong>Other compatible agents</strong></summary>

The Agent Skills format is supported by a growing number of tools including Goose, Junie (JetBrains), Amp, Roo Code, OpenHands, Kiro, and many more. See the [full client showcase](https://agentskills.io/clients) for setup links.

The general pattern is:

1. Place the `skills/` directory where your agent can discover it (usually the project root).
2. If the agent reads `AGENTS.md`, place or symlink it at the project root.
3. Skills are discovered automatically — no further configuration required.

</details>

---

## Repository layout

```
AgentTide/
├── AGENTS.md                          # Unified agent entrypoint
├── skills/                            # Agent Skills directory
│   ├── opentide-threat-vector/
│   │   └── SKILL.md
│   ├── kusto-query-language/
│   │   ├── SKILL.md
│   │   └── references/
│   │       ├── Best-Practices.md
│   │       └── Hypothesis-Anti-Patterns.md
│   ├── microsoft-sentinel/
│   │   ├── SKILL.md
│   │   └── references/
│   │       └── Anti-Patterns.md
│   └── ...                            # 27 skills total
├── LICENSE                            # EUPL 1.2
└── README.md
```

---

## The OpenTide ecosystem

AgentTide is one part of a three-layer architecture:

| Layer | Repository | Role |
|-------|-----------|------|
| **Engine** | [CoreTide](https://github.com/OpenTideHQ/CoreTide) | Schema validation, object indexing, CI/CD pipelines for detection-as-code |
| **Content** | [ShareTide](https://github.com/OpenTideHQ/ShareTide) | Community-shared `TLP:CLEAR` OpenTide objects — threat vectors, detection objectives, detection rules |
| **Agent harness** | **AgentTide** (this repo) | Agent Skills and instructions that teach AI assistants how to author, review, and operationalise detection content |

---

## Contributing

Substantive changes to the harness — new skills, refactors, schema-affecting edits — land through reviewed pull requests against `main`. Skill content should be grounded in real production experience, not LLM-generated generalities.

**Want to contribute a skill?**

1. Read the [Agent Skills specification](https://agentskills.io/specification) and [best practices](https://agentskills.io/skill-creation/best-practices).
2. Study existing skills in this repository for the expected depth of tribal knowledge.
3. Create a new directory under `skills/` with a `SKILL.md` containing YAML frontmatter and Markdown instructions.
4. Open a pull request with a clear description of what the skill covers and why.

**Want to request a skill?**

Open an issue with concrete operational notes — vendor documentation links, real query examples, known gotchas — that we can shape into a skill.

---

## Licence

Distributed under the [European Union Public Licence v. 1.2](LICENSE) — the same licence used across the OpenTide project.
