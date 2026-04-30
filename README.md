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

AgentTide skills work with any tool that supports the [Agent Skills specification](https://agentskills.io/specification). The cross-harness default location is **`.agents/skills/`** in your project root — most compatible agents discover skills there automatically.

Pick the method that suits your workflow:

### Option 1 — One-liner with `npx skills add` (easiest)

The community [`skills`](https://www.npmjs.com/package/skills) CLI can install skills directly from GitHub into `.agents/skills/`:

```bash
npx skills add OpenTideHQ/AgentTide
```

This copies the skill directories into your project. No git history, no submodules — just the files. Requires Node.js.

### Option 2 — Manual download (no tooling required)

Download the repository as a ZIP from GitHub and copy the `skills/` contents into your project:

```bash
# Download and extract
curl -sL https://github.com/OpenTideHQ/AgentTide/archive/refs/heads/main.tar.gz | tar xz

# Copy skills into the cross-harness default location
mkdir -p .agents/skills
cp -r AgentTide-main/skills/* .agents/skills/

# Optionally copy the AGENTS.md entrypoint
cp AgentTide-main/AGENTS.md .

# Clean up
rm -rf AgentTide-main
```

### Option 3 — Git submodule (stays in sync)

```bash
git submodule add https://github.com/OpenTideHQ/AgentTide.git .agents/AgentTide
```

This pins AgentTide to a specific commit. Update with `git submodule update --remote`. Most agents discover skills inside submodule directories automatically.

### Option 4 — Git clone as a sibling (for development)

```bash
git clone https://github.com/OpenTideHQ/AgentTide.git
```

Useful when you want to contribute back to AgentTide or keep it as a standalone reference alongside your OpenTide content repository.

---

### Harness-specific notes

Once the skills are in your project, most agents discover them automatically. Here are harness-specific details for the most popular tools:

<details>
<summary><strong>VS Code / GitHub Copilot</strong></summary>

VS Code discovers skills from `.agents/skills/` by default. If you used any of the installation methods above, skills are available immediately in Agent mode.

To also use the `AGENTS.md` as custom instructions:

```jsonc
// .vscode/settings.json
{
  "github.copilot.chat.codeGeneration.instructions": [
    { "file": "AGENTS.md" }
  ]
}
```

Verify skills are loaded: open Copilot Chat in Agent mode and type `/skills` to list discovered skills.

📖 [VS Code Agent Skills docs](https://code.visualstudio.com/docs/copilot/customization/agent-skills)

</details>

<details>
<summary><strong>Cursor</strong></summary>

Cursor discovers skills from `skills/` and `.agents/skills/` directories in your project root.

To also load `AGENTS.md` as project-level rules, copy or symlink it into `.cursor/rules/`:

```bash
mkdir -p .cursor/rules
cp AGENTS.md .cursor/rules/
```

📖 [Cursor Skills docs](https://cursor.com/docs/context/skills)

</details>

<details>
<summary><strong>Claude Code</strong></summary>

Claude Code discovers skills from `.claude/skills/` and `.agents/skills/`. It also reads `AGENTS.md` from the repository root automatically.

If you used the submodule approach, add AgentTide as an additional directory so Claude Code discovers its skills:

```bash
# Option A: symlink skills into Claude Code's path
ln -s .agents/AgentTide/skills .claude/skills

# Option B: reference in CLAUDE.md
echo "Read .agents/AgentTide/AGENTS.md for detection engineering instructions." >> CLAUDE.md
```

📖 [Claude Code Skills docs](https://code.claude.com/docs/en/skills)

</details>

<details>
<summary><strong>OpenAI Codex</strong></summary>

Codex reads `AGENTS.md` from the repository root and discovers skills in `agents/skills/` and `skills/` directories.

If you used the submodule approach, symlink the key paths:

```bash
ln -s .agents/AgentTide/AGENTS.md AGENTS.md
ln -s .agents/AgentTide/skills agents/skills
```

📖 [Codex Skills docs](https://developers.openai.com/codex/skills/)

</details>

<details>
<summary><strong>Gemini CLI</strong></summary>

Gemini CLI discovers skills from `.agents/skills/` in your project root — no extra configuration needed if you used Option 1, 2, or 3 above.

📖 [Gemini CLI Skills docs](https://geminicli.com/docs/cli/skills/)

</details>

<details>
<summary><strong>Junie (JetBrains)</strong></summary>

Junie discovers Agent Skills from `.agents/skills/` in your project root automatically.

📖 [Junie Skills docs](https://junie.jetbrains.com/docs/agent-skills.html)

</details>

<details>
<summary><strong>Other compatible agents</strong></summary>

The Agent Skills format is supported by a growing ecosystem of tools including [Goose](https://block.github.io/goose/), [Amp](https://ampcode.com/), [Roo Code](https://roocode.com/), [OpenHands](https://openhands.dev/), [Kiro](https://kiro.dev/), [OpenCode](https://opencode.ai/), and [many more](https://agentskills.io/clients).

The general pattern is:

1. Place skills in `.agents/skills/` (the cross-harness default) or the agent's preferred path.
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
