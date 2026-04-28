# AGENTS.md — Unified agent entrypoint (OpenTide / AgentTide)

Canonical instructions for autonomous coding assistants working across **AgentTide** (this harness repository) and **OpenTide content** repositories. Pair with granular skills under **`.cursor/skills/<skill-name>/SKILL.md`** (`description` YAML frontmatter enables discovery similarly to broader [Agent Skill patterns](https://agentskills.io/skill-creation/best-practices)).

---

## Repository roles

| Context | Responsibility |
|---------|----------------|
| **AgentTide (`OpenTideHQ/AgentTide`)** | Maintain **AGENTS.md**, pointer stubs (**`CLAUDE.md`**, **`GEMINI.md`**), reusable skills. Treat substantive harness alterations like product code — **merge via reviewed pull requests** unless admins explicitly bootstrap or hotfix **`main`**.|
| **Content repositories (`ShareTide`, tenants, clones)** | Produce **validated YAML objects**, respect CI, never mutate undelegated scaffolding (schemas/engine paths).|

When unclear which corpus you are editing — ask **before creating paths**.

---

## Prime directives

- **Correctness** — Treat intelligence fidelity and analytic literalness seriously.
- **Consistency** — Prefer adjusting related artefacts coherently over isolated one-offs.
- **Transparency** — Decisions surfaced in summaries / commit messages reviewers can consume.
- **Critical thinking** — Challenge weak analytic leaps—politely.
- **Autonomy when safe** — Drive tasks end-to-end when scope permits.

---

## Threat intelligence vs TVM authoring (explicit scoping rule)

Historical confusion would split unstructured intel triage and TVM authoring into sibling skills—a pattern that risks ambiguous triggers (“Are we brainstorming or emitting YAML?”). Consolidated practice here: everything that lands in a Threat Vector file flows through the **`opentide-threat-vector`** skill, separating **Phase A intelligence structuring** from **Phase B schema-backed YAML authoring** inside one skill lifecycle. Maintain one deliverable lineage from signal intake to **`tvm::…`** artefacts.

*(Progressive layering matches guidance that skills tie to deterministic deliverables whenever possible.)*

---

## Framework essentials (compact)

OpenTide models Threat Informed Detection Engineering as interoperable artefacts:

| Type | Typical schema tag | Responsibility |
|------|---------------------|----------------|
| **Threat Vector (TVM)** | `tvm::…` | Atomic TTP depiction, chaining, evidenced terrain narratives. |
| **Detection Objective (DOM)** | `dom::…` | Which signals realise coverage, methodological rigour, data contracts. |
| **Detection Rule (MDR)** | `mdr::…` | Deployable payloads per connected stack—**`configurations.*` blocks keyed by detector platform**.|

Always ingest **living templates** bundled with whichever repository syncs schemas—identifiers evolve.

Detection capability surfaces enumerated by CoreTide-aligned deployments routinely include **`sentinel`**, **`defender_for_endpoint`**, **`splunk`**, **`crowdstrike`**, **`carbon_black_cloud`**, **`sentinel_one`**—consult active meta-schema release notes whenever expanding beyond this catalogue.

---

## Default workflow

1. **TVM intake & modelling**
2. **DOM signalisation**
3. **MDR platform binding(s)**

Avoid mixing heterogeneous object edits in one merge unless explicitly orchestrated—the review surface stays sharper per object type otherwise.

---

## Query & platform skill routing

Microsoft stacks share **KQL** idioms (**`kusto-query-language`**), diverging operationally (**`microsoft-sentinel`** vs **`microsoft-defender-endpoint`**). Splunk adopts **SPL** (**`splunk-spl-processing`**). Endpoint / XDR SaaS integrations each carry authored guardrails (**`crowdstrike-falcon`**, **`sentinelone-singularity`**, **`carbon-black-cloud`**, **`harfanglab`**). Operational maturity spanning hunts→alerts leverages **`detection-engineering`** regardless of vendor.

Never invent vendor syntax—defer to sanctioned references or mirrored samples.

---

## Content repository guardrails (reiterate)

Unless explicitly commissioned:

- **Do not hand-edit schema templates/meta-registries blindly.**
- **Do not restructure authoritative folder layouts.**
- **Generate fresh UUID** values for genuinely new artefacts—reuse only when logically identical lineage persists.
- Prefer **British English** unless policy overrides downstream.

---

## Skills index (`AgentTide/.cursor/skills`)

| Skill | Purpose |
|-------|---------|
| `opentide-threat-vector` | Intel structuring + TVMs |
| `opentide-detection-objective` | DOM authoring |
| `opentide-detection-rule` | MDR authoring & platform bridging |
| `detection-engineering` | Cross-object sequencing & analytic operationalisation hygiene |
| `kusto-query-language` | Vendor-neutral advanced KQL for Microsoft Sentinel + Defender Advanced Hunting workloads |
| `microsoft-sentinel` | Sentinel / Log Analytics operational specifics atop KQL |
| `microsoft-defender-endpoint` | Defender for Endpoint specifics atop KQL |
| `splunk-spl-processing` | SPL for Splunk-centred artefacts |
| `crowdstrike-falcon` | CrowdStrike configuration guidance |
| `carbon-black-cloud` | Carbon Black Cloud Enterprise EDR guidance |
| `sentinelone-singularity` | SentinelOne Singularity guidance (non-Microsoft-sentinel!) |
| `harfanglab` | HarfangLab orb guidance |

Load the **narrowest** skill first — escalate outward when coordination demands.

---

## Cross-harness stubs

Primary knowledge lives here (**`AGENTS.md`**). Thin pointer files (**`CLAUDE.md`**, **`GEMINI.md`**) steer tools that insist on proprietary filenames toward this document.

---

## Git expectations

Bootstrap scenarios aside, **`main`** on `OpenTideHQ/AgentTide` retains **minimal** licensing/readme scaffolding — harness enrichment lands through **approved pull requests** so reviewers can deliberate without surprise history rewriting.
