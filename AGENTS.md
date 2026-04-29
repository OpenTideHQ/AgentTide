# AGENTS.md — Unified agent entrypoint (OpenTide / AgentTide)

Canonical instructions for autonomous coding assistants working across **AgentTide** (this harness repository) and **OpenTide content** repositories. Pair with granular skills under **`skills/<skill-name>/SKILL.md`** following the [Agent Skills specification](https://agentskills.io/specification) — each `SKILL.md` carries YAML frontmatter (`name`, `description`) for discovery, with optional `references/`, `assets/`, and `scripts/` subdirectories.

---

## Repository roles

| Context | Responsibility |
|---------|----------------|
| **AgentTide (`OpenTideHQ/AgentTide`)** | Maintain **AGENTS.md** and reusable skills. Treat substantive harness alterations like product code — **merge via reviewed pull requests** unless admins explicitly bootstrap or hotfix **`main`**.|
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

## Skills index (`AgentTide/skills`)

### OpenTide content authoring
| Skill | Purpose |
|---|---|
| `opentide-threat-vector` | TVM authoring — Phase A intelligence structuring + Phase B schema-backed YAML |
| `opentide-detection-objective` | DOM authoring — signals, methodology, data contracts |
| `opentide-detection-rule` | MDR authoring + platform `configurations.*` bridging |

### Detection-engineering practice
| Skill | Purpose |
|---|---|
| `detection-engineering` | Cross-object sequencing, hunt-to-rule conversion (7-step), platform pairing matrix, maturity progression, PR scope discipline |
| `threat-hunting` | Hypothesis discipline (ABLE), confidence/relevance/priority scoring, archetypes, data-gap analysis, hunt → OpenTide content conversion |
| `mitre-attack-mapping` | ATT&CK technique/sub-technique selection, tactic assignment, version pinning, revocation handling, coverage analysis |

### Languages & platforms
| Skill | Purpose |
|---|---|
| `kusto-query-language` | Vendor-neutral KQL — operator hierarchy, joins, FP engineering, anti-patterns (+ `references/Best-Practices.md`, `references/Hypothesis-Anti-Patterns.md`) |
| `microsoft-sentinel` | Sentinel / Log Analytics specifics — table domain matrix, ResultType codes, NRT vs scheduled rules, ASIM, TI patterns (+ `references/Anti-Patterns.md`) |
| `microsoft-defender-endpoint` | Defender Advanced Hunting specifics — Device*/Email* schemas, mandatory output columns, FileProfile, AdditionalFields, NRT constraints (+ `references/Anti-Patterns.md`) |
| `entra-id-protection` | Entra ID identity-attack detection — sign-in/user risk, SKU gating, ResultType codes, AiTM/MFA fatigue/OAuth abuse patterns (+ `references/ResultType-Codes.md`) |
| `windows-event-logs` | Windows native event IDs (Security/Sysmon/PowerShell), audit policy prerequisites, platform table mapping (+ `references/Audit-Policy-Matrix.md`) |
| `splunk-spl-processing` | SPL for Splunk Enterprise / ES — index/sourcetype discipline, stats vs tstats vs mstats, accelerated DMs, ES correlation searches, RBA (+ `references/Anti-Patterns.md`) |
| `crowdstrike-falcon` | Falcon surface map (Insight FQL, NG-SIEM CQL, Custom IOA/IOC, Fusion, RTR), Storyline ID correlation, sensor coverage (+ `references/FQL-Field-Reference.md`) |
| `carbon-black-cloud` | Carbon Black Cloud Enterprise EDR — Watchlist Reports, scheduled searches, process_guid correlation, Live Response |
| `sentinelone-singularity` | SentinelOne Singularity (NOT Microsoft Sentinel) — STAR Custom Logic, DVQL, PowerQuery / SDL, Storyline ID, exclusion discipline (+ `references/DVQL-Field-Reference.md`) |
| `harfanglab` | HarfangLab orb — Sigma rule packs, RHQL hunting, YARA, custom detection rules |
| `okta-identity` | Okta System Log event schema, authentication flows, cross-tenant impersonation, session theft, admin API abuse |
| `amazon-web-services` | CloudTrail events, IAM mechanics, GuardDuty findings, S3/EC2 exfiltration, cross-account access |
| `microsoft-azure` | Activity Log, ARM operations, RBAC/PIM, managed identities, Key Vault, VM extensions |
| `google-cloud-platform` | Cloud Audit Logs, IAM/service accounts, workload identity, Chronicle/YARA-L mapping |

### Defensive internals
| Skill | Purpose |
|---|---|
| `windows-internals` | Process creation chain, access tokens/privileges, DLL loading, SCM, COM/WMI, named pipes, ETW, AMSI, registry |
| `active-directory` | Kerberos/NTLM flows, DCSync/DCShadow, delegation abuse, AD CS (ESC1-ESC13), GPO, LDAP reconnaissance |
| `identity-providers` | OAuth2/OIDC flows, SAML/Golden SAML, PRT mechanics, refresh token binding, federation chains, MFA ceremonies |
| `network-protocols` | DNS tunnelling/DGA, TLS anomalies, SMB coercion, HTTP/S C2 beaconing, LDAP, RDP, WinRM, SMTP headers |
| `email-and-collaboration` | Exchange Online mail flow, mailbox forwarding, OAuth app permissions, MailItemsAccessed, SharePoint, Teams, Purview UAL |
| `linux-internals` | Process model, capabilities, auditd, eBPF/Falco/Tetragon, systemd, PAM, SSH, container isolation |
| `macos-internals` | launchd/XPC, TCC framework, Gatekeeper/notarisation, code signing, persistence locations, Keychain, Endpoint Security |

Load the **narrowest** skill first — escalate outward when coordination demands. For any KQL surface always pair `kusto-query-language` with the relevant Microsoft platform skill.

---

## Git expectations

Bootstrap scenarios aside, **`main`** on `OpenTideHQ/AgentTide` retains **minimal** licensing/readme scaffolding — harness enrichment lands through **approved pull requests** so reviewers can deliberate without surprise history rewriting.
