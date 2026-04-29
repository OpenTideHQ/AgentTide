---
name: detection-engineering
description: Detection engineering lifecycle across the OpenTide TVM → DOM → MDR sequence and the operational practice of converting validated hunting queries into production detection rules. Encodes hunting-vs-detection trade-offs, hunt-to-rule conversion (7-step process with FP reduction, entity mapping, NRT compliance, response actions), platform pairing matrix (Microsoft KQL split, Splunk SPL, vendor consoles), maturity progression, PR scope discipline, and quality bars. Use when planning multi-phase detection work, sequencing object types in OpenTide content repos, reviewing PR scope, or operationalising hunts into MDR objects.
---

# Detection engineering — OpenTide + DetectionOps

This skill governs **how** detection content moves through its lifecycle. It pairs OpenTide's object lineage (Threat Vector → Detection Objective → Detection Rule) with the practical mechanics of converting validated hunting queries into production-grade detection rules on the platforms CoreTide deploys to.

> Always pair with: language skills (`kusto-query-language`, `splunk-spl-processing`), platform skills (`microsoft-sentinel`, `microsoft-defender-endpoint`, `crowdstrike-falcon`, `carbon-black-cloud`, `sentinelone-singularity`, `harfanglab`), and the OpenTide object skills (`opentide-threat-vector`, `opentide-detection-objective`, `opentide-detection-rule`).

---

## 1. OpenTide sequencing

1. **Evidence / threat modelling** — `opentide-threat-vector` (TVM YAML, Phase A intel structuring + Phase B authoring).
2. **Detection intent & signals** — `opentide-detection-objective` (DOM YAML, signals, data contracts, methodology).
3. **Deployable artefacts** — `opentide-detection-rule` (MDR YAML, plus platform-specific `configurations.*` blocks).

**Default rule**: one object type per change request unless explicitly running an end-to-end vertical slice (drill, pilot deployment, framework-bootstrap).

CoreTide-aligned configuration keys most commonly seen:

| Key | Platform | Pair with |
|---|---|---|
| `sentinel` | Microsoft Sentinel | `microsoft-sentinel` + `kusto-query-language` |
| `defender_for_endpoint` | M365 Defender Advanced Hunting | `microsoft-defender-endpoint` + `kusto-query-language` |
| `splunk` | Splunk Enterprise / ES | `splunk-spl-processing` |
| `crowdstrike` | CrowdStrike Falcon | `crowdstrike-falcon` |
| `carbon_black_cloud` | VMware Carbon Black Cloud | `carbon-black-cloud` |
| `sentinel_one` | SentinelOne Singularity | `sentinelone-singularity` |
| `harfanglab` | HarfangLab orb | `harfanglab` |

Always confirm the exact keys against the active meta-schema and the `Configurations/systems` directory of the content repository — keys evolve.

---

## 2. Hunting versus production detection

| Aspect | Hunting query | Production detection rule |
|---|---|---|
| Purpose | Retroactive investigation; evidence search | Continuous monitoring; alert future activity |
| Execution | One-shot, ad-hoc | Automated, recurring, NRT or scheduled |
| Result handling | Analyst reviews full result set | Each row → alert (+ optional response action) |
| Time filter | Explicit `ago(Nd)` | Platform-managed (frequency + lookback) |
| Output columns | Flexible — whatever helps triage | **Mandatory** schema for alert generation |
| FP tolerance | Some FPs acceptable | Low — every FP degrades analyst trust |
| Tuning lifecycle | Per-hunt threshold tweaks | Stabilised before deployment; monitored continuously |
| Scope | Full fleet or targeted | Often scoped to device/entity groups |

### Design philosophy

1. **Start from validated hunts.** Never deploy a detection without hunting validation.
2. **Minimise FPs.** Every FP is a noise alert that erodes analyst trust.
3. **Start conservative.** Lower severity, "investigate" response actions, escalate after stability is established.
4. **Document everything.** Detections must carry the same rationale quality as hunting queries.
5. **Test inside the frequency window.** Run the candidate query with the production lookback to confirm result counts are manageable.

### Maturity progression

```
THEORETICAL → VALIDATED hunt → Detection candidate → Deployed (conservative) → Tuned (production)
```

A hunt may become a detection only after:
- Hunting status is `VALIDATED`.
- True positives are confirmed.
- FP rate is documented.
- Filters are tuned to reduce noise.
- Expected result volume is known for the target frequency.

---

## 3. Pairing languages and platforms

| Technology family | Query expression | Skills |
|---|---|---|
| Microsoft Sentinel + Defender Advanced Hunting | KQL | Shared: `kusto-query-language`; platform-specific: `microsoft-sentinel`, `microsoft-defender-endpoint` |
| Splunk Enterprise / ES | SPL | `splunk-spl-processing` |
| CrowdStrike Falcon | FQL / NG-SIEM (LogScale) | `crowdstrike-falcon` |
| SentinelOne Singularity | Star Custom Logic / Deep Visibility / PowerQuery | `sentinelone-singularity` |
| Carbon Black Cloud Enterprise EDR | Watchlist / process search syntax | `carbon-black-cloud` |
| HarfangLab orb | Sigma + RHQL | `harfanglab` |

**Never invent vendor syntax.** If the relevant platform skill does not assert a fact, route to vendor documentation rather than fabricating syntax.

---

## 4. Hunt-to-detection conversion — 7 steps

### Pre-conversion checklist

- [ ] Hunt query has `validation_status: VALIDATED`.
- [ ] True positives confirmed in production telemetry.
- [ ] FP rate documented from hunt iterations.
- [ ] Filters tuned based on hunt observations.
- [ ] Expected result volume known for the target frequency window.

### Step 1 — Adjust the time filter

| Target | Action |
|---|---|
| Defender custom detection | **Remove** the time filter — engine manages lookback by frequency |
| Sentinel scheduled rule | Replace `ago(30d)` with interval + ingestion buffer (e.g. `ago(1h15m)` for 1h interval) |
| Sentinel NRT | **Remove** `TimeGenerated` filter — NRT engine uses `ingestion_time()` |
| Defender NRT | **Remove** time filter and all `//` comments |

### Step 2 — Add required output columns

**Defender custom detection** (mandatory, otherwise rule creation fails):

```kql
| project Timestamp, DeviceId, ReportId,                 // mandatory
    DeviceName, AccountName, AccountSid,                  // entity mapping
    FileName, ProcessCommandLine                          // evidence + enrichment
```

**Sentinel analytic rule** — entity identifier columns must be in projection so entity mapping resolves:

```kql
| project TimeGenerated,                                  // timestamp
    UserPrincipalName,                                     // Account entity
    IPAddress,                                             // IP entity
    Location, AppDisplayName, RiskLevel                    // enrichment
```

### Step 3 — Reduce false positives

For each FP class observed in hunting:

```kql
// Per-FP exclusion with justification
| where not(FileName =~ "legitimate_tool.exe" and FolderPath has "KnownGoodPath")
| where AccountName !in~ ("svc_monitoring", "svc_backup")

// Per-deployment block
// --- BEGIN ENVIRONMENT FILTERS (customise per deployment) ---
| where /* environment-specific exclusions */
// --- END ENVIRONMENT FILTERS ---
```

Each exclusion must carry a comment explaining the FP scenario. Reviewers reject blanket `where not(...)` clauses.

### Step 4 — Test with the frequency lookback

Run the candidate query for the production lookback window. Verify:
- Result count < 150 (alert limit per run).
- Results actionable (not dominated by FPs).
- No critical events fall outside the lookback window.

### Step 5 — Map entities

| Defender entity | Required columns |
|---|---|
| Device | `DeviceId`, `DeviceName` |
| User | `AccountSid`, `AccountName`, `AccountUpn` |
| File | `SHA256`, `FileName`, `FolderPath` |
| Process | `ProcessId`, `ProcessCommandLine` |
| IP | `RemoteIP` |
| URL | `RemoteUrl` |

| Sentinel entity | Identifier columns |
|---|---|
| Account | `UserPrincipalName`, `AccountSid`, `AadUserId` |
| Host | `Computer`, `HostName` |
| IP | `IPAddress` |
| URL | `Url` |
| File | `FileName`, `FileHash` |
| Process | `ProcessId`, `CommandLine` |
| Azure Resource | `ResourceId` |
| DNS | `DomainName` |
| Mailbox | `MailboxPrimaryAddress` |

For other platforms (Splunk ES notable events, Falcon detection metadata, CBC alerts, S1 stories, HarfangLab cases), identifier discipline is platform-specific — see platform skills.

### Step 6 — Set conservative response actions

- Defender: default to **"Initiate investigation"**. Reserve isolation/quarantine for high-confidence critical-severity rules.
- Sentinel: start at **Medium severity** with per-event alerting. Add automated playbooks (Logic Apps) only after detection proves reliable.
- Other platforms: default to alert-only / case creation. Add response automation only after stability is established.

### Step 7 — Handle NRT constraints

| Constraint | Defender NRT | Sentinel NRT |
|---|---|---|
| Single table only | YES (strict) | NO (multi-table supported) |
| `//` comments forbidden | YES | NO |
| `externaldata()` forbidden | YES | YES |
| `TimeGenerated` / `Timestamp` filter | Remove | Remove |
| Max NRT rules per workspace | n/a | 50 |
| Query length | n/a | ≤ 10 000 chars |

**NRT pre-flight**:
- Defender: confirm the table supports NRT (see `microsoft-defender-endpoint`).
- Sentinel: ≤ 50 NRT rules per workspace; no `search *` / `union *`.

### Conversion checklist

- [ ] Time filter removed/adjusted per target.
- [ ] Required columns present.
- [ ] FPs from hunting excluded with justification.
- [ ] Result volume tested under frequency lookback (< 150).
- [ ] Entity columns in projection.
- [ ] Response actions conservative.
- [ ] NRT constraints satisfied where applicable.
- [ ] Severity set conservatively with documented escalation criteria.
- [ ] Alert enrichment (custom details, `{{ColumnName}}` tokens) configured.
- [ ] MITRE technique + tactic mapped.

---

## 5. Detection rule quality standards

### Query quality (in addition to language-skill bar)

- [ ] No unnecessary complexity — detection queries should be **simpler** than hunting queries.
- [ ] Deterministic — no random sampling, no probabilistic filters.
- [ ] Stable output schema — column names consistent run-to-run for entity mapping.
- [ ] Designed to produce < 150 results per run (Sentinel + Defender alert limit).

### Documentation quality

Every rule must document, in MDR YAML or platform metadata:

| Field | Content |
|---|---|
| Detection name | Clear, descriptive |
| Frequency | Chosen frequency with justification |
| Severity | Chosen severity with escalation criteria |
| MITRE | Technique IDs + tactics |
| Entity mapping | Which columns map to which entities |
| Response actions | Configured actions and rationale |
| FP exclusions | Each exclusion with justification |
| Tuning guidance | How to adjust thresholds/exclusions per deployment |
| Source hunt | Reference to the validated hunting query/lead |

### Tuning philosophy

1. **Start broad, narrow carefully** — begin with the hunt's filters and add exclusions one at a time.
2. **Document every exclusion** — `where not(...)` without a comment is rejected.
3. **`let` for thresholds** — make tuning parameters explicit and adjustable.
4. **Monitor alert volume** — track alerts/week and investigate sudden changes.
5. **Review quarterly** — re-evaluate relevance against the current threat landscape.

---

## 6. Platform comparison (KQL surfaces)

| Feature | Defender custom detection | Sentinel analytic rule |
|---|---|---|
| Required output | `Timestamp`, `DeviceId`, `ReportId` | Entity identifier columns |
| Max alerts per run | 150 | 150 (per-event mode) |
| NRT single-table | YES (strict) | NO (multi-table OK) |
| NRT no comments | YES (strict) | NO restriction |
| Time field | `Timestamp` | `TimeGenerated` |
| Response actions | Device isolate, file quarantine, user disable | Via Logic Apps playbooks |
| Alert grouping | `ReportId` dedup | Entity-based incident grouping |
| Query length limit | No practical limit | 10 000 characters |
| MITRE mapping | Rule metadata | Rule configuration UI |
| Dynamic title tokens | `{{ColumnName}}` | `{{ColumnName}}` |
| Event grouping | Per-event only | Group all OR per-event |
| Suppression | `ReportId` dedup | Configurable 1 h – 24 h |

For Splunk / CrowdStrike / Carbon Black / SentinelOne / HarfangLab equivalents, see their platform skills.

---

## 7. PR scope discipline (OpenTide change requests)

- Default pull requests contain **one object type at a time** (TVM, DOM, or MDR).
- An end-to-end vertical slice is acceptable when explicitly orchestrated (drill, pilot, framework bootstrap) — call it out in the pull request narrative.
- Detection rule changes that span multiple platform `configurations.*` blocks may live in one MDR file but should be reviewed per-platform.
- Schema/template changes never travel inside a content merge — they go through dedicated framework merges.

---

## 8. References

- `kusto-query-language/SKILL.md` (+ `references/Best-Practices.md`, `references/Hypothesis-Anti-Patterns.md`)
- `microsoft-sentinel/SKILL.md` (+ `references/Anti-Patterns.md`)
- `microsoft-defender-endpoint/SKILL.md` (+ `references/Anti-Patterns.md`)
- `splunk-spl-processing/SKILL.md`
- `crowdstrike-falcon/SKILL.md`, `carbon-black-cloud/SKILL.md`, `sentinelone-singularity/SKILL.md`, `harfanglab/SKILL.md`
- `opentide-threat-vector/SKILL.md`, `opentide-detection-objective/SKILL.md`, `opentide-detection-rule/SKILL.md`
- `threat-hunting/SKILL.md` — hypothesis discipline (ABLE) and hunt quality scoring
