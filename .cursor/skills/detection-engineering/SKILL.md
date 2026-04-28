---
name: detection-engineering
description: Guides the OpenTide detection-engineering lifecycle across TVMs, DOMs, and MDRs, and bridges validated hunting hypotheses into deployable analytics on CoreTide-backed platforms. Covers sequencing, merge scope, maturity progression, hunt-to-rule conversion checklist, platform pairing (KQL tenants vs SPL vs vendor consoles), and quality bars. Use when planning multi-phase work, reviewing MR scope, or converting validated queries into production detections referenced from MDR YAML.
---

# Detection engineering (OpenTide + DetectionOps alignment)

## OpenTide sequencing

1. **Evidence / threat modelling** (`opentide-threat-vector`)
2. **Detection intent & signals** (`opentide-detection-objective`)
3. **Deployable artefacts** (`opentide-detection-rule` + **platform-specific skills below**)

Default to **one object type per change request** unless the user insists on an end-to-end vertical slice for a drill or pilot deployment.

Supported provider surfaces in CoreTide-style corpora commonly map to configuration blocks such as: `sentinel`, `defender_for_endpoint`, `splunk`, `crowdstrike`, `carbon_black_cloud`, `sentinel_one`. Always read the tenant’s **`Configurations/systems`** and live MDR templates—the concrete keys/version labels evolve with releases.

---

## Hunting versus production detection (shared discipline)

Across SIEM/XDR backends, disciplined teams treat hunts and scheduled detections differently:

| Aspect | Hunting / prototyping | Automated detection rule |
|--------|--------------------------|---------------------------|
| **Purpose** | Investigate hypotheses over historical data | Produce durable, operator-actionable alerts |
| **Cadence & window** | Analyst chooses lookback interactively | Platform cadence defines lookback; align query to that envelope |
| **Output shape** | Wide columns tolerated | Stable columns for entity enrichment, ticketing, SOC workflow |
| **False positives** | Triage cost limited to searcher | Alerts page every responder—noise erodes confidence |
| **Evolution stage** | Theoretical → validated through evidence | Conservative deployment → iterative tuning |

Maturity shorthand many teams adopt: **concept → validated hypothesis → tuned detection candidate → enforced deployment workflow** (severity, response integrations, exclusions documented).

Operationalise hunts before encoding them verbatim into MDR `configurations.*` payloads.

---

## Pairing languages and platforms

| Technology family | Typical query expressions | Harness skills |
|-------------------|---------------------------|----------------|
| **Microsoft data plane (Log Analytics + Defender Advanced Hunting)** | **KQL** | Shared: `kusto-query-language`; split platform execution details: `microsoft-sentinel`, `microsoft-defender-endpoint` |
| **Splunk** | SPL | `splunk-spl-processing` |
| CrowdStrike Falcon | Platform query / scheduled search syntax | `crowdstrike-falcon` |
| SentinelOne Singularity | Platform detector/search language per product area | `sentinelone-singularity` |
| VMware Carbon Black Cloud Enterprise EDR | Watchlist/query constructs | `carbon-black-cloud` |
| HarfangLab orb | Platform query schema | `harfanglab` |

KQL spans **multiple Microsoft entry points** — keep optimisation guidance in **`kusto-query-language`**, and keep Sentinel vs Defender particulars (tables, ingestion contracts, analytic rule quirks) inside the respective Microsoft skill.

---

## From hunting validation to DOM / MDR

1. **Anchor to DOM signals** — Each detector should cite which signal id it realises when your schema binds them.
2. **Document assumptions & exclusions** — Operator-tunable placeholders belong in prose fields and/or configuration comments sanctioned by governance.
3. **Match rule frequency / performance envelope** — heavy joins may be hunt-only unless scheduled cadence affords them.
4. **Platform parity** — If only one SIEM lands first, expose gaps honestly in `description`, `procedure`, or `response.playbook`.

---

## Review checklist before merge

- [ ] Existing objects consulted; UUID strategy explicit (reuse vs supersede vs new lineage).
- [ ] Schema-valid YAML; pipelines pass or deltas explained.
- [ ] Detection logic references are testable—not aspirational placeholders—unless flagged with follow-up ownership.
- [ ] Appropriate platform skill consulted for specialised syntax (SPL vendor dialects versus KQL, etc.).
- [ ] User-facing summaries respect British English prose unless corpus policy overrides.

---

## Reference graph

```
opentide-threat-vector
        ↓
opentide-detection-objective  ← connects TVMs & signals to coverage narrative
        ↓
opentide-detection-rule       ← attaches configuration blocks per deployed system
```

Use `detection-engineering` when stitching these layers simultaneously or aligning SOC operating procedures across teams.
