---
name: opentide-detection-rule
description: Authors OpenTide Detection Rule (MDR) YAML—descriptions, response metadata, playbook hooks, analytic references—and wires platform-specific configurations (Sentinel KQL blobs, SPL, Defender advanced hunting exports, Falcon queries, SentinelOne rules, CBC watchlists, HarfangLab content) keyed per CoreTide deployment manifests. Use when producing deployable artefacts or updating existing rules under Detection Rules folders.
---

# OpenTide Detection Rule (MDR)

## Preconditions

1. Hydrate **`Schemas/Templates`** for **MDR** (`mdr::*`) and compare with active JSON schemas.
2. Confirm **DOM linkage** integrity—signals you operationalise exist and remain authoritative.
3. Consult tenant **`Configurations/systems`** to know which backends (for example `sentinel`, `defender_for_endpoint`, `splunk`, `crowdstrike`, `carbon_black_cloud`, `sentinel_one`) are licensed and routed through CoreTide deployments.

Typical **`configurations` block placeholders** resemble:

```yaml
configurations:
  # sentinel:
  # defender_for_endpoint:
  # splunk:
  # crowdstrike:
  # carbon_black_cloud:
  # sentinel_one:
```

Exact nesting keys follow generated templates—mirror your repository's sanctioned structure.

---

## Placement rules

| Concern | Instruction |
|---------|---------------|
| **Executable logic** | Lives under sanctioned platform keys—never improvised sibling YAML keys.|
| **`description` / prose** | Describes operator context, exclusions, escalation expectations separately from encoded queries.|
| **Response** | Severity, playbook pointers, responders, investigative `procedure.analysis` narratives stay aligned with SOC policy.|
| **Tuning** | If logic requires staged rollout (`shadow`, alerting toggles), document interplay per platform capabilities.|

Invoke **query language skill** aligned with targeted stack:

| Stack | Skill pairing |
|-------|----------------|
| Sentinel & Log Analytics | `kusto-query-language` + `microsoft-sentinel` |
| Defender for Endpoint (custom detection authoring path) | `kusto-query-language` + `microsoft-defender-endpoint` |
| Splunk SPL searches / ES correlation searches | `splunk-spl-processing` |
| CrowdStrike | `crowdstrike-falcon` |
| SentinelOne Singularity | `sentinelone-singularity` |
| Carbon Black Cloud | `carbon-black-cloud` |
| HarfangLab | `harfanglab` |

Avoid shipping vendor-specific artefacts your manifest does not advertise—explicitly annotate gaps ("Sentinel backlog item #123") instead of placeholders that read as executable content.
