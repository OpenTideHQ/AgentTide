---
name: harfanglab
description: HarfangLab orb / EDR authoring guidance — Sigma rule pack ingestion, RHQL hunt query language, custom detection rules, telemetry policies, exclusions and whitelists, sensor capability map across Windows / macOS / Linux, threat intelligence integration, and entity-identifier alignment. Use for harfanglab-keyed configurations in OpenTide MDR objects.
---

# HarfangLab orb (EDR) — content authoring

This skill encodes operational context for content authoring against HarfangLab's EDR product (orb). HarfangLab is a French EDR vendor with strong Sigma support; rule authoring blends Sigma packs (vendor-curated and customer-authored) with the platform's native query language (RHQL — Realtime Hunting Query Language) for hunting.

---

## 1. Surface identification

| Surface | Purpose | Authoring expression |
|---|---|---|
| **Sigma rules** | Behavioural detection rule packs | Sigma YAML (HarfangLab tooling translates internally) |
| **Custom detection rules** | Customer-authored behavioural rules | Sigma YAML, optionally with RHQL extensions |
| **RHQL hunting** | Ad-hoc hunting queries | RHQL |
| **YARA rules** | File / memory pattern matching | Standard YARA |
| **Whitelists** | Exclusions for known-good behaviour | Path / hash / signer / process |
| **Threat Intel** | IOC ingestion | STIX / CSV / API |

The primary detection-authoring surface is **Sigma**. HarfangLab's posture leans heavily on the open Sigma standard, which is a significant differentiator from most other EDR vendors.

---

## 2. Sigma rules — discipline

Sigma is a portable detection format. HarfangLab consumes both:

- **Vendor-curated** Sigma rule packs (subscribed and updated centrally).
- **Customer-authored** Sigma rules deployed per tenant.

### Standard Sigma sections

```yaml
title: Suspicious encoded PowerShell execution
id: <UUIDv4>
status: experimental | test | stable
description: Detects PowerShell with -EncodedCommand parameter typical of loaders.
references:
  - <source URL>
author: <author>
date: <YYYY/MM/DD>
modified: <YYYY/MM/DD>
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
    CommandLine|contains:
      - '-EncodedCommand'
      - '-enc '
  filter_legitimate:
    ParentImage|endswith:
      - '\sccm\ccmexec.exe'
  condition: selection and not filter_legitimate
falsepositives:
  - Legitimate enterprise software-deployment tooling
level: high
```

### Authoring discipline

- **`logsource` accuracy**: HarfangLab routes Sigma rules to the right telemetry by `product` / `category` / `service`. Wrong logsource = rule never fires.
- **Modifiers**: use `|endswith`, `|contains`, `|startswith`, `|re` deliberately. Avoid loose `|contains` on high-volume fields (`CommandLine`).
- **`filter_*` blocks**: name FP filters explicitly (`filter_legitimate`, `filter_signed`, etc.) and reference them in `condition`.
- **`level`** maps to severity — calibrate against the SOC's alert-volume budget.
- **`tags`**: ATT&CK technique IDs (`attack.t1059.001`), TLP, and any internal taxonomy.
- **`falsepositives`**: list known FP scenarios; surfaced to analysts.
- **`status: experimental`** until validated on production telemetry.

### HarfangLab-specific Sigma extensions

- Some HarfangLab telemetry fields don't map 1:1 to canonical Sigma field names. Vendor documentation lists field mappings; cross-reference before assuming a Sigma field exists.
- Custom logsources for HarfangLab-specific telemetry channels.

---

## 3. RHQL — Realtime Hunting Query Language

RHQL is HarfangLab's native query DSL for hunting. Field-comparison + boolean composition, with pipeline operators reminiscent of SPL/KQL hybrids.

### Idiomatic patterns

```
process.image.path matches ".*\\powershell\\.exe$"
    and process.command_line contains "-EncodedCommand"
| group by host.name
```

| RHQL construct | Notes |
|---|---|
| `field == value` | Equality |
| `field matches "<regex>"` | Regex |
| `field contains "value"` | Substring |
| `field in ["a", "b"]` | Multi-value |
| `and`, `or`, `not` | Boolean (parenthesise mixes) |
| `| group by`, `| count`, `| sort` | Pipeline aggregation |

Confirm exact syntax against vendor documentation before authoring — RHQL evolves between versions.

---

## 4. YARA — file and memory pattern matching

HarfangLab supports YARA rules for static pattern matching. Standard YARA syntax applies; relevant scopes include:

- **File scan**: applied at file write / first-seen.
- **Memory scan**: applied to running process memory.
- **Module scan**: applied to loaded DLLs / executable images.

### Authoring discipline

- Standard YARA hygiene: meta block populated (author, date, hash references), `condition` clauses referencing strings rather than dragging full file scans, anchors via `at` / `in` where appropriate.
- Avoid pure-string YARA against high-volume telemetry — performance cost is real.

---

## 5. Whitelists / exclusions

| Type | Scope |
|---|---|
| Path | Directory / executable allow |
| Hash | SHA256 allow |
| Signer | Certificate-based trust |
| Process | Allow specific executable interactions |
| Network | IP / domain / subnet allow |

Same discipline as other EDR platforms: tightest scope, audit metadata (ticket, owner, expiry), quarterly review.

Document **expected whitelist patterns** in the Sigma rule's `falsepositives` block so SOC engineers can manage allow-lists without retuning rules.

---

## 6. Sensor capability boundaries

| Capability | Windows | macOS | Linux |
|---|---|---|---|
| Process / file / network telemetry | Full | Full | Full |
| Registry | Full | n/a | n/a |
| DNS | Full | Full | Per kernel module |
| Memory protection | Full | Limited | Limited |
| YARA file / memory scanning | Full | Full | Full |
| Driver-level visibility | Full (Windows kernel) | n/a | n/a |

Document gaps in MDR `description` rather than assuming parity. Linux endpoint coverage depends on kernel module / eBPF availability.

---

## 7. Entity identifier alignment

| Concept | HarfangLab | Microsoft Defender | CrowdStrike | SentinelOne |
|---|---|---|---|---|
| Host | `host.name`, `agent.id` | `DeviceId`, `DeviceName` | `aid`, `ComputerName` | `agent.uuid`, `endpoint.name` |
| User | `user.name` | `AccountName`, `AccountUpn` | `UserName` | `user.name` |
| Process | `process.id` (with `process.start_time` for stability) | `ProcessUniqueId` | `ContextProcessId_decimal` | `process.storyline.id` |
| Hash | `process.image.hash.sha256` | `SHA256` | `SHA256HashData` | `tgt.process.image.sha256` |

Cross-platform correlation at the SOAR / SIEM layer.

---

## 8. Mapping into OpenTide MDR

When HarfangLab content lives in `configurations.harfanglab`:

- **Identify the surface** (Sigma rule / RHQL hunt / YARA / Whitelist).
- **Sigma YAML** carried inline; logsource accuracy verified.
- **MITRE mapping** in `tags` + MDR `description`.
- **Sensor / OS coverage** declared.
- **Expected whitelist patterns** documented in `falsepositives`.
- Coordinate with `opentide-detection-rule` for placement and `detection-engineering` for lifecycle.

---

## 9. Quality checklist

- [ ] Surface identified (Sigma / RHQL / YARA / Whitelist).
- [ ] Sigma `logsource` accurate.
- [ ] Sigma modifiers deliberate; `filter_*` blocks named explicitly.
- [ ] `level` calibrated against alert-volume budget.
- [ ] `falsepositives` populated.
- [ ] `tags` include ATT&CK technique IDs.
- [ ] `status: experimental` until production-validated.
- [ ] Sensor / OS coverage declared in MDR description.
- [ ] YARA rules carry `meta` provenance.
- [ ] Whitelists carry audit metadata.
