---
name: crowdstrike-falcon
description: CrowdStrike Falcon deployment guidance for OpenTide configurations.crowdstrike blocks — distinguishes Falcon Insight (Event Search / EAM) from Falcon Next-Gen SIEM (LogScale / CQL), covers Falcon Query Language idioms, custom IOA / IOC discipline, scheduled search lifecycle, Falcon Fusion workflow automation, sensor coverage gaps across Windows / macOS / Linux, real-time response guardrails, and entity-identifier alignment for cross-platform incident correlation. Use when authoring or reviewing CrowdStrike-keyed configurations in OpenTide MDR objects.
---

# CrowdStrike Falcon — content authoring

This skill encodes operational context for authoring detection content destined for `configurations.crowdstrike` blocks in OpenTide MDR objects. Falcon's content surfaces are split across **multiple distinct products** with different query languages and lifecycle expectations — the first decision is identifying which surface the rule targets.

---

## 1. Surface identification

| Surface | Query language | Use for |
|---|---|---|
| **Falcon Insight — Event Search** | Falcon Query Language (FQL) | Ad-hoc hunting, scheduled searches; original EAM data store |
| **Falcon Insight — Custom IOAs** | IOA rule-builder (UI-driven, condition tree) | Real-time behavioural detection on the sensor |
| **Falcon Insight — Custom IOCs** | Indicator API (hash, IP, domain) | Block / detect-only on observable atoms |
| **Falcon Next-Gen SIEM (NG-SIEM, ex-Humio / LogScale)** | LogScale Query Language (CQL) | Log search, dashboards, scheduled queries; multi-source ingestion |
| **Falcon Fusion (workflows)** | YAML / UI workflow definitions | Automated response orchestration |
| **Falcon Real-Time Response (RTR)** | RTR command set (limited shell) | Manual or automated response actions |

Confirm which surface the content targets before authoring. The same intent (e.g. "alert on suspicious PowerShell") looks very different as an IOA, an Event Search scheduled query, an NG-SIEM correlation rule, or a Fusion workflow.

---

## 2. Sensor coverage — gaps to declare

Falcon sensor capabilities differ by OS and licensing tier. Document gaps in the MDR `description` rather than assuming parity.

| Capability | Windows | macOS | Linux |
|---|---|---|---|
| Process tree depth | Full | Full | Full |
| Command-line capture | Full | Full | Limited (per-distro) |
| File system events | Full | Full | Full (eBPF on supported kernels) |
| Registry events | Full | n/a | n/a |
| Network connection events | Full | Full | Full |
| DNS query events | Full | Full | Limited |
| Script content (PowerShell ScriptBlock, etc.) | Full (modules dependent) | Limited | n/a |

Detection rules targeting Linux endpoints require explicit kernel/distro assumptions. Detections that hard-code Windows-style identifiers (`AccountSid`, `Hostname`) will produce no Linux coverage.

---

## 3. Falcon Query Language (Event Search) — idioms

FQL combines field-level filters with aggregation operators. It is **not** SQL; it is **not** SPL; it is **not** KQL. Treat unfamiliar syntax as a lookup-required surface.

### Idiomatic patterns

```
event_simpleName=ProcessRollup2 ImageFileName=*\\powershell.exe
| stats count by ComputerName, UserName, CommandLine
```

```
event_simpleName=DnsRequest DomainName=*.evil.example
| table ComputerName, ContextProcessId_decimal, DomainName, _time
```

| FQL construct | Notes |
|---|---|
| `event_simpleName=` | Primary event-type filter — always include |
| `aid=` | Agent ID (per-host UUID) — primary host identifier |
| `ContextProcessId_decimal` | Process correlation across multi-event chains |
| `_time` | Event timestamp (relative bounding via the time picker, not inline) |
| `*` wildcards | Permitted at field level (`ImageFileName=*\\powershell.exe`) |
| `| stats`, `| table`, `| eval` | Pipeline aggregation/projection (Splunk-like syntax) |

**Reference discipline**: Falcon's exact FQL grammar evolves. When unsure, link to a tenant-validated example from the Falcon Console rather than fabricating syntax.

### Process chain correlation

Use `ContextProcessId_decimal` (not OS-level PID) to correlate parent → child events. PIDs recycle; Falcon's context ID is stable per process instance.

---

## 4. Custom IOAs

Custom IOAs are **on-sensor behavioural detections** — they evaluate at the time of the event and block (Prevention) or detect-only (Detect). They are the closest Falcon analogue to "production detection rule".

### IOA rule structure

| Field | Detail |
|---|---|
| Rule type | Process creation, Network connection, File creation, Registry, Domain |
| Match conditions | Field comparisons (Image path, Command line, Parent image, etc.) |
| Disposition | Detect / Prevent / Monitor |
| Severity | Low / Medium / High / Critical |
| Description / MITRE | Free-form prose + technique mapping |

### Authoring discipline

- **Detect-only first.** Never deploy a new IOA in Prevent mode. Stage in Detect for at least one full alert-volume cycle.
- **Tighten command-line conditions.** Wildcard command-line matches (`Command line contains "powershell"`) generate massive volume. Combine with parent image, account, integrity level.
- **Explicit MITRE mapping.** Falcon UI accepts technique IDs — populate them, don't leave inline-only.
- **Tenant scope.** Test in a single host group before fleet-wide deployment.

---

## 5. Custom IOCs

Custom IOCs are atomic indicator matches (SHA256, MD5, IPv4/v6, domain). The Falcon API accepts:

| Field | Required |
|---|---|
| `type` | One of `sha256`, `md5`, `ipv4`, `ipv6`, `domain` |
| `value` | The indicator |
| `action` | `detect` / `prevent` / `prevent_no_ui` / `allow` |
| `severity` | `informational` / `low` / `medium` / `high` / `critical` |
| `expiration` | ISO 8601 — **always set** |
| `applied_globally` or `host_groups` | Scope |
| `description`, `source`, `tags` | Provenance |

**Rules**:
- **Always set `expiration`.** Permanent IOCs accumulate and degrade detection performance.
- **Source provenance.** Tags should include the originating CTI feed / report reference.
- **Avoid IP IOCs from shared infrastructure.** Cloud, CDN, and CGN IPs cause widespread false positives. Prefer SHA256, domain, and full URLs.

---

## 6. Falcon Next-Gen SIEM (LogScale / CQL)

NG-SIEM is the evolved Humio / LogScale surface. CQL is **not** FQL — it is closer to SPL conceptually but with its own syntax.

### CQL essentials

```cql
#repo=falcon_data event_simpleName=DnsRequest
| in(field=DomainName, values=["evil.example", "c2.example.net"])
| groupBy(ComputerName, function=count())
```

| CQL construct | Notes |
|---|---|
| `#repo=` | Repository (tenant data partition) — always include |
| `| in(field=, values=[])` | Multi-value membership |
| `| groupBy(...)` | Aggregation |
| `| timeChart(...)` | Time bucketing |
| `| join(...)` | Cross-repo joining |

### Scheduled queries and alerts

- **Schedule discipline**: aligned to sensor data ingestion cadence; respect query budget per tenant.
- **Notable creation**: alert actions can call Fusion workflows for orchestration.
- **Suppression**: per-entity, per-time-window — always set on production alerts.

---

## 7. Falcon Fusion workflows

Fusion is the orchestration layer — the analogue to Sentinel Logic Apps or SOAR playbooks.

### Common automation patterns

| Trigger | Action |
|---|---|
| Detection received | Notify analyst (email / Slack / Teams) |
| Detection received + severity ≥ High | Network containment (host quarantine via API) |
| IOC matched | Add to watchlist, expand to similar indicators via TI enrichment |
| Real-Time Response session | Run sanctioned RTR script, capture output, attach to detection |

### Authoring discipline

- **Start manual, automate gradually.** Document the analyst playbook before encoding it.
- **Network containment is destructive.** Reserve auto-containment for high-confidence rules with low FP rate. Always test in detect-only first.
- **Audit RTR usage.** Every Fusion-triggered RTR command must reach the audit log; review periodically.

---

## 8. Real-Time Response

RTR is a constrained shell that runs through the sensor for incident response. Commands are categorised:

| Category | Examples | Risk |
|---|---|---|
| **Read-only** | `ps`, `netstat`, `ls`, `cat`, `eventlog` | Low — investigation |
| **Write/state-changing** | `kill`, `rm`, `mv`, `put` | Medium — containment, evidence collection |
| **Custom scripts** | `runscript -CloudFile=...`, `runscript -Raw=...` | High — arbitrary code execution |

**Authoring discipline**:
- All RTR commands embedded in Fusion workflows must be reviewed by an analyst capable of running them manually.
- Custom scripts uploaded to the cloud script library must carry provenance comments (author, source, purpose).
- Never embed credentials or secrets in RTR scripts.

---

## 9. Entity identifier alignment (cross-platform correlation)

When OpenTide MDR objects bridge Falcon detections with Microsoft / Splunk equivalents, ensure identifier columns align:

| Concept | Falcon | Microsoft Defender | Sentinel |
|---|---|---|---|
| Host | `aid` (UUID), `ComputerName` | `DeviceId` (UUID), `DeviceName` | `Computer` (hostname) |
| User | `UserName`, `UserSid` | `AccountName`, `AccountUpn`, `AccountSid` | `UserPrincipalName`, `AccountSid` |
| Process correlation | `ContextProcessId_decimal` | `ProcessUniqueId` / `InitiatingProcessUniqueId` | n/a (`ProcessId` only — recycled) |
| File hash | `SHA256HashData` | `SHA256` | `FileHash` |
| Network | `RemoteAddressIP4` | `RemoteIP` | `IPAddress` |

Correlation **must happen at the analyst / orchestrator layer** (Fusion, SIEM, or SOAR) — direct cross-platform joins between Falcon and Microsoft data are unreliable.

---

## 10. Mapping into OpenTide MDR

When Falcon content lives in `configurations.crowdstrike` blocks:

- **Identify the surface** (Event Search / NG-SIEM / Custom IOA / Custom IOC / Fusion) in the configuration block — they are not interchangeable.
- **Detection prose, severity, MITRE mapping, response procedure** → MDR `description` and `response.*` fields per MDR schema.
- **Sensor coverage gaps** declared explicitly so reviewers can assess platform fitness.
- Coordinate with `opentide-detection-rule` for placement and `detection-engineering` for the lifecycle bar.

---

## 11. Quality checklist

- [ ] Surface identified (FQL Event Search vs CQL NG-SIEM vs IOA vs IOC vs Fusion).
- [ ] Sensor coverage gaps declared per OS in `description`.
- [ ] IOAs staged in Detect mode before Prevent.
- [ ] IOCs carry `expiration` and source provenance.
- [ ] CQL repo (`#repo=`) and time scope set.
- [ ] FQL queries pivot via `ContextProcessId_decimal`, not OS PID.
- [ ] Fusion workflows reviewed for destructive actions; auto-containment guarded.
- [ ] RTR scripts authored manually before automation.
- [ ] Entity identifiers documented for cross-platform correlation.

---

## 12. Reference catalogues

- `references/FQL-Field-Reference.md` — FQL event types, field names by category (process, network, DNS, file, registry, auth), CQL differences, and Custom IOA field mapping.
