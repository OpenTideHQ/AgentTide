---
name: carbon-black-cloud
description: VMware Carbon Black Cloud Enterprise EDR authoring guidance — distinguishes process search query syntax (CBC search language) from watchlist feeds, scheduled searches, and live response. Covers indicator vs IOC discipline, watchlist subscription model, alert override / interrupt, sensor capability boundaries, and entity identifier alignment for cross-platform correlation. Use for carbon_black_cloud-keyed configurations in OpenTide MDR objects.
---

# Carbon Black Cloud Enterprise EDR — content authoring

This skill encodes operational context for authoring detection content in `configurations.carbon_black_cloud` blocks of OpenTide MDR objects. Carbon Black Cloud (CBC) Enterprise EDR (formerly CB ThreatHunter) is the relevant product surface; older CB Response (on-prem) is **not** the same product.

---

## 1. Surface identification

| Surface | Used for |
|---|---|
| **Process Search (Investigate)** | Ad-hoc hunting via the search bar / API |
| **Watchlists** | Recurring alert generation backed by Reports / IOCs |
| **Scheduled Searches** (via API) | Custom periodic queries with action hooks |
| **Alerts** | Notable events from Watchlist hits, sensor IOC matches, NGAV detections |
| **Live Response** | Constrained shell over the sensor for IR |
| **Threat Intel Feeds** | Subscribed third-party / Carbon Black-curated indicator streams |

CBC's primary detection authoring surface is **Watchlists** (curated collections of Reports, each containing one or more IOCs/queries). Scheduled searches are a complementary mechanism for query-based detections that need richer aggregation.

---

## 2. Process search query syntax

CBC search syntax is its own DSL — not Lucene, not KQL, not SPL. Field-level filters with boolean operators:

```
process_name:powershell.exe AND process_cmdline:*-EncodedCommand*
```

```
device_os:WINDOWS AND netconn_action:ACTION_CONNECTION_CREATE
    AND netconn_remote_port:443 AND -netconn_remote_ipv4:10.0.0.0/8
```

| Operator | Meaning |
|---|---|
| `field:value` | Equality |
| `field:*partial*` | Wildcard match |
| `AND`, `OR`, `NOT` (or `-`) | Boolean |
| `field:[a TO b]` | Range |
| `()` | Grouping |

**Common fields** (process search):

| Field | Description |
|---|---|
| `process_name`, `process_cmdline`, `process_hash` | Target process |
| `parent_name`, `parent_cmdline`, `parent_hash` | Parent process |
| `process_username`, `process_integrity_level` | Identity / privilege |
| `device_name`, `device_os`, `device_policy` | Host context |
| `netconn_*`, `filemod_*`, `regmod_*`, `crossproc_*` | Behaviour scopes |
| `process_effective_reputation` | CBC reputation classification |
| `alert_category`, `ttp` | Alert / TTP enrichment |

**Time scope** is set via the search interface time picker, not inline.

---

## 3. Watchlists, Reports, and IOCs

CBC's authoring hierarchy:

```
Watchlist  ──contains──▶  Report  ──contains──▶  IOC(s)
                                              │  ├─ query (saved process search)
                                              │  ├─ equality (atomic value match)
                                              │  └─ regex (pattern match)
```

| Concept | Description |
|---|---|
| **Watchlist** | Subscription unit — a tenant subscribes to a Watchlist and receives alerts for any matching report |
| **Report** | A named detection — title, description, severity, IOCs, optional tags, optional MITRE mapping |
| **IOC** | The atomic match — query, equality, or regex |

### Authoring discipline

- **One TTP per Report.** Do not pack multiple unrelated detections into a single Report (CBC's analogue of AP-H2 Kitchen Sink).
- **Severity calibration.** Reserve Severity 8–10 for high-confidence detections that justify analyst paging. Most behavioural detections sit at Severity 5–7.
- **MITRE mapping** populated in the Report metadata, not just inline.
- **Report tags** for taxonomy (e.g. `T1059`, `Initial Access`, `RansomwarePrecursor`).
- **Description prose** documents intent, FP scenarios, and triage steps — CBC alerts surface this directly to analysts.

### Watchlist hygiene

- Custom watchlists scoped to a tenant; subscribed alongside vendor watchlists.
- Periodic review of report-level alert volume — high-volume reports tune or disable.
- Keep IOC-only reports separate from query reports; they have different update cadences.

---

## 4. Scheduled searches (API-driven)

For detections requiring aggregation across many events (e.g. beaconing, frequency-based anomaly), use the Scheduled Search API:

| Field | Detail |
|---|---|
| `query` | CBC process search query |
| `interval` | Cadence (configurable) |
| `device_filter` | Optional scope filter |
| `notification_action` | Email / webhook / SOAR endpoint on hit |

Scheduled searches do **not** generate alerts in the alert pipeline by default — they fire notifications. For alert-pipeline integration, the workflow typically writes results back into a Watchlist Report or SIEM.

---

## 5. Sensor capability boundaries

| Capability | Windows | macOS | Linux |
|---|---|---|---|
| Process tree | Full | Full | Full |
| Command line | Full | Full | Full (per kernel) |
| File modifications | Full | Full | Full |
| Network connections | Full | Full | Full |
| Registry | Full | n/a | n/a |
| DNS | Full (Endpoint Standard tier) | Full | Limited |
| Cross-process events | Full | Limited | Limited |
| ScriptBlock content (PowerShell) | Full | Limited | n/a |

**Tier matters**: Endpoint Standard (NGAV-only) is **not** the same SKU as Enterprise EDR. Detection content requiring process-tree depth or behavioural data needs Enterprise EDR licensing on the host.

---

## 6. NGAV alerts vs EDR detections

Two separate alert categories on the same sensor:

| Source | Alert type | Notes |
|---|---|---|
| **NGAV** (Predictive Cloud Engine) | TTP / Carbon Black Reputation / Malware | Sensor-side prevention/detection |
| **Watchlist** | Custom or subscribed Report hit | Cloud-side analysis |
| **CB Threat Intel feeds** | Vendor / CB-curated IOC matches | Hash, IP, domain |

Custom detection content lives in Watchlists. NGAV behavioural rules are vendor-managed.

---

## 7. Alert override / interrupt

CBC supports **override** rules for known-good behaviour:

| Override type | Scope |
|---|---|
| Hash override | Allow a specific SHA256 |
| Path override | Allow a specific binary path |
| Cert override | Allow a specific signer |
| IT tool override | Sanction enterprise tools that trigger NGAV |

Author detection content with awareness of overrides — a generic ransomware detection that hits because of a backup tool will be silenced via override rather than tuned in the rule. Document expected override patterns in the Report description.

---

## 8. Live Response

Constrained sensor-side shell. Commands include:

| Category | Examples |
|---|---|
| **Read-only** | `ps`, `dir`, `cat`, `reg query`, `netstat` |
| **Investigative** | `memdump`, `get`, `kill` |
| **State-changing** | `put`, `rm`, `delete`, `execfg` |

Same authoring discipline as CrowdStrike RTR: read-only first, document intent before automation, no embedded secrets.

---

## 9. Entity identifier alignment

| Concept | CBC | Microsoft Defender | Sentinel | CrowdStrike |
|---|---|---|---|---|
| Host | `device_id`, `device_name` | `DeviceId`, `DeviceName` | `Computer` | `aid`, `ComputerName` |
| User | `process_username` | `AccountName`, `AccountUpn` | `UserPrincipalName` | `UserName` |
| Process | `process_guid` (stable) | `ProcessUniqueId` | n/a | `ContextProcessId_decimal` |
| Hash | `process_hash` (SHA256/MD5) | `SHA256` | `FileHash` | `SHA256HashData` |

`process_guid` is CBC's stable per-process identifier — use it for chain correlation, not PIDs.

---

## 10. Mapping into OpenTide MDR

When CBC content lives in `configurations.carbon_black_cloud`:

- **Identify the surface** (Watchlist Report / Scheduled Search / API IOC) in the configuration block.
- **Watchlist Report metadata** (title, description, severity, MITRE tags) populated; the MDR `description` mirrors / extends with operational context.
- **Sensor tier requirement** declared (Endpoint Standard vs Enterprise EDR) so reviewers can assess fitness.
- Coordinate with `opentide-detection-rule` for placement and `detection-engineering` for lifecycle.

---

## 11. Quality checklist

- [ ] Surface identified (Watchlist Report / Scheduled Search / IOC).
- [ ] One TTP per Report.
- [ ] Severity calibrated (high values reserved for paging-worthy).
- [ ] MITRE mapping in Report metadata + MDR description.
- [ ] Process correlation via `process_guid`, not PID.
- [ ] Sensor tier requirement declared.
- [ ] Override patterns documented in Report description.
- [ ] FP triage steps in description.
- [ ] Live Response scripts reviewed before automation.
