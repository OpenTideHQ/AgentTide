---
name: splunk-spl-processing
description: Splunk Enterprise / Enterprise Security SPL authoring discipline for hunting and correlation searches deployed via OpenTide MDR configurations.splunk blocks. Covers index/sourcetype filtering, time bounding, transforming vs streaming command semantics, stats vs tstats vs mstats, accelerated data models, lookups and KV stores, eventtypes/tags, macros, ES correlation search lifecycle, notable events, risk-based alerting, summary indexing, and SPL vs KQL conceptual translation. Use for splunk-keyed configurations in OpenTide detection rules.
---

# Splunk SPL — hunting & correlation search authoring

Author and review SPL for Splunk Enterprise / Enterprise Security. The discipline here mirrors the rigour applied to KQL in `kusto-query-language` — filter early, structure deliberately, and document every assumption.

---

## 1. Search-time discipline

### 1.1 Always lead with index, sourcetype, time

Splunk searches without an index constraint scan every index the user can read. Always start a search with the most selective root expression Splunk offers:

```spl
index=wineventlog sourcetype="WinEventLog:Security" earliest=-7d@d latest=now
```

| Construct | Use |
|---|---|
| `index=` | Primary partition — always include |
| `sourcetype=` | Schema-level filter — narrow further |
| `host=`, `source=` | Index-time fields — fast |
| `earliest=` / `latest=` | Time bound — relative (`-24h`, `-7d@d`) or absolute |

**Time tokens**: `@d` snaps to start of day; `@h` to start of hour. `-7d@d` is "midnight 7 days ago" — typically what you want. Unsnapped (`-7d`) creates a sliding window relative to "now" which leaks event-time variance.

### 1.2 Indexed vs search-time fields

Splunk extracts fields in two phases:

- **Index-time fields** (`index`, `sourcetype`, `source`, `host`, `_time`, anything in `transforms.conf`) — filtered without parsing.
- **Search-time fields** (everything else) — extracted per matching event.

**Filter on index-time fields first; search-time fields last.** This is the Splunk equivalent of KQL's "filter early" rule.

```spl
// GOOD: index-time filter precedes search-time field
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688
| where like(CommandLine, "%-encodedcommand%")

// BAD: search-time filter forces parsing before index narrowing
| where like(CommandLine, "%-encodedcommand%")
| search index=wineventlog
```

### 1.3 Streaming vs transforming commands

Streaming commands (`eval`, `where`, `rex`, `fields`) operate per-event and parallelise across indexers. Transforming commands (`stats`, `chart`, `timechart`, `top`, `dedup`) collect events to a single search head.

**Push streaming work before transforming work**. Once `stats` runs, the search head is the bottleneck.

```spl
// GOOD: filter and project before stats
index=wineventlog EventCode=4688
| where match(CommandLine, "(?i)-(enc|encodedcommand)")
| eval ParentName=lower(ParentImage)
| fields _time, host, User, CommandLine, ParentName
| stats count by host, ParentName

// BAD: project after stats
index=wineventlog EventCode=4688
| stats count by host, CommandLine, ParentImage
| where match(CommandLine, "(?i)-(enc|encodedcommand)")
```

---

## 2. `stats` vs `tstats` vs `mstats`

| Command | Source | Speed | Use when |
|---|---|---|---|
| `stats` | Raw events | Slowest — full event read | Default; fields not in tsidx |
| `tstats` | Indexed fields (tsidx) only | 10–100× faster | All needed fields are index-time / accelerated |
| `mstats` | Metrics index | Fast | Metric data (numeric time series) |

### `tstats` patterns

```spl
// Direct against tsidx (index-time fields only)
| tstats count where index=wineventlog sourcetype="WinEventLog:Security" by host

// Against an accelerated data model
| tstats summariesonly=true count from datamodel=Endpoint.Processes
    where Processes.process_name=powershell.exe
    by Processes.dest, Processes.user, Processes.process

// Always pair tstats with summariesonly=true on accelerated data models —
// without it, Splunk falls back to raw events for unaccelerated time ranges
```

**Accelerated data models** (Common Information Model — CIM): authentication, network traffic, malware, web, change. ES correlation searches typically run against accelerated CIM data models for performance.

### `mstats` for metrics

```spl
| mstats avg(_value) prestats=true span=5m where index=metrics_security
    metric_name="auth.failures"
| timechart avg(_value) span=5m
```

---

## 3. Lookups, KV store, eventtypes, macros

### Lookups

```spl
... | lookup threat_intel_feed indicator AS src_ip OUTPUT category, severity
```

| Lookup type | Backend | Use when |
|---|---|---|
| CSV | File on search head | Static reference (tier 0 list, asset inventory) |
| KV store | MongoDB-backed | Dynamic, replicated, large reference data |
| External | Python script | API-driven enrichment |

**Hygiene**: Validate `lookup_definition` exists; use `OUTPUT` (replace) vs `OUTPUTNEW` (preserve existing) deliberately; keep CSV lookups under ~1 M rows or migrate to KV store.

### Eventtypes and tags

`eventtype=` references a saved search filter; `tag=` references a category applied via `eventtypes.conf`. Both are search-time, but they make searches portable across deployments where source naming differs:

```spl
// Portable across deployments using CIM:
tag=authentication tag=failure
| stats count by user, src
```

### Macros

Splunk macros (`macros.conf`) are reusable SPL fragments invoked with backticks:

```spl
`security_indexes`
| `windows_authentication_failures`
| stats count by user, src
```

Author detection logic to use established CIM tags and tenant macros where possible — improves portability and survives source/index renames.

---

## 4. Enterprise Security: correlation searches

### Lifecycle

1. **Hunting search** validated as ad-hoc.
2. **Saved as scheduled** correlation search (typically every 5–15 min, lookback aligned).
3. **Adaptive Response**: notable event creation (`alert_action.notable`), risk score boost (`alert_action.risk`), TTP annotation, automation hooks.
4. **Tuning** via thresholds, suppression, exclusions.
5. **Risk-based alerting (RBA)**: low-fidelity findings boost a per-entity risk score; high-cumulative scores escalate.

### Notable events

```spl
... | `get_correlation_search_annotations`
| eval rule_name="Suspicious PowerShell Execution",
       severity=high,
       src=host,
       dest=host,
       user=User,
       signature="T1059.001",
       description="powershell -enc invocation matching loader profile"
```

The `notable` alert action ingests this into ES's `notable` index for analyst triage.

### Risk-based alerting

```spl
... | eval risk_message="Unusual login from impossible-travel pair",
       risk_object=user, risk_object_type="user", risk_score=40,
       threat_object=src_ip, threat_object_type="ip_address"
| `risk_modifier`
```

RBA correlation searches should be **low-fidelity, high-volume signals** that aggregate per-entity over time. Notable creation reserved for high-fidelity rules or when cumulative risk exceeds thresholds.

### Suppression

In ES correlation search definition: `Throttling` field controls suppression by entity (`src`, `dest`, `user`) for a configurable window. Always set throttling on production correlation searches — duplicate notables erode analyst trust.

### Summary indexing

For long lookback aggregations that would re-scan terabytes nightly:

```spl
// Schedule daily; collect rolled-up data into summary index
index=wineventlog earliest=-1d@d latest=@d
| stats dc(user) AS unique_users count AS event_count by host, sourcetype
| collect index=summary_endpoint sourcetype=daily_rollup
```

Detection searches then run against the summary index instead of raw events.

---

## 5. Common SPL idioms

```spl
// Top-N + percentage
| stats count by user
| eventstats sum(count) AS total
| eval pct = round(count * 100.0 / total, 2)
| sort - count

// Beaconing detection (interval consistency)
index=proxy sourcetype=proxy_logs earliest=-7d@d
| stats min(_time) AS first_seen max(_time) AS last_seen count AS conn_count
    list(_time) AS times
    by src dest dest_port
| where conn_count > 20
| eval intervals = mvrange(first_seen, last_seen, (last_seen - first_seen) / conn_count)
| eval mean_interval = (last_seen - first_seen) / (conn_count - 1)
| eval stdev_interval = stdev(mvmap(times, _time - first_seen))
| where (stdev_interval / mean_interval) < 0.2

// Impossible travel (per-user pairwise)
| sort 0 user, _time
| streamstats current=false last(_time) AS prev_time last(country) AS prev_country by user
| where country != prev_country
| eval delta_min = (_time - prev_time) / 60
| where delta_min > 0 AND delta_min < 60

// Rare-process per host (anomaly via dcount)
| stats dc(host) AS host_count by process_name
| where host_count <= 3
```

---

## 6. SPL vs KQL — conceptual translation

| KQL | SPL |
|---|---|
| `where TimeGenerated > ago(7d)` | `earliest=-7d@d` |
| `where Column has "value"` | `Column=*value*` (or CIM tagged search) |
| `where Column == "value"` | `Column="value"` |
| `where Column in (a,b,c)` | `Column IN (a, b, c)` |
| `summarize count() by X, bin(Time, 5m)` | `bin _time span=5m \| stats count by X, _time` |
| `summarize arg_max(Time, *) by Key` | `... \| dedup Key sortby -_time` (or `stats latest(*) by Key`) |
| `join kind=inner` | Avoid — use `lookup`, `subsearch`, or summary indexing |
| `materialize()` | Summary indexing or `tstats from datamodel=...` against accelerated DMs |
| `parse_json()` | `spath` |
| `extend` | `eval` |
| `let var = ...` | `| eval` early in pipeline, or saved macro |
| Comments `//` | Triple-backtick block comments (see §7 below) |

**Critical mindset shift**: `join` in SPL is expensive at scale. Use `lookup` for static reference data, `subsearch` (`search ... [search ...]`) for small primary sets, or accelerated data models for cross-sourcetype correlation.

---

## 7. Comment discipline

Splunk comments use triple backticks:

````spl
``` Detection: Suspicious encoded PowerShell ```
``` Source: <reference> ```
``` MITRE: T1059.001 ```
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688 earliest=-7d@d
| where match(CommandLine, "(?i)-(enc|encodedcommand)")
| stats count by host, User, CommandLine
````

Apply the same header structure used in KQL (Hunt, Source, MITRE, Platform). Production correlation searches should also document their notable / RBA configuration at the top.

---

## 8. Quality checklist

- [ ] `index=` and `sourcetype=` (or CIM tag/eventtype) present.
- [ ] Time bound via `earliest=` / `latest=`, snapped where appropriate.
- [ ] Streaming commands precede transforming commands.
- [ ] `stats` only when `tstats` against accelerated DM is not viable.
- [ ] `summariesonly=true` on `tstats from datamodel=...`.
- [ ] No unnecessary `join` — replaced with `lookup` / `subsearch` / summary index where possible.
- [ ] `make_set()`-equivalent constructs (`values()`, `mvlist()`) bounded for high-cardinality fields.
- [ ] Header comment block populated.
- [ ] Suppression / throttling configured on correlation searches.
- [ ] Notable / RBA fidelity choice deliberate and documented.

---

## 9. Mapping into OpenTide MDR

When SPL is wired into a `configurations.splunk` block in an OpenTide MDR object:

- Description, tuning narrative, severity, response procedure → MDR `description` and `response.*` fields per MDR schema.
- Inline SPL still carries the header block and comment discipline above.
- Coordinate with `opentide-detection-rule` for placement and `detection-engineering` for hunt-to-rule conversion.

---

## 10. Reference catalogues

- `references/Anti-Patterns.md` — AP-S1 through AP-S12 SPL anti-pattern rejection checklist.
