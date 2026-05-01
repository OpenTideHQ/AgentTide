---
name: splunk
description: Splunk Enterprise / Enterprise Security SPL authoring discipline for detection engineering. Covers search-time discipline (index/sourcetype/time), streaming vs transforming command semantics, stats vs tstats vs mstats, CIM data model catalogue, three-layer macro architecture (source/process/filter), detection type patterns (TTP/Anomaly/Hunting/Correlation/Baseline), anomaly detection with eventstats 3-sigma, eval function reference, ES correlation search lifecycle, notable events, risk-based alerting (RBA), lookup patterns, and SPL vs KQL conceptual translation. Distilled from analysis of 2000+ production detections in splunk/security_content. Use for splunk-keyed configurations in OpenTide detection rules.
---

# Splunk SPL — detection engineering

Author and review SPL for Splunk Enterprise / Enterprise Security. The discipline here mirrors the rigour applied to KQL in `kusto-query-language` — filter early, structure deliberately, and document every assumption.

> **Distilled from**: Analysis of 2009 production detections, 234 macros, and 104 lookups in [splunk/security_content](https://github.com/splunk/security_content) (ESCU v5.26+).
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

### The three-layer macro architecture

Production detection frameworks (e.g., ESCU) use a three-layer macro system for portability:

**Layer 1 — Source macros** (index/sourcetype abstraction):

| Macro | Purpose | Customer action |
|---|---|---|
| `` `wineventlog_security` `` | Windows Security log | Replace with local index/sourcetype |
| `` `sysmon` `` | Sysmon operational log | Replace with local source |
| `` `powershell` `` | PowerShell operational log | Replace with local source |
| `` `cloudtrail` `` | AWS CloudTrail | Replace with local sourcetype |
| `` `okta` `` | Okta System Log | Replace with local sourcetype |
| `` `linux_auditd` `` | Linux auditd | Replace with local sourcetype |

**Layer 2 — Process macros** (binary matching with anti-evasion):

```spl
`process_powershell`
// Expands to: (Processes.process_name=pwsh.exe OR Processes.process_name=powershell.exe
//              OR Processes.original_file_name=pwsh.dll OR Processes.original_file_name=PowerShell.EXE)
```

Matching by both `process_name` and `original_file_name` catches renamed binaries.

**Layer 3 — Filter macros** (FP tuning):

Every detection ends with `` `<detection_name>_filter` `` — empty by default (`search *`). Customers add environment-specific exclusions without modifying the detection itself.

```spl
| `suspicious_powershell_execution_filter`
```

**Principle**: Detections are write-once, deploy-anywhere. Customers modify macros, never the search.

---

## 4. CIM data model catalogue

The Common Information Model (CIM) normalises data across sources. `tstats` against accelerated CIM data models is 10–100× faster than raw search.

| Data model | Node | Detection use | Example fields |
|---|---|---|---|
| `Endpoint` | `Processes` | Process execution, command-line, LOLBAS | `process_name`, `process`, `parent_process`, `dest`, `user` |
| `Endpoint` | `Registry` | Registry modifications, persistence | `registry_path`, `registry_value_data`, `dest` |
| `Endpoint` | `Filesystem` | File creation/deletion, ransomware | `file_name`, `file_path`, `action`, `dest` |
| `Endpoint` | `Services` | Service installation, persistence | `service_name`, `start_mode`, `dest` |
| `Network_Traffic` | `All_Traffic` | Port scans, lateral movement, C2 | `src`, `dest`, `dest_port`, `transport`, `action` |
| `Network_Resolution` | (DNS) | DNS exfiltration, DGA | `query`, `answer`, `query_type`, `src` |
| `Web` | (default) | Web attacks, SQLi, webshells | `url`, `http_method`, `status`, `src`, `dest` |
| `Authentication` | (default) | Logon events, brute force | `user`, `src`, `dest`, `action`, `app` |
| `Change` | `All_Changes` | Account/config changes | `user`, `object`, `action`, `command` |
| `Risk` | `All_Risk` | RBA correlation | `risk_object`, `risk_score`, `source`, `annotations` |

### `tstats` + data model canonical pattern

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  FROM datamodel=Endpoint.Processes
  WHERE <filter_conditions>
  BY Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| <post_processing>
| `<detection_name>_filter`
```

Key macros:
- `` `security_content_summariesonly` `` — controls `summariesonly` flag for acceleration
- `` `drop_dm_object_name(Processes)` `` — strips data model prefix from field names
- `` `security_content_ctime(field)` `` — converts epoch to human-readable timestamp

---

## 5. Detection type patterns

Different detection types have distinct SPL shapes:

### TTP (Tactics, Techniques, Procedures) — ~60% of detections

Direct pattern matching. Highest confidence.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  FROM datamodel=Endpoint.Processes
  WHERE Processes.process_name=ntdsutil.exe Processes.process="*ac i ntds*"
  BY Processes.dest, Processes.user, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `ntdsutil_export_ntds_filter`
```

### Anomaly — ~20% of detections

Statistical deviation from baseline using `eventstats` + 3-sigma.

```spl
`wineventlog_security` EventCode=4776 TargetUserName!=*$ Status=0xC000006A
| bucket span=2m _time
| stats dc(TargetUserName) AS unique_accounts values(TargetUserName) as tried_accounts
  BY _time, Workstation
| eventstats avg(unique_accounts) as comp_avg, stdev(unique_accounts) as comp_std BY Workstation
| eval upperBound=(comp_avg+comp_std*3)
| eval isOutlier=if(unique_accounts > 10 AND unique_accounts >= upperBound, 1, 0)
| search isOutlier=1
```

### Hunting — ~10% of detections

Broader filters, more context in output. Lower confidence, higher volume.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  FROM datamodel=Endpoint.Processes
  WHERE Processes.process="*-enc*" OR Processes.process="*-encodedcommand*"
  BY Processes.dest, Processes.user, Processes.process
| `drop_dm_object_name(Processes)`
| where match(process, "(?i)-(enc|encodedcommand)")
```

### Correlation (RBA) — ~5% of detections

Aggregates risk events from the Risk data model.

```spl
| tstats `security_content_summariesonly` min(_time) as firstTime max(_time) as lastTime
  sum(All_Risk.calculated_risk_score) as risk_score
  count(All_Risk.calculated_risk_score) as risk_event_count
  values(All_Risk.annotations.mitre_attack.mitre_tactic_id) as annotations.mitre_attack.mitre_tactic_id
  dc(source) as source_count
  FROM datamodel=Risk.All_Risk
  WHERE All_Risk.analyticstories="<Story Name>" All_Risk.risk_object_type="system"
  BY All_Risk.risk_object All_Risk.risk_object_type
| `drop_dm_object_name(All_Risk)`
| where source_count >= 5
```

### Baseline — ~5% of detections

Builds historical lookup tables. Not alerting — scheduled to run periodically.

```spl
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Services
  BY _time, Services.service_name, Services.dest span=1d
| `drop_dm_object_name(Services)`
| inputlookup append=t previously_seen_running_windows_services
| stats min(firstTimeSeen) as firstTimeSeen by service_name, dest
| outputlookup previously_seen_running_windows_services
```

---

## 6. Enterprise Security: correlation searches

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

## 7. Common SPL idioms

```spl
// Top-N + percentage
| stats count by user
| eventstats sum(count) AS total
| eval pct = round(count * 100.0 / total, 2)
| sort - count

// Beaconing detection (interval consistency)
index=proxy sourcetype=proxy_logs earliest=-7d@d
| sort 0 src, dest, dest_port, _time
| streamstats current=false last(_time) AS prev_time by src, dest, dest_port
| where isnotnull(prev_time)
| eval interval = _time - prev_time
| stats count AS conn_count avg(interval) AS mean_interval stdev(interval) AS stdev_interval
    by src, dest, dest_port
| where conn_count > 20
| eval cv = stdev_interval / mean_interval
| where cv < 0.2

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

## 8. Eval function reference

Key `eval` functions for detection engineering:

| Function | Purpose | Example |
|---|---|---|
| `if(cond, true, false)` | Conditional value | `eval severity=if(count>100, "high", "medium")` |
| `case(c1,v1, c2,v2, ...)` | Multi-branch conditional | `eval category=case(port==22,"ssh", port==3389,"rdp", 1==1,"other")` |
| `coalesce(f1, f2, ...)` | First non-null value | `eval user=coalesce(TargetUserName, SubjectUserName)` |
| `match(field, regex)` | Regex match (boolean) | `where match(process, "(?i)mimikatz")` |
| `like(field, pattern)` | Wildcard match | `where like(CommandLine, "%-encodedcommand%")` |
| `cidrmatch(cidr, ip)` | CIDR range match | `where cidrmatch("10.0.0.0/8", src_ip)` |
| `mvfilter(expr)` | Filter multivalue field | `eval bad_ports=mvfilter(match(dest_port, "^(4444|5555)$"))` |
| `mvcount(field)` | Count multivalue entries | `where mvcount(dest_port) > 5` |
| `mvindex(field, start, end)` | Slice multivalue field | `eval first_value=mvindex(values, 0)` |
| `mvjoin(field, delim)` | Join multivalue to string | `eval port_list=mvjoin(dest_port, ",")` |
| `split(field, delim)` | String to multivalue | `eval parts=split(process, "\\")` |
| `replace(field, regex, repl)` | Regex replace | `eval clean=replace(url, "\?.*$", "")` |
| `substr(field, start, len)` | Substring extraction | `eval ext=substr(file_name, -4)` |
| `len(field)` | String length | `where len(CommandLine) > 500` |
| `tonumber(field, base)` | String to number | `eval hex_val=tonumber(Status, 16)` |
| `tostring(field, format)` | Number to string | `eval time_str=tostring(_time, "commas")` |
| `strftime(time, format)` | Epoch to formatted string | `eval date=strftime(_time, "%Y-%m-%d")` |
| `strptime(str, format)` | String to epoch | `eval epoch=strptime(timestamp, "%Y-%m-%dT%H:%M:%S")` |
| `relative_time(time, spec)` | Time arithmetic | `eval yesterday=relative_time(now(), "-1d@d")` |
| `now()` | Current epoch time | `eval age=now()-_time` |
| `lower(field)` / `upper(field)` | Case normalisation | `eval proc=lower(process_name)` |
| `urldecode(field)` | URL decode | `eval decoded=urldecode(url)` |
| `base64decode(field)` | Base64 decode (via macro) | `` eval decoded=`base64decode(encoded_field)` `` |
| `spath(field, path)` | JSON/XML extraction | `eval user=spath(_raw, "actor.alternateId")` |
| `json_extract(field, path)` | JSON field extraction | `eval val=json_extract(event_data, "$.CommandLine")` |

### Stats function reference

| Function | Purpose | Notes |
|---|---|---|
| `count` | Event count | Most common |
| `dc(field)` | Distinct count | Lateral movement (dc of hosts), brute force (dc of users) |
| `values(field)` | Distinct values (sorted) | Context preservation |
| `list(field)` | All values (unsorted, with dupes) | Raw enumeration |
| `earliest(field)` / `latest(field)` | First/last by `_time` | Timeline analysis |
| `first(field)` / `last(field)` | First/last in result order | Order-dependent |
| `sum(field)` / `avg(field)` | Arithmetic aggregation | Risk score totals, averages |
| `min(field)` / `max(field)` | Range bounds | Time windows (`min(_time)`, `max(_time)`) |
| `stdev(field)` / `var(field)` | Statistical dispersion | Anomaly detection (3-sigma) |
| `perc<N>(field)` | Percentile | `perc95(response_time)` for outlier detection |
| `mode(field)` / `median(field)` | Central tendency | Baseline establishment |

---

## 9. SPL vs KQL — conceptual translation

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

## 10. Comment discipline

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

## 11. Quality checklist

- [ ] `index=` and `sourcetype=` (or CIM tag/eventtype/source macro) present.
- [ ] Time bound via `earliest=` / `latest=`, snapped where appropriate.
- [ ] Streaming commands precede transforming commands.
- [ ] `tstats` used when all needed fields are in an accelerated CIM data model.
- [ ] `summariesonly=true` (via macro) on `tstats from datamodel=...`.
- [ ] `drop_dm_object_name()` applied after `tstats` to strip data model prefix.
- [ ] `security_content_ctime()` applied to `firstTime` / `lastTime` fields.
- [ ] No unnecessary `join` — replaced with `lookup` / `subsearch` / summary index.
- [ ] Source macro used for index/sourcetype abstraction (portability).
- [ ] Filter macro (`` `<detection_name>_filter` ``) appended as last pipe.
- [ ] Process matching uses both `process_name` and `original_file_name` where applicable.
- [ ] Anomaly detections use `eventstats avg/stdev` + threshold, not arbitrary magic numbers.
- [ ] Header comment block populated (detection name, source, MITRE, platform).
- [ ] Suppression / throttling configured on correlation searches.
- [ ] Notable / RBA fidelity choice deliberate and documented.
- [ ] Detection type (TTP/Anomaly/Hunting/Correlation/Baseline) matches the SPL pattern.

---

## 12. Mapping into OpenTide MDR

When SPL is wired into a `configurations.splunk` block in an OpenTide MDR object:

- Description, tuning narrative, severity, response procedure → MDR `description` and `response.*` fields per MDR schema.
- Inline SPL still carries the header block and comment discipline above.
- Coordinate with `opentide-detection-rule` for placement and `detection-engineering` for hunt-to-rule conversion.

---

## 13. Reference catalogues

- `references/Anti-Patterns.md` — AP-S1 through AP-S12 SPL anti-pattern rejection checklist.
