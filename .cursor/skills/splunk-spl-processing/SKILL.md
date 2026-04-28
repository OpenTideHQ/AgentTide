---
name: splunk-spl-processing
description: Splunk Enterprise / ES SPL guidance for correlating searches and detection logic embedded in Splunk-deployment blocks (splunk:: schema families in CoreTide). Covers command ordering, indexing-time awareness, lookups, macros, accelerating frameworks, SPL versus KQL conceptual translation notes. Pair with detection-engineering for production alerting lifecycle. Use for splunk keyed sections in OpenTide detection rules—not for Microsoft platforms.
---

# Splunk Processing Language (SPL core habits)

Splunk ingestion partitions data into sourcetypes/indexes/host metadata—queries must constrain **earliest/latest** aggressively and push **indexed fields** filters forward.

### Discipline

| Practice | SPL angle |
|-----------|-----------|
| Time bounding | Prefer `index=<>` + `_time`-bounded windows aligned to intended detection cadence; avoid unintentional full-index scans.|
| Density | Use `stats`/`tstats`/`mstats` wisely—`tstats`/metrics where dataset supports acceleration.|
| Macros & lookups | Maintain lookup hygiene (KV store performance, replication drift).|
| Scheduling | Honour correlation search concurrency & alert_actions vs phantom noise—pair with SOC response expectations authored in **`detection-engineering`** when operationalising hunts.|

### Translation mindset from KQL

| KQL impulse | SPL analogue reminder |
|-------------|-----------------------|
| `summarize … by bin(TimeGenerated,5m)` | `timechart`/`bin _time`/stats by `_time` bucket |
| `join` cardinality controls | **`join`** vs **`lookup`** vs **`subsearch`** cost trade-offs—subsearches sting at scale|

### OpenTide mapping

Treat SPL text under **`configurations.splunk`** (or templated equivalents) exactly like other vendor blobs: deterministic, reviewer-testable searches with documented assumptions in `description`/procedure fields rather than orphaned query fragments.
