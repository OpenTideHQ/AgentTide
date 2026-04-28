---
name: kusto-query-language
description: Writes and reviews Kusto Query Language (KQL) for Microsoft Sentinel and Log Analytics—schema discipline, time bounding, joins, performance, and mapping into OpenTide MDR Sentinel configurations. Use when authoring or tuning Sentinel queries, hunting searches, or scheduled analytics rules.
---

# Kusto Query Language (KQL) for detection

## Goal

Produce **correct, efficient** KQL that fits **MDR `configurations.sentinel`** (or equivalent) blocks and behaves predictably at SOC scale.

## Baseline pattern

1. **Table last** — Start from the narrowest table or materialised view the tenant actually ingests.
2. **Time first** — Always bound with `where TimeGenerated > ago(...)` (or event-time column if non-standard and documented).
3. **Project early** — Reduce columns before heavy operators.
4. **Join small-on-large** — Build the smaller side first; avoid broadcast joins without need.
5. **Materialise when repeating** — `materialize()` for reused expensive extracts (use sparingly).

## Sentinel-oriented tables (examples)

Exact names depend on data connectors — **verify** in the workspace:

- `SecurityAlert`, `SecurityIncident` — SOC workflow.
- `SecurityEvent`, `WindowsEvent` — Windows security channel style.
- `Device*`, `Email*`, `Identity*` — Defender / M365 shapes when present.
- Custom logs — follow normalised column conventions from the tenant.

## Detection logic hygiene

- **Explicit intent** — Name flags (`IsSuspicious`, `Reason`) rather than opaque boolean soup.
- **Allow-lists** — Centralise exclusions the operator can tune (VIP accounts, patching hosts).
- **Rate limits** — Consider `summarize ... by bin(TimeGenerated, 5m)` and thresholds to reduce noise storms.
- **Data skew** — `take` during exploration only; production rules must be deterministic.

## OpenTide alignment

When embedding KQL inside an **MDR**, ensure:

- The query implements a **specific DOM signal** (or subset) and references that intent in **`description`** / comments.
- **Alert tuning** narratives in YAML match what the query actually filters.

## Anti-patterns

- Unbounded scans across high-volume tables.
- Joining on volatile columns without aggregation.
- Copy-pasting hunting queries verbatim as scheduled rules without false-positive review.
