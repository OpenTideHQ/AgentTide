# Splunk SPL Anti-Patterns (AP-S1 — AP-S12)

Common anti-patterns in SPL query design for Splunk Enterprise / Enterprise Security. Use as a rejection checklist.

---

## AP-S1: The Indexless Search

**Pattern**: No `index=` constraint — scans every index the user can read.

```spl
// BAD
sourcetype="WinEventLog:Security" EventCode=4688

// GOOD
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688
```

**Why it fails**: Without `index=`, Splunk scans all permitted indexes. On a multi-TB deployment this is catastrophically slow and may hit search quota limits.

---

## AP-S2: The Timeless Search

**Pattern**: No `earliest=` / `latest=` time bound.

```spl
// BAD
index=wineventlog EventCode=4625

// GOOD
index=wineventlog EventCode=4625 earliest=-7d@d latest=now
```

**Why it fails**: Unbounded searches scan the full retention window. Always include time bounds justified in the rationale.

---

## AP-S3: The Premature Transform

**Pattern**: Transforming command (`stats`, `chart`, `timechart`) before streaming filters.

```spl
// BAD: stats runs on millions of events, then filters
index=wineventlog EventCode=4688 earliest=-7d@d
| stats count by host, CommandLine
| where match(CommandLine, "(?i)-(enc|encodedcommand)")

// GOOD: streaming filter first, then aggregate
index=wineventlog EventCode=4688 earliest=-7d@d
| where match(CommandLine, "(?i)-(enc|encodedcommand)")
| stats count by host, CommandLine
```

**Why it fails**: `stats` materialises all groups on the search head before post-aggregation filters apply. Streaming commands (`where`, `eval`, `rex`) parallelise across indexers.

---

## AP-S4: The Subsearch Bomb

**Pattern**: Subsearch returning too many results (default cap: 10,000 results, 60 seconds).

```spl
// BAD: subsearch may hit the 10k cap silently
index=proxy [search index=threat_intel | fields indicator]

// GOOD: use lookup instead
index=proxy
| lookup threat_intel_lookup indicator AS dest_ip OUTPUT category
| where isnotnull(category)
```

**Why it fails**: Subsearches have hard limits (10k results, 60s timeout). Exceeding them silently truncates results — the search appears to work but misses matches. Use `lookup` or `inputlookup` for reference data.

---

## AP-S5: The Join Addiction

**Pattern**: Using `join` for correlation instead of `lookup`, `stats`, or data models.

```spl
// BAD: join is expensive and memory-bound
index=wineventlog EventCode=4624
| join type=inner host [search index=wineventlog EventCode=4688]

// GOOD: stats-based correlation
index=wineventlog (EventCode=4624 OR EventCode=4688) earliest=-1d@d
| stats values(EventCode) AS events dc(EventCode) AS event_types by host, user
| where event_types >= 2
```

**Why it fails**: `join` loads the entire right side into memory on the search head. For large datasets, use `stats` with multi-event correlation, `lookup` for reference data, or accelerated data models with `tstats`.

---

## AP-S6: The stats-When-tstats-Works

**Pattern**: Using `stats` against raw events when `tstats` against an accelerated data model would be 10-100x faster.

```spl
// BAD: full event scan
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688
| stats count by host, user

// GOOD: accelerated data model
| tstats summariesonly=true count from datamodel=Endpoint.Processes
    where Processes.action=allowed
    by Processes.dest, Processes.user
```

**Why it fails**: `tstats` reads from pre-built tsidx summaries. `stats` reads and parses every raw event. The performance difference is dramatic on large datasets.

**Caveat**: `summariesonly=true` only returns data from accelerated time ranges. Without it, Splunk falls back to raw events for unaccelerated periods.

---

## AP-S7: The Unthrottled Notable

**Pattern**: ES correlation search with no throttling — generates duplicate notables for the same entity.

```spl
// BAD: fires a notable for every matching event
... | sendalert notable

// GOOD: throttle by entity
... | sendalert notable
// Throttling: fields="user,src" duration="1h"
```

**Why it fails**: Without throttling, a brute-force attack generating 1000 events creates 1000 notables. Analysts drown. Always set throttling fields that define alert uniqueness.

---

## AP-S8: The Macro Black Box

**Pattern**: Detection query relies on undocumented macros that reviewers cannot evaluate.

```spl
// BAD: what does this macro expand to?
`soc_macro_exclude_scanners`
| `windows_authentication_failures`
| stats count by user, src

// GOOD: inline the logic or document the macro
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625 earliest=-1d@d
| where NOT match(src, "10\.0\.1\.(50|51)")  // vulnerability scanners
| stats count by user, src
| where count > 50
```

**Why it fails**: Macros are opaque to reviewers and portable deployments. Either inline the logic or document what each macro resolves to in the MDR description.

---

## AP-S9: The Unbounded make_values

**Pattern**: `values()` or `list()` without size limits on high-cardinality fields.

```spl
// BAD: an IP with 50k+ users yields gigabytes
| stats values(user) AS all_users by src_ip

// GOOD: limit and count separately
| stats values(user) AS user_sample dc(user) AS user_count by src_ip
| where user_count > 10
```

**Why it fails**: `values()` collects every distinct value. On high-cardinality fields this consumes excessive memory and produces unreadable results.

---

## AP-S10: The Unindexed Field Scan

**Pattern**: Filtering on search-time fields before index-time fields.

```spl
// BAD: CommandLine is search-time — parsed for every event
index=wineventlog CommandLine="*mimikatz*"

// GOOD: narrow with index-time fields first
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688
| where match(CommandLine, "(?i)mimikatz")
```

**Why it fails**: Index-time fields (`index`, `sourcetype`, `source`, `host`, `EventCode`) are filtered without parsing. Search-time fields require full event parsing. Filter on index-time fields first.

---

## AP-S11: The Risk Score Without Rationale

**Pattern**: RBA risk scores assigned without documented justification.

```spl
// BAD: why 40? why not 20 or 80?
| eval risk_score=40

// GOOD: documented rationale
| eval risk_score=40
``` ``` Risk score 40: Medium-confidence behavioural signal. Threshold for
    notable creation is 100 per entity per 24h. Two of these signals
    from the same user within 24h will trigger investigation. ```
```

**Why it fails**: Arbitrary scores make RBA untunable. Document the scoring rationale so analysts and tuning engineers can adjust thresholds.

---

## AP-S12: The CIM Field Assumption

**Pattern**: Using CIM field names without verifying the data model is accelerated and the sourcetype is CIM-compliant.

```spl
// BAD: assumes CIM normalisation exists
| tstats count from datamodel=Authentication
    where Authentication.action=failure
    by Authentication.user, Authentication.src

// GOOD: verify first, document requirement
``` ``` Requires: Authentication data model accelerated.
    Sourcetypes mapped: WinEventLog:Security (via TA-windows). ```
| tstats summariesonly=true count from datamodel=Authentication
    where Authentication.action=failure
    by Authentication.user, Authentication.src
```

**Why it fails**: CIM data models only work when sourcetypes are mapped via Technology Add-ons (TAs) and the data model is accelerated. Without this, `tstats` returns zero results — interpreted as "no threats" rather than "broken query".

---

## Quick reference

| Red flag | Anti-pattern | Fix |
|---|---|---|
| No `index=` | AP-S1 | Always specify index |
| No `earliest=` | AP-S2 | Always specify time bounds |
| `stats` before `where` | AP-S3 | Stream first, transform last |
| Subsearch for large datasets | AP-S4 | Use `lookup` or `inputlookup` |
| `join` for correlation | AP-S5 | Use `stats`, `lookup`, or `tstats` |
| `stats` when DM is accelerated | AP-S6 | Use `tstats summariesonly=true` |
| No throttling on notables | AP-S7 | Set throttling fields + duration |
| Undocumented macros | AP-S8 | Inline or document macro expansion |
| Unbounded `values()` | AP-S9 | Limit or use `dc()` |
| Search-time field in base search | AP-S10 | Index-time fields first |
| Risk score without rationale | AP-S11 | Document scoring logic |
| CIM fields without DM verification | AP-S12 | Verify acceleration + TA mapping |
