---
name: kusto-query-language
description: Provides platform-neutral Kusto Query Language (KQL) optimisation and pattern guidance shared by Microsoft Sentinel (Log Analytics) and Microsoft Defender for Endpoint advanced hunting — filter ordering, string operators, joins, summarise patterns, commenting discipline, FP engineering, anti-patterns. Pair with microsoft-sentinel or microsoft-defender-endpoint for schemas, ingestion contracts, analytic rule constraints, table catalogues and native execution quirks.
---

# Kusto Query Language (shared Microsoft security stack)

**When to use**: Any time you write or refactor KQL for Microsoft Sentinel workspaces **or** Microsoft Defender Advanced Hunting—the optimisation rules are identical even though **`TimeGenerated`** (Sentinel) vs **`Timestamp`** (Defender endpoint tables) differs.

**When to pair**: Always load **`microsoft-sentinel`** and/or **`microsoft-defender-endpoint`** beside this skill—you need authoritative table/column inventories, entity mapping nuances, ingestion delays, analytic rule length limits, and per-surface caveats those skills carry.

---

## Rule 1 — Filter early, filter hard

| Priority | Filter style | Reason |
|---------|---------------|--------|
| 1 | Time predicate on clustered datetime column (`TimeGenerated`/`Timestamp`) | Shard elimination |
| 2 | Narrow enumerations (`==`, `in`) where indexed |
| 3 | `has` / `has_cs` token lookups | Leverage inverted indexes |
| 4 | `contains` family | substring scans |
| 5 | `matches regex` | Last resort; full scans |

Illustrative pattern:

```kql
HeartOfQuery
| where ingestion_time_column > ago(7d)     // sentinel vs defender chooses field name
| where categorical_field == expected_value    // tighten before textual search
| where free_text_column has "tokenofinterest"
```

---

## Prefer `has` over `contains`

`has` uses token-aware indexing; plain `contains` substring-scansunless there is deliberate reason (partial token inside another token).

## Case sensitivity

Case-sensitive predicates cost less whenever tenant data tolerates strict casing (`==`, `has_cs`). Fall back to `=~`, `has`, `in~` when casing drift is common (UPNs, UNC paths).

## Short tokens

Ultra-short literals may not leverage indexes—prefer anchoring around longer tokens (executable names, GUIDs, URLs) before regex.

---

## Operator guardrails (`where`)

- Prefer `has_any`/`has_all` for multi-token membership.
- **Negation traps**: multi-value macros such as `has_any`, `contains_any` combine poorly with unary `!`; wrap with `not( expression )` explicitly.
- **Boolean precedence**: When mixing `and` / `or`, parenthesise non-trivial mixes—ambiguous intent hides logic bugs across future edits.

---

## Mandatory comment header discipline

Structured headers keep SOC collaboration consistent:

```kql
// ============================================================
// Hunt: Hypothesis nickname
// Purpose: Behavioural observation under test
// Source intelligence: pointer (TLP respecting)
// MITRE ATT&CK: Technique id(s)
// Platform: Sentinel | Defender (device/email identity tables)
// Precision hypothesis: HIGH | MEDIUM | LOW
// Recall risk: HIGH | MEDIUM | LOW
// ============================================================
```

Comment each non-trivial filter with **why**, not merely **what**.

---

## `let`, constants, IOC lists

- Centralise IOC arrays with `dynamic([...])` and cite provenance in comments inline.
- Use `materialize()` when the same extracted dataset feeds multiple downstream joins—it prevents redundant scans.
- For large static reference sets, weigh query-size limits imposed by Sentinel analytics rules (~10 000 characters)—factor logic into reusable functions only when tooling permits.

---

## Join guidance

| Practice | Guidance |
|----------|-----------|
| Smaller bounded set left-side | Reduces lookups |
| Time bound both operands | Sentinel may require ingestion slack where Defender already caps device retention |
| `kind=inner` vs defaults | Understand dedup semantics (`innerunique`) |
| Hints (`hint.strategy`, `shuffle`) | Apply consciously on very large cardinality joins |

Window / sequence analytics (`prev`, `next`, `row_window_session`) excel at brute-force spraying, MFA noise bursts, or chained operations—budget compute.

---

## Summarisation and aggregation

Avoid summarising uniqueness that could be retrieved by simple projection. Use `shuffle` summarise hints when cardinality explodes (`summarize hint.shufflekey = ...`).

---

## False-positive engineering pillars

1. Tunable thresholds at top (`let`).
2. Documented exclusions with governance-friendly justification.
3. Optional environment blocks delineated (`--- ENVIRONMENT SANCTIONED FILTERS ---`) so operators customise without rewriting core logic.

---

## Quality checklist — language layer

- Time predicate first unless platform rules forbid (scheduled detection vs NRT vs interactive hunt).
- No bare `Regex` anchored at table start unless justified.
- Projection reduces columns before joins.
- Parentheses tame complex boolean logic.
- Negations avoid illegal operator combinations noted above.

Platform-specific overlays (Mandatory columns like `ReportId`, absence of joins in Defender NRT, Sentinel NRT ingestion rules) reside in **`microsoft-defender-endpoint`** and **`microsoft-sentinel`**.
