---
name: microsoft-defender-endpoint
description: Microsoft Defender for Endpoint specifics for Advanced Hunting tables (Device*, Email*, identity-adjacent Defender datasets), Mandatory columns when raising custom detection rules, NRT single-table/no-comment quirks, retention boundaries, enrichment via Defender incident graph. Combine with kusto-query-language KQL optimisation. Use for defender_for_endpoint configurations in OpenTide MDR objects and Defender-first hunts.
---

# Microsoft Defender for Endpoint (advanced hunting surfaces)

## Scope boundaries

Leverage Sentinel skill when ingestion lands primarily through Sentinel connectors without requiring Defender Hunting IDE semantics—often split work by **hypothesis**:

| Hypothesis telemetry | Typical starting point |
|----------------------|-----------------------|
| Process / file / on-device lateral movement observable via `Device*` tables | Defender Advanced Hunting tables |
| Entra ID interactive sign-ins, OAuth abuse, Sentinel UEBA cross feeds | Sentinel skill |

## Non-negotiable device-rule columns (conceptual checklist)

Advanced hunting exports feeding **custom detection** flows must honour platform mandatory columns per Microsoft documentation—for example **Timestamp**, stable **device identifiers**, **`ReportId`** where required—for alert fabric deduplication. Absence ⇒ generation failure. Exact requirements evolve—read current Microsoft Defender detection-authoring docs before shipping.

Near-real-time rules enforce **single-table** evaluation, forbidding joins / unions (`join`, `union`, multi-hop correlation) alongside **no //-style comments** constraints per published limitations—never rely on hearsay alone.

Retrieval windows historically cap shorter than Sentinel historical lake deals—budget accordingly when correlating marathon campaigns.

## Authoring playbook

1. Begin with behavioural decomposition at device scope (binary → child process chain → egress).  
2. Validate column names exclusively against Defender schema references—not Sentinel column synonyms. Example swap families: Defender `Timestamp`/`DeviceId` vs Sentinel `TimeGenerated`/`Computer` hostname usage patterns.  
3. Layer **`kusto-query-language`** optimisation first; then Defender-specific quirks.  
4. For multi-hop stories spanning identity + endpoint, articulate separate queries referencing each modality (document cross-correlation rationale in narratives rather than brute forcing impossible cross-table joins incompatible with tooling).

## Incident graph alignment

Understand how Defender translates query columns into device / user / IP / mailbox entities for Automated Investigation graphs—helps analyst UX parity when editing OpenTide `response` investigative metadata alongside `description`.
