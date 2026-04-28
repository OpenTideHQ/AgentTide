---
name: microsoft-sentinel
description: Microsoft Sentinel (Azure Log Analytics) specifics for authoring and reviewing KQL in analytics rules and interactive hunting—canonical time field, identity and cloud workloads, ingestion delays, Sentinel NRT rule caveats vs scheduled rules, watchlists, enrichment patterns. Always combine with kusto-query-language for language-level optimisation rules. Use for configurations.sentinel blocks in OpenTide MDR objects and Sentinel-first hypotheses.
---

# Microsoft Sentinel (Log Analytics)

## Scope boundaries

Partner with **`microsoft-defender-endpoint`** when telemetry originates from Microsoft Defender Advanced Hunting Device* tables—even if surfaced through Sentinel workspaces via data connectors—the mental model splits **cloud/identity SaaS/firewall ingestion** versus **pure endpoint sensor tables authored inside Defender portals**.

Sentinel excels at identity (`SigninLogs`, `AuditLogs`), SaaS/office (`OfficeActivity`, `CloudAppEvents`), Azure infrastructure (`AzureActivity`, `AzureDiagnostics`), broad syslog / CEF / firewall transforms (`CommonSecurityLog`, parsers), Sentinel-native artefacts (`ThreatIntelligenceIndicator` variants depending on ingestion), behavioural analytics overlays when connectors exist.

## First principles

| Topic | Sentinel expectation |
|-------|-----------------------|
| **Primary datetime** | Prefer `TimeGenerated` except where specific tables document alternative semantics. Analytics rules impose length / complexity quotas—factor while designing joins. |
| **Ingestion lag** | Add buffer when aligning scheduled analytic frequency + lookbacks (common guidance: overlap ≥ interval plus ingestion jitter). Interactive hunts choose explicit trailing windows. |
| **NRT pipelines** | Special compile-time constraints (no unbounded wildcard unions, ingestion_time discipline, concurrency caps per workspace)—validate against current Microsoft Sentinel release notes prior to asserting absolutes here. |

## Operational hints

1. Prefer explicit table enumeration over wildcard `union *` scans in scheduled analytics.
2. For JSON-heavy columns (`AdditionalData`, `DeviceDetail`), parse after coarse filters minimise JSON payload fan-out cost.
3. Document entity-mapping columns aligning to Sentinel incident enrichment (`UserPrincipalName`, `IPAddress`, `Computer`, schema-specific identity columns).
4. Cross-reference **`kusto-query-language`** filters first; only then customise for Sentinel quirks.

## Relation to detection engineering packaging

Operational concerns—scheduled vs near-real-time, alert thresholds, suppression, MITRE bridging in Sentinel UI—layer with **`detection-engineering`** when converting validated hunts pulled from Sentinel workspaces into hardened detection assets referenced by OpenTide MDR objects.
