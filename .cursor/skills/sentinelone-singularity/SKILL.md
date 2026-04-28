---
name: sentinelone-singularity
description: SentinelOne Singularity authoring guidance for sentinel_one::* deployment artefacts—distinct from Microsoft Sentinel. Covers behavioural rule concepts, ingestion APIs, exclusions, versioning caveats—not KQL. Use when authoring sentinel_one keyed configuration blocks inside OpenTide MDR objects.
---

# SentinelOne Singularity

Different **Sentinel-one** acronym namespace vs Microsoft Sentinel—never confuse UI surfaces.

### Focus areas

| Area | Operational notes |
|------|---------------------|
| **Locales** | Windows/macOS/Linux agents differ — confirm coverage when porting hunts.|
| **Content types** | Custom rules / Star custom logic / ingestion APIs depend on SKU—defer to organisational baselines mirrored in templates.|
| **False positives / suppression** | Exclusion philosophy must reconcile with ransomware/stopper sensitivity—coordinate with SOC policy before broad exclusions.|
| **Platform mapping** | Keep YAML anchors aligned with sentinel_one templated scaffolding from CI-generated schemas.|

When needing Microsoft KQL—for example cross-pollinating with Defender—use **`microsoft-defender-endpoint`** + **`kusto-query-language`** instead—SentinelOne has separate expression languages.
