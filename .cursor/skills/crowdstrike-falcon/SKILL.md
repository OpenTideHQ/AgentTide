---
name: crowdstrike-falcon
description: CrowdStrike Falcon deployment guidance aligned with CrowdStrike query / scheduled-search contexts (crowdstrike:: schema families)—entity identifiers, IOC management patterns, alerting surfaces, ingestion caveats—not KQL/SPL—when filling crowdstrike configuration blocks inside OpenTide MDR objects. Combine with detection-engineering for operational maturity expectations.
---

# CrowdStrike Falcon authoring notes

CrowdStrike content layers span **queries, scheduled searches, IOCs**, and alerting pathways distinct from Splunk/Microsoft stacks.

### Working approach

| Track | Aim |
|-------|-----|
| **Understand sensor coverage** | Windows/macOS/Linux visibility differs by licensing & modules—explicitly caveat gaps in rule prose or OpenTide `description`. |
| **Query discipline** | Use vendor-current query language constructs—consult tenant documentation or exported samples instead of hallucinating specialised syntax.|
| **Entity IDs** | Where CrowdStrike uses device IDs / customer IDs correlation, ensure playbook fields cross-reference same identifiers surfaced in Sentinel/Defender hunts if bridging incidents. |
| **Deployment mapping** | CoreTide `crowdstrike` configuration blocks dictate structure—populate only sanctioned keys mirrored from regenerated templates.|
