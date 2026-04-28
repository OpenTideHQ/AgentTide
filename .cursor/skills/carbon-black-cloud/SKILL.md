---
name: carbon-black-cloud
description: VMware Carbon Black Cloud Enterprise EDR (carbon_black_cloud:: schema lineage) authoring guidance — watchlists, scheduled searches/reporting distinctions, reputational enrichments—not KQL—with constraints for aligning OpenTide MDR configuration blocks under carbon_black_cloud keys. Blend with detection-engineering for alerting lifecycle coherence.
---

# Carbon Black Cloud

Carbon Black detectors frequently combine **IOC watchlists**, **behaviour restrictions**, **search exports**, and reputational lookups—capabilities vary by SKU.

### Practitioner checklist

| Area | Instruction |
|------|---------------|
| **Authoritative syntax** | Source queries from sanctioned Carbon Black search documentation or mirrored internal libraries—agents must avoid fabricating undocumented field names.|
| **Entity correlation** | Map device identifiers & sensor clusters consistently across narratives feeding OpenTide `response` artefacts.|
| **Performance** | Long-horizon searching through raw events may be prohibitively costly—explicitly annotate heavy searches and prefer acceleration-friendly patterns.|
| **Configuration fidelity** | Only populate templated YAML structure generated for `carbon_black_cloud` integrations—never stray keys.|
