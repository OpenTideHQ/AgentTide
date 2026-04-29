---
name: opentide-detection-objective
description: Authors OpenTide Detection Objective (DOM) YAML—priorities, compositions, ATT&CK cross-links where applicable, signal contracts, methodologies, entities, data availability/requirements—with traceability toward linked Threat Vectors. Use whenever creating or refactoring files under Detection Objectives or structuring coverage intents before Detection Rules attach.
---

# OpenTide Detection Objective (DOM)

### Preconditions

1. Load **`Schemas/Templates`** for DOM (`dom::*`) and authoritative JSON schemas.
2. Identify related **TVM UUIDs**. Update rather than duplicate when coverage shifts.

### Anatomy highlights

| Section | Guidance |
|---------|-----------|
| `metadata` | Schema id parity, versioning dates, UUID stability when editing—not regenerated casually. |
| `objective` | Narrative bridging threat story to SOC actions; `composition.strategy` aligns leadership expectations. |
| `objective.signals[]` | Each signal has its own methodology, severity, measurable data requirements (`availability`, textual `requirements`). |
| Entities / detectors | Populate only columns your schema recognises; prefer explicit signal UUID references for traceability downstream. |

### Authoring norms

- **Signal atomicity**: If a mitigation or dataset split would materially change alerting, prefer multiple signals—not catch-all hybrids.
- **Data realism**: Document acquisition difficulty (streaming vs batch, entitlement prerequisites) plainly.
- **Investment notes**: Capture engineering effort realistically when templates expose optional `effort`/investment fields.

### Collaboration with neighbouring skills

- Upstream **`opentide-threat-vector`** for threat fidelity.
- Downstream **`opentide-detection-rule`** for executable bodies.
- **Platform/query skills** validate technical feasibility (**`kusto-query-language`**, `splunk-spl-processing`, etc.) according to tooling each signal references.
