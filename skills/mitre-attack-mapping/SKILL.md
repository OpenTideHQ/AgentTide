---
name: mitre-attack-mapping
description: MITRE ATT&CK mapping discipline for OpenTide TVM, DOM, and MDR objects — technique vs sub-technique selection, tactic assignment, multi-technique chaining, version pinning, revocation handling, coverage gap analysis, and the inverse mapping from defensive capabilities to ATT&CK coverage. Use when populating threat.att&ck fields in TVMs, mapping DOM signals to techniques, tagging MDR rules, or assessing detection coverage against the ATT&CK matrix.
---

# MITRE ATT&CK mapping — OpenTide integration

This skill encodes the discipline of mapping adversary behaviour to ATT&CK and back. Every OpenTide object type carries ATT&CK references; getting them right is a quality gate. Current baseline: **ATT&CK v19** (April 2026, Enterprise domain: 15 tactics, 222 techniques, 475 sub-techniques).

> **v19 breaking change**: Defense Evasion was split into **Stealth** (TA0005) and **Defense Impairment** (TA0112). Any existing mappings referencing TA0005 as "Defense Evasion" must be reviewed and re-assigned.

---

## 1. Tactic, technique, sub-technique — when to use which

| Level | Use when | Example |
|---|---|---|
| **Tactic only** | Early TVM drafting where the specific technique is unknown or the intelligence is vague | "Adversary seeks credential access" → `TA0006` |
| **Technique** | The behaviour class is clear but the specific implementation is not documented | "Adversary uses credential dumping" → `T1003` |
| **Sub-technique** | The specific implementation is documented in the intelligence | "Adversary dumps LSASS memory" → `T1003.001` |

### Decision rules

1. **Always prefer the most specific level the evidence supports.** If the source says "Mimikatz sekurlsa::logonpasswords", map to `T1003.001`, not `T1003`.
2. **Never map to a sub-technique without also implying the parent.** The parent is implicit in ATT&CK's hierarchy — do not list both `T1003` and `T1003.001` for the same behaviour.
3. **Map to the parent technique only when** the source describes the behaviour class but not the specific method, or when multiple sub-techniques apply and you cannot distinguish which.
4. **Do not over-tag.** If a detection rule catches one specific sub-technique, map to that sub-technique only. LLMs tend to list every plausible sub-technique — resist this.

---

## 2. Tactic assignment

A technique can appear under multiple tactics. Select the tactic that matches the **adversary's goal in context**, not every tactic the technique could theoretically serve.

| Scenario | Correct tactic | Wrong |
|---|---|---|
| Adversary uses `schtasks` to persist | Persistence (TA0003) | Execution (TA0002) — even though schtasks executes |
| Adversary uses `schtasks` to run a payload once | Execution (TA0002) | Persistence (TA0003) — no persistence intent |
| Adversary uses PowerShell to download a payload | Command and Scripting Interpreter (T1059.001) under Execution | Don't also tag Initial Access |

### v19 tactic split

| Old tactic | New tactics (v19) | Action |
|---|---|---|
| Defense Evasion (TA0005) | **Stealth** (TA0005) — hiding artefacts, obfuscation, masquerading | Review existing TA0005 mappings |
| | **Defense Impairment** (TA0112) — disabling tools, clearing logs, firewall modification | Re-assign where the goal is impairing defences |

---

## 3. Multi-technique chaining

A single TVM or MDR may reference multiple techniques when the intelligence documents a **behavioural chain**. Rules:

1. **Each technique in the chain must be independently evidenced.** Do not infer intermediate steps.
2. **Order matters in TVMs.** The `chaining` field should reflect the temporal sequence documented in the intelligence.
3. **MDR rules typically map to 1-2 techniques.** A detection rule that claims to cover 5+ techniques is almost certainly an AP-H2 Kitchen Sink (see `threat-hunting` skill).
4. **DOM signals map to the technique(s) the signal can actually detect**, not the full chain the parent TVM describes.

---

## 4. Version pinning and revocation handling

### Version pinning

- OpenTide content should reference ATT&CK technique IDs without version suffixes (e.g. `T1059.001`, not `T1059.001 v2.0`).
- The **repository-level** ATT&CK version is declared in the content repo's metadata or schema configuration. Individual objects inherit this.
- When ATT&CK releases a new version, review objects whose mapped techniques had **major version changes** or **revocations**.

### Revocations

ATT&CK periodically revokes techniques, replacing them with new IDs. v19 examples:
- `Impair Defenses` → revoked, replaced by `Disable or Modify Tools` (T1685)
- `Disable or Modify System Firewall` → revoked, replaced by T1686

**Handling revocations in OpenTide:**
1. Search the content repo for the revoked technique ID.
2. Update to the replacement technique ID.
3. Review the description — the replacement may have a narrower or broader scope.
4. Log the change in the PR narrative.

### Deprecations

Deprecated techniques have no replacement. Remove the mapping and document the gap.

---

## 5. Mapping in OpenTide objects

### TVM (Threat Vector)

| Field | ATT&CK content |
|---|---|
| `threat.att&ck` | Array of technique/sub-technique IDs with tactic context |
| `terrain` | Narrative references to ATT&CK behaviours with evidence |
| `chaining` | Ordered technique sequence when the TVM describes a multi-step chain |

**Quality bar**: Every technique ID in `threat.att&ck` must trace to a specific claim in the source intelligence. Unmapped techniques are preferable to speculative mappings.

### DOM (Detection Objective)

| Field | ATT&CK content |
|---|---|
| `objective.signals[].att&ck` | Technique(s) the signal can detect |
| Coverage narrative | Which sub-techniques are covered vs gaps |

**Quality bar**: A DOM signal should map to the technique(s) it can actually observe, not the full TVM chain. If a signal detects `T1003.001` (LSASS dump) but not `T1003.003` (NTDS), map only `.001`.

### MDR (Detection Rule)

| Field | ATT&CK content |
|---|---|
| Rule metadata / `configurations.*.mitre` | Technique IDs for the platform rule |
| `description` | Technique context in prose |

**Quality bar**: The MDR technique mapping must match what the query actually detects. A KQL query filtering on `FileName =~ "ntdsutil.exe"` maps to `T1003.003`, not the parent `T1003`.

---

## 6. Coverage analysis (inverse mapping)

ATT&CK mapping also works in reverse: given a set of detection rules, which techniques are covered?

### Coverage matrix construction

1. Extract all technique IDs from MDR objects in the content repo.
2. Map against the ATT&CK Enterprise matrix (222 techniques, 475 sub-techniques in v19).
3. Classify coverage:

| Level | Definition |
|---|---|
| **Detected** | At least one production MDR rule maps to this technique |
| **Hunted** | A validated hunt query exists but no production rule |
| **Theoretical** | A DOM signal is defined but no query exists |
| **Gap** | No coverage at any level |

### Coverage anti-patterns

| Anti-pattern | Description |
|---|---|
| **Breadth without depth** | Mapping to parent techniques only, claiming "T1059 covered" when only PowerShell (T1059.001) has a rule |
| **Phantom coverage** | Mapping a rule to a technique it cannot actually detect (e.g. a network rule claiming to detect a registry technique) |
| **Stale coverage** | Rules mapped to revoked technique IDs that no longer exist in the current ATT&CK version |
| **Platform mismatch** | Claiming Linux technique coverage with a Windows-only detection rule |

---

## 7. Common mapping mistakes

| Mistake | Fix |
|---|---|
| Listing both parent and sub-technique for the same behaviour | Use the most specific level only |
| Mapping to every tactic a technique supports | Select the tactic matching the adversary's goal in context |
| Copying technique lists from CTI reports without validation | Verify each mapping against the actual behaviour described |
| Using deprecated/revoked technique IDs | Check against current ATT&CK version |
| Mapping a detection rule to techniques it cannot observe | Map only to what the query's data source can see |
| Over-tagging MDR rules with 5+ techniques | One rule typically detects 1-2 specific behaviours |

---

## 8. ATT&CK data sources and data components

ATT&CK v19 includes **Data Components** (e.g. Process Creation, File Modification, Network Connection Creation) that link techniques to observable telemetry. Use these to validate that your detection platform actually has visibility into the mapped technique:

| Data component | Sentinel table | Defender table |
|---|---|---|
| Process Creation | `SecurityEvent` (4688) | `DeviceProcessEvents` |
| File Creation | `SecurityEvent` (4663) | `DeviceFileEvents` |
| Network Connection Creation | `CommonSecurityLog` | `DeviceNetworkEvents` |
| User Account Authentication | `SigninLogs` | `DeviceLogonEvents` |
| Windows Registry Key Modification | `SecurityEvent` (4657) | `DeviceRegistryEvents` |
| Module Load | — | `DeviceImageLoadEvents` |

If the data component required by a technique is not available on your platform, the mapping is theoretical — document the gap.

---

## 9. Quality checklist

- [ ] Every technique ID is valid in the current ATT&CK version.
- [ ] Sub-technique used when the specific implementation is documented; parent when not.
- [ ] Parent and sub-technique not both listed for the same behaviour.
- [ ] Tactic matches the adversary's goal in context, not every possible tactic.
- [ ] MDR technique mapping matches what the query actually detects.
- [ ] DOM signal mapping covers only the techniques the signal can observe.
- [ ] TVM technique mapping traces to specific source intelligence claims.
- [ ] No revoked or deprecated technique IDs remain.
- [ ] Coverage claims validated against available data sources.
- [ ] Multi-technique chains are independently evidenced per step.
