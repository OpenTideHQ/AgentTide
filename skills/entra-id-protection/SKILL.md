---
name: entra-id-protection
description: Microsoft Entra ID (Azure AD) identity-attack detection guidance — sign-in risk vs user risk semantics, Identity Protection P1 vs P2 SKU gating, Conditional Access policy detection, risky sign-in patterns (AiTM, token theft, MFA fatigue, OAuth abuse, BEC), ResultType code catalogue, service principal vs user principal telemetry split, cross-tenant and B2B considerations, and entity alignment for cross-platform correlation. Always pair with microsoft-sentinel for SigninLogs/AuditLogs query mechanics. Use for identity-focused hypotheses and Sentinel-side detection rules targeting Entra ID telemetry.
---

# Microsoft Entra ID Protection — identity-attack detection

This skill encodes the identity-platform tribal knowledge that sits between raw `SigninLogs`/`AuditLogs` telemetry (covered by `microsoft-sentinel`) and the detection engineering lifecycle (covered by `detection-engineering`). Use it when the hypothesis or detection targets **identity-layer behaviour**: authentication attacks, privilege escalation via directory changes, OAuth/consent abuse, or cross-tenant lateral movement.

> **Naming**: "Azure AD" was renamed to "Microsoft Entra ID" in 2023. Sentinel tables retain the old names (`SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AuditLogs`). This skill uses "Entra ID" for the product and the legacy table names for queries.

---

## 1. SKU gating — what you can and cannot detect

Identity Protection features are **licence-dependent**. Detection content must declare which tier it requires.

| Feature | Entra ID P1 | Entra ID P2 | Free |
|---|---|---|---|
| `SigninLogs` table | Yes | Yes | Yes (limited) |
| `RiskLevelDuringSignIn` column | No | Yes | No |
| `RiskState`, `RiskDetail` columns | No | Yes | No |
| `RiskEventTypes_V2` column | No | Yes | No |
| `risky Users` / `riskDetections` APIs | No | Yes | No |
| Conditional Access policy evaluation logs | Yes | Yes | No |
| `AADNonInteractiveUserSignInLogs` | Yes | Yes | No |
| `ManagedIdentitySignInLogs` | Yes | Yes | No |
| `ServicePrincipalSignInLogs` | Yes | Yes | No |

**Rule**: Always use `column_ifexists()` for P2-only columns. A detection that filters on `RiskLevelDuringSignIn == "high"` silently returns zero results in P1 tenants — the column exists but contains only `"none"`.

```kql
// Safe pattern for P2-optional risk filtering
| extend RiskLevel = column_ifexists("RiskLevelDuringSignIn", "unknown")
| where RiskLevel in ("medium", "high") or RiskLevel == "unknown"
```

---

## 2. Sign-in risk vs user risk

Two distinct risk models that are often confused:

| Concept | Sign-in risk | User risk |
|---|---|---|
| Scope | Per-authentication event | Per-user entity (cumulative) |
| Column | `RiskLevelDuringSignIn` | `RiskLevelAggregated` (via `risky Users` API) |
| Triggers | Anomalous IP, impossible travel, AiTM proxy, malware-linked IP | Leaked credentials, confirmed compromise, cumulative sign-in risk |
| Remediation | MFA challenge, block | Password reset, block, confirm compromise |
| Detection use | Real-time alerting on suspicious sign-ins | Trend analysis, account compromise confirmation |

**Detection discipline**: Use sign-in risk for real-time detection rules. Use user risk for enrichment and escalation logic, not as a primary detection signal (it lags).

---

## 3. ResultType code catalogue (critical subset)

`ResultType` in `SigninLogs` is a **string**, not an integer. Always compare as string.

| Code | Meaning | Detection relevance |
|---|---|---|
| `"0"` | Success | Baseline; combine with anomalous context |
| `"50126"` | Invalid credentials | Password spray, brute force |
| `"50053"` | Account locked | Brute force threshold reached |
| `"50057"` | Account disabled | Attempted use of disabled account |
| `"50074"` | MFA required (strong auth) | MFA challenge triggered |
| `"50076"` | MFA challenge failed | MFA bypass attempt |
| `"500121"` | MFA denied (user rejected) | MFA fatigue attack |
| `"50140"` | Keep Me Signed In (KMSI) interrupt | Session management |
| `"50158"` | External security challenge | Conditional Access external control |
| `"53003"` | Blocked by Conditional Access | Policy enforcement |
| `"530032"` | Blocked by security defaults | Baseline protection |
| `"700016"` | Application not found in tenant | Misconfigured or malicious app |
| `"7000218"` | Request body must contain client_assertion | Service principal auth issue |
| `"90094"` | Admin consent required | OAuth consent flow |

**Always comment ResultType codes inline** — reviewers and analysts cannot memorise them.

---

## 4. Identity attack patterns

### 4.1 Password spray

```
Multiple failed sign-ins (50126/50053) from one IP across many users in a short window.
```

| Signal | Table | Key columns |
|---|---|---|
| High failure count per IP | `SigninLogs` | `IPAddress`, `ResultType`, `UserPrincipalName` |
| Many distinct users per IP | `SigninLogs` | `dcount(UserPrincipalName) by IPAddress` |
| Residential proxy infrastructure | `SigninLogs` | `IPAddress` + TI enrichment |

### 4.2 MFA fatigue / push bombing

```
Repeated MFA denials (500121) for one user in a short window, followed by a success (0).
```

| Signal | Table | Key columns |
|---|---|---|
| MFA denial burst | `SigninLogs` | `ResultType == "500121"`, `UserPrincipalName` |
| Subsequent success | `SigninLogs` | `ResultType == "0"` within N minutes |
| Non-standard user agent | `SigninLogs` | `UserAgent` |

### 4.3 AiTM / adversary-in-the-middle phishing

```
Successful sign-in from a known AiTM proxy infrastructure, often with anomalous user agent or session token replay.
```

| Signal | Table | Key columns |
|---|---|---|
| Risky sign-in + anomalous UA | `SigninLogs` | `RiskLevelDuringSignIn`, `UserAgent` |
| Session token replay | `SigninLogs` | `CorrelationId`, `TokenIssuerType` |
| Immediate inbox rule creation | `OfficeActivity` | `Operation in ("New-InboxRule", "Set-InboxRule")` |

### 4.4 OAuth / consent abuse

```
Malicious application granted permissions via user or admin consent, enabling persistent access without credentials.
```

| Signal | Table | Key columns |
|---|---|---|
| New consent grant | `AuditLogs` | `OperationName == "Consent to application"` |
| High-privilege permissions | `AuditLogs` | `TargetResources[0].modifiedProperties` |
| Non-baseline application | `AuditLogs` | Baseline comparison via `set_difference()` |

### 4.5 Conditional Access policy weakening

```
Modification of Conditional Access policies to remove MFA requirements or exclude privileged roles.
```

| Signal | Table | Key columns |
|---|---|---|
| CA policy modification | `AuditLogs` | `OperationName has "conditional access"` |
| MFA requirement removed | `AuditLogs` | `TargetResources` JSON parsing |
| Privileged role exclusion | `AuditLogs` | Policy JSON diff |

### 4.6 Service principal compromise

```
Anomalous service principal sign-in from unexpected IP or with unexpected permissions.
```

| Signal | Table | Key columns |
|---|---|---|
| SP sign-in anomaly | `ServicePrincipalSignInLogs` | `ServicePrincipalId`, `IPAddress` |
| New credential added to SP | `AuditLogs` | `OperationName == "Add service principal credentials"` |
| Federated credential added | `AuditLogs` | `OperationName has "federatedIdentityCredential"` |

---

## 5. Telemetry split — user vs service principal vs managed identity

| Principal type | Sign-in table | Audit table |
|---|---|---|
| Interactive user | `SigninLogs` | `AuditLogs` |
| Non-interactive user | `AADNonInteractiveUserSignInLogs` | `AuditLogs` |
| Service principal | `ServicePrincipalSignInLogs` | `AuditLogs` |
| Managed identity | `ManagedIdentitySignInLogs` | `AuditLogs` |

**Common mistake**: Querying only `SigninLogs` and missing non-interactive sign-ins. Token refresh, background app activity, and service-to-service calls appear in `AADNonInteractiveUserSignInLogs` or `ServicePrincipalSignInLogs`.

For comprehensive identity coverage, union the relevant tables:

```kql
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(14d)
| where ResultType == "0"
// ... detection logic
```

---

## 6. Cross-tenant and B2B considerations

| Scenario | Column | Value |
|---|---|---|
| Home tenant sign-in | `HomeTenantId == ResourceTenantId` | Normal |
| Guest user (B2B) | `HomeTenantId != ResourceTenantId` | Cross-tenant access |
| External identity provider | `TokenIssuerType` | `"External"` |

**Detection discipline**: B2B guest access is legitimate but high-risk. Detections should distinguish between established B2B relationships and novel cross-tenant access.

---

## 7. Nested JSON parsing patterns

Many `SigninLogs` and `AuditLogs` columns contain nested JSON. Standard extraction patterns:

```kql
// Location details
| extend ParsedLocation = parse_json(LocationDetails)
| extend City = tostring(ParsedLocation.city)
| extend Country = tostring(ParsedLocation.countryOrRegion)

// Device details
| extend ParsedDevice = parse_json(DeviceDetail)
| extend Browser = tostring(ParsedDevice.browser)
| extend OS = tostring(ParsedDevice.operatingSystem)
| extend IsCompliant = tobool(ParsedDevice.isCompliant)

// Conditional Access policies
| mv-expand CAPolicy = parse_json(ConditionalAccessPolicies)
| extend PolicyName = tostring(CAPolicy.displayName)
| extend PolicyResult = tostring(CAPolicy.result)

// AuditLogs target resources
| extend TargetUPN = tostring(TargetResources[0].userPrincipalName)
| extend ModifiedProps = parse_json(tostring(TargetResources[0].modifiedProperties))
```

---

## 8. Entity identifier alignment

| Concept | Entra ID / Sentinel | Defender | CrowdStrike |
|---|---|---|---|
| User | `UserPrincipalName`, `UserId` (GUID) | `AccountUpn`, `AccountSid` | `UserName` |
| Device | `DeviceDetail.deviceId` | `DeviceId` | `aid` |
| IP | `IPAddress` | `RemoteIP` | `RemoteAddressIP4` |
| Application | `AppId`, `AppDisplayName` | — | — |
| Service principal | `ServicePrincipalId` | — | — |

Cross-platform correlation happens at the SIEM/SOAR layer. The `UserPrincipalName` is the most reliable cross-platform join key for identity.

---

## 9. Quality checklist

- [ ] SKU tier requirement declared (P1 vs P2).
- [ ] `column_ifexists()` used for P2-only columns.
- [ ] `ResultType` compared as string, not integer.
- [ ] ResultType codes commented inline with meaning.
- [ ] All relevant sign-in tables queried (interactive + non-interactive + SP where applicable).
- [ ] Nested JSON parsed via `parse_json()` / `todynamic()`.
- [ ] Cross-tenant scenarios considered (B2B guest access).
- [ ] Risk columns used for enrichment, not as sole detection signal in P1 environments.
- [ ] MITRE technique mapping accurate (T1078, T1098, T1556, T1621, T1557 as applicable).
- [ ] Coordinate with `microsoft-sentinel` for query mechanics and `detection-engineering` for lifecycle.
