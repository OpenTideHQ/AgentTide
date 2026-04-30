---
name: entra-id
description: Microsoft Entra ID (formerly Azure AD) — identity platform internals, telemetry, and attack detection. Covers the full Entra ID surface including sign-in logs (interactive, non-interactive, service principal, managed identity), audit logs, Identity Protection risk signals, Conditional Access evaluation, directory role management, OAuth/consent grants, PRT/token mechanics, cross-tenant B2B/B2C, and workload identities. Includes SKU gating (P1 vs P2), ResultType code catalogue, identity attack patterns (password spray, AiTM, MFA fatigue, token theft, OAuth abuse, Golden SAML), and entity alignment for cross-platform correlation. Use for any work involving Entra ID telemetry, identity-focused detection, or directory security posture. Pair with the relevant platform skill for query mechanics (microsoft-sentinel, splunk-spl-processing, crowdstrike-falcon, etc.).
---

# Microsoft Entra ID — identity platform & detection

This skill encodes the identity-platform tribal knowledge for **Microsoft Entra ID** (formerly Azure AD) — the central identity provider for Microsoft 365, Azure, and thousands of SaaS applications. It covers the platform's architecture, telemetry surfaces, security features, and attack detection patterns.

Use this skill when working with:
- **Authentication telemetry** — sign-in logs, audit logs, risk detections
- **Identity attacks** — password spray, AiTM, MFA fatigue, token theft, OAuth abuse
- **Directory security** — role assignments, Conditional Access, PIM, app registrations
- **Cross-tenant scenarios** — B2B guest access, cross-tenant synchronisation, external identities
- **Workload identities** — service principals, managed identities, federated credentials

> **Naming**: "Azure AD" was renamed to "Microsoft Entra ID" in July 2023. The diagnostic log categories retain the legacy names (`SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AuditLogs`). These names are used by Sentinel, but the same data is available in any SIEM via Event Hubs, Graph API, or diagnostic settings — field names and schemas are identical regardless of destination. This skill uses "Entra ID" for the product and the canonical log category names throughout.

---

## 0. Entra ID architecture overview

Entra ID is a **multi-tenant, cloud-based identity and access management service**. Every Microsoft 365 and Azure subscription has an Entra ID tenant. Key concepts:

| Concept | Description |
|---------|-------------|
| **Tenant** | A dedicated instance of Entra ID representing an organisation. Identified by a tenant ID (GUID) and one or more verified domains. |
| **User principal** | A human identity (`user@domain.com`). Can be a member or a guest (B2B). |
| **Service principal** | An application identity in a tenant. Created when an app registration is consented to or provisioned. |
| **Managed identity** | An Azure-managed service principal bound to an Azure resource (VM, Function, etc.). No credential management required. |
| **App registration** | The global definition of an application (multi-tenant). The service principal is the per-tenant instance. |
| **Directory roles** | Built-in or custom roles granting administrative permissions (Global Admin, Security Reader, etc.). |
| **Conditional Access** | Policy engine evaluating sign-in context (user, device, location, risk, app) to enforce access controls. |
| **Identity Protection** | Risk-based detection engine (P2) that scores sign-in risk and user risk. |
| **PIM (Privileged Identity Management)** | Just-in-time role activation for privileged roles (P2). |

### Entra ID log categories

These are the canonical diagnostic log categories emitted by Entra ID. The names below are used in Sentinel, but the **same schema and field names** apply when ingested into Splunk (via Event Hubs / Azure Monitor Add-on), CrowdStrike NG-SIEM, Elastic, or any other SIEM.

| Log category | What it captures | Licence | Ingestion path |
|-------------|-----------------|---------|----------------|
| `SigninLogs` | Interactive user sign-ins | Free (limited), P1, P2 | Diagnostic settings, Graph API |
| `NonInteractiveUserSignInLogs` | Token refreshes, background app activity, SSO | P1, P2 | Diagnostic settings |
| `ServicePrincipalSignInLogs` | Service principal (app) authentications | P1, P2 | Diagnostic settings |
| `ManagedIdentitySignInLogs` | Managed identity authentications | P1, P2 | Diagnostic settings |
| `AuditLogs` | Directory changes (user/group/role/app/policy CRUD) | Free, P1, P2 | Diagnostic settings, Graph API |
| `RiskyUsers` | User risk state and history | P2 | Graph API |
| `UserRiskEvents` | Individual risk detections | P2 | Graph API |
| `RiskyServicePrincipals` | Workload identity risk | P2 | Graph API |
| `ProvisioningLogs` | Cross-tenant sync, HR provisioning | P1, P2 | Diagnostic settings |
| `NetworkAccessTrafficLogs` | Global Secure Access (Entra Internet/Private Access) | Separate licence | Diagnostic settings |

> **SIEM mapping note**: In Sentinel, `NonInteractiveUserSignInLogs` maps to the `AADNonInteractiveUserSignInLogs` table. In Splunk, the same data arrives via the `azure:aad:signin` sourcetype. In Elastic, it lands in `azure.signinlogs`. The **field names within each record** (e.g., `ResultType`, `UserPrincipalName`, `IPAddress`) are consistent across all destinations because they originate from the same Entra ID diagnostic schema.

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

| Signal | Log category | Key fields |
|---|---|---|
| High failure count per IP | `SigninLogs` | `IPAddress`, `ResultType`, `UserPrincipalName` |
| Many distinct users per IP | `SigninLogs` | `dcount(UserPrincipalName) by IPAddress` |
| Residential proxy infrastructure | `SigninLogs` | `IPAddress` + TI enrichment |

### 4.2 MFA fatigue / push bombing

```
Repeated MFA denials (500121) for one user in a short window, followed by a success (0).
```

| Signal | Log category | Key fields |
|---|---|---|
| MFA denial burst | `SigninLogs` | `ResultType == "500121"`, `UserPrincipalName` |
| Subsequent success | `SigninLogs` | `ResultType == "0"` within N minutes |
| Non-standard user agent | `SigninLogs` | `UserAgent` |

### 4.3 AiTM / adversary-in-the-middle phishing

```
Successful sign-in from a known AiTM proxy infrastructure, often with anomalous user agent or session token replay.
```

| Signal | Log category | Key fields |
|---|---|---|
| Risky sign-in + anomalous UA | `SigninLogs` | `RiskLevelDuringSignIn`, `UserAgent` |
| Session token replay | `SigninLogs` | `CorrelationId`, `TokenIssuerType` |
| Immediate inbox rule creation | `OfficeActivity` | `Operation in ("New-InboxRule", "Set-InboxRule")` |

### 4.4 OAuth / consent abuse

```
Malicious application granted permissions via user or admin consent, enabling persistent access without credentials.
```

| Signal | Log category | Key fields |
|---|---|---|
| New consent grant | `AuditLogs` | `OperationName == "Consent to application"` |
| High-privilege permissions | `AuditLogs` | `TargetResources[0].modifiedProperties` |
| Non-baseline application | `AuditLogs` | Baseline comparison via `set_difference()` |

### 4.5 Conditional Access policy weakening

```
Modification of Conditional Access policies to remove MFA requirements or exclude privileged roles.
```

| Signal | Log category | Key fields |
|---|---|---|
| CA policy modification | `AuditLogs` | `OperationName has "conditional access"` |
| MFA requirement removed | `AuditLogs` | `TargetResources` JSON parsing |
| Privileged role exclusion | `AuditLogs` | Policy JSON diff |

### 4.6 Service principal compromise

```
Anomalous service principal sign-in from unexpected IP or with unexpected permissions.
```

| Signal | Log category | Key fields |
|---|---|---|
| SP sign-in anomaly | `ServicePrincipalSignInLogs` | `ServicePrincipalId`, `IPAddress` |
| New credential added to SP | `AuditLogs` | `OperationName == "Add service principal credentials"` |
| Federated credential added | `AuditLogs` | `OperationName has "federatedIdentityCredential"` |

---

## 5. Telemetry split — user vs service principal vs managed identity

| Principal type | Sign-in log category | Audit log category |
|---|---|---|
| Interactive user | `SigninLogs` | `AuditLogs` |
| Non-interactive user | `NonInteractiveUserSignInLogs` | `AuditLogs` |
| Service principal | `ServicePrincipalSignInLogs` | `AuditLogs` |
| Managed identity | `ManagedIdentitySignInLogs` | `AuditLogs` |

**Common mistake**: Querying only interactive sign-ins and missing non-interactive activity. Token refresh, background app activity, and service-to-service calls appear in the non-interactive and service principal log categories.

For comprehensive identity coverage, query across all relevant sign-in categories. Example (KQL — adapt to your SIEM's query language):

```kql
// Sentinel / KQL example — adapt for Splunk, Elastic, etc.
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

## 8. Directory role and PIM monitoring

### Critical directory roles

| Role | Risk | Why |
|------|------|-----|
| Global Administrator | Critical | Full tenant control — can reset any password, modify any policy |
| Privileged Role Administrator | Critical | Can assign any role including Global Admin |
| Application Administrator | High | Can create/modify app registrations and consent to permissions |
| Cloud Application Administrator | High | Same as above minus on-prem app proxy |
| Exchange Administrator | High | Mailbox access, mail flow rules — BEC enabler |
| Security Administrator | High | Can modify security policies, read all security data |
| Conditional Access Administrator | High | Can weaken or disable CA policies |
| Partner Tier2 Support | Critical | Delegated admin — supply-chain attack vector |

### PIM activation detection

```kql
AuditLogs
| where OperationName == "Add member to role completed (PIM activation)"
| extend ActivatedRole = tostring(TargetResources[0].displayName)
| extend ActivatedBy = tostring(InitiatedBy.user.userPrincipalName)
| where ActivatedRole in ("Global Administrator", "Privileged Role Administrator")
```

### Permanent role assignment (bypassing PIM)

```kql
AuditLogs
| where OperationName == "Add member to role"
| where Result == "success"
| extend RoleName = tostring(TargetResources[0].displayName)
| extend AssignedUser = tostring(TargetResources[0].userPrincipalName)
| extend AssignedBy = tostring(InitiatedBy.user.userPrincipalName)
```

---

## 9. Token and session mechanics

Understanding token types is critical for detecting token theft and replay:

| Token | Lifetime | Storage | Theft vector |
|-------|----------|---------|-------------|
| **Access token** | 60–90 min (configurable) | Memory | Process memory dump, AiTM proxy |
| **Refresh token** | 90 days (sliding) | Disk/browser | Malware, AiTM, device compromise |
| **Primary Refresh Token (PRT)** | 14 days | TPM-bound (ideally) | `mimikatz`, `ROADtools`, device compromise |
| **Session cookie** | Varies | Browser | Cookie theft, AiTM proxy |
| **FOCI token** | Varies | Shared across FOCI apps | One compromised FOCI app exposes others |

### FOCI (Family of Client IDs)

Microsoft first-party apps share refresh tokens via FOCI. If an attacker steals a refresh token for one FOCI app (e.g., Outlook), they can exchange it for tokens to other FOCI apps (e.g., Teams, OneDrive) without re-authenticating. Key FOCI client IDs:

| App | Client ID |
|-----|-----------|
| Microsoft Office | `d3590ed6-52b3-4102-aeff-aad2292ab01c` |
| Microsoft Teams | `1fec8e78-bce4-4aaf-ab1b-5451cc387264` |
| Outlook Mobile | `27922004-5251-4030-b22d-91ecd9a37ea4` |
| OneDrive | `ab9b8c07-8f02-4f72-87fa-80105867a763` |

### Token theft detection signals

| Signal | Where to look |
|--------|--------------|
| Access token replay from new IP | `SigninLogs` — same `CorrelationId`, different `IPAddress` |
| Refresh token used from anomalous device | `AADNonInteractiveUserSignInLogs` — `DeviceDetail` mismatch |
| PRT theft (pass-the-PRT) | `SigninLogs` — `AuthenticationProcessingDetails` contains `"Is Primary Refresh Token"` |
| Impossible travel on token refresh | `AADNonInteractiveUserSignInLogs` — geo-distance between consecutive sign-ins |

---

## 10. Application and consent landscape

### App registration vs service principal

| Concept | Scope | Created by |
|---------|-------|-----------|
| **App registration** | Global (multi-tenant) or single-tenant | Developer |
| **Service principal** | Per-tenant instance | Auto-created on consent or provisioning |
| **Enterprise application** | UI name for service principal | — |

### Dangerous permissions to monitor

| Permission | Type | Risk |
|-----------|------|------|
| `Mail.ReadWrite` | Application | Read/write all mailboxes — BEC |
| `Files.ReadWrite.All` | Application | Read/write all OneDrive/SharePoint — exfiltration |
| `Directory.ReadWrite.All` | Application | Full directory modification — persistence |
| `RoleManagement.ReadWrite.Directory` | Application | Assign any directory role — privilege escalation |
| `AppRoleAssignment.ReadWrite.All` | Application | Grant any app permission — self-escalation |
| `User.ReadWrite.All` | Application | Modify any user — password reset, MFA bypass |

### Consent grant detection

```kql
AuditLogs
| where OperationName == "Consent to application"
| extend ConsentedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend AppName = tostring(TargetResources[0].displayName)
| extend Permissions = tostring(TargetResources[0].modifiedProperties)
| where ConsentedBy !in (known_admin_list)
```

---

## 11. Entity identifier alignment

| Concept | Entra ID / Sentinel | Defender | CrowdStrike |
|---|---|---|---|
| User | `UserPrincipalName`, `UserId` (GUID) | `AccountUpn`, `AccountSid` | `UserName` |
| Device | `DeviceDetail.deviceId` | `DeviceId` | `aid` |
| IP | `IPAddress` | `RemoteIP` | `RemoteAddressIP4` |
| Application | `AppId`, `AppDisplayName` | — | — |
| Service principal | `ServicePrincipalId` | — | — |

Cross-platform correlation happens at the SIEM/SOAR layer. The `UserPrincipalName` is the most reliable cross-platform join key for identity.

---

## 12. Detection cheatsheet — quick-reference queries

> The examples below use KQL (Sentinel). The **logic and field names are portable** — adapt the syntax to your SIEM (SPL for Splunk, EQL/ES|QL for Elastic, CQL for CrowdStrike NG-SIEM, etc.).

### Password spray (high-volume failed auth from single IP)

```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType in ("50126", "50053", "50064")
| summarize FailCount = count(), DistinctUsers = dcount(UserPrincipalName) by IPAddress
| where DistinctUsers > 10 and FailCount > 50
```

### MFA fatigue (repeated denials then success)

```kql
let MFADenials = SigninLogs
    | where ResultType == "500121"
    | summarize DenialCount = count(), FirstDenial = min(TimeGenerated), LastDenial = max(TimeGenerated) by UserPrincipalName
    | where DenialCount >= 5;
let Successes = SigninLogs
    | where ResultType == "0";
MFADenials
| join kind=inner Successes on UserPrincipalName
| where TimeGenerated between (LastDenial .. (LastDenial + 30m))
```

### New inbox rule after risky sign-in (AiTM chain)

```kql
let RiskySignIns = SigninLogs
    | where column_ifexists("RiskLevelDuringSignIn", "none") in ("medium", "high")
    | where ResultType == "0"
    | project RiskyTime = TimeGenerated, UserPrincipalName, IPAddress;
OfficeActivity
| where Operation in ("New-InboxRule", "Set-InboxRule")
| join kind=inner RiskySignIns on $left.UserId == $right.UserPrincipalName
| where TimeGenerated between (RiskyTime .. (RiskyTime + 1h))
```

### Suspicious OAuth consent grant

```kql
AuditLogs
| where OperationName == "Consent to application"
| extend AppName = tostring(TargetResources[0].displayName)
| extend ConsentedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend Perms = tostring(TargetResources[0].modifiedProperties)
| where Perms has_any ("Mail.ReadWrite", "Files.ReadWrite.All", "Directory.ReadWrite.All")
```

### Service principal credential addition (persistence)

```kql
AuditLogs
| where OperationName in ("Add service principal credentials", "Update application – Certificates and secrets management")
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetApp = tostring(TargetResources[0].displayName)
```

### Cross-tenant anomaly (novel B2B access)

```kql
SigninLogs
| where HomeTenantId != ResourceTenantId
| where ResultType == "0"
| summarize FirstSeen = min(TimeGenerated), Count = count() by UserPrincipalName, HomeTenantId, AppDisplayName
| where FirstSeen > ago(7d)
```

---

## 13. Quality checklist

- [ ] SKU tier requirement declared (P1 vs P2).
- [ ] `column_ifexists()` used for P2-only columns.
- [ ] `ResultType` compared as string, not integer.
- [ ] ResultType codes commented inline with meaning.
- [ ] All relevant sign-in tables queried (interactive + non-interactive + SP where applicable).
- [ ] Nested JSON parsed via `parse_json()` / `todynamic()`.
- [ ] Cross-tenant scenarios considered (B2B guest access).
- [ ] Risk columns used for enrichment, not as sole detection signal in P1 environments.
- [ ] Directory role changes monitored (permanent assignments, PIM activations).
- [ ] Token type and theft vector documented for token-based detections.
- [ ] Dangerous application permissions flagged in consent-based detections.
- [ ] FOCI token sharing considered for token theft scope assessment.
- [ ] MITRE technique mapping accurate (T1078, T1098, T1556, T1621, T1557 as applicable).
- [ ] Coordinate with the relevant platform skill for query mechanics (`microsoft-sentinel`, `splunk-spl-processing`, `crowdstrike-falcon`, etc.) and `detection-engineering` for lifecycle.
