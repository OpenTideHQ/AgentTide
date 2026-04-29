---
name: amazon-web-services
description: AWS security telemetry and internals for detection engineering — CloudTrail event structure (management vs data events, read-only vs write), IAM mechanics (roles, policies, assume-role chains, SCPs, permission boundaries), GuardDuty finding types, S3 access logging, VPC Flow Logs, Lambda execution model, cross-account access patterns, and the mapping between AWS operations and detection telemetry. Use when authoring detections targeting AWS cloud infrastructure abuse, privilege escalation, data exfiltration, or persistence.
---

# Amazon Web Services — detection-relevant internals

This skill encodes how AWS security-relevant services work at the level needed to detect cloud infrastructure abuse.

---

## 1. CloudTrail event structure

Every AWS API call generates a CloudTrail event. Key fields:

| Field | Type | Detection use |
|---|---|---|
| `eventSource` | string | AWS service (e.g. `iam.amazonaws.com`, `s3.amazonaws.com`) |
| `eventName` | string | API action (e.g. `CreateUser`, `PutBucketPolicy`) |
| `eventType` | string | `AwsApiCall`, `AwsConsoleSignIn`, `AwsServiceEvent` |
| `sourceIPAddress` | string | Caller IP. `AWS Internal` for service-initiated. |
| `userIdentity` | object | Who made the call. Contains `type`, `arn`, `accountId`, `principalId`. |
| `userIdentity.type` | string | `Root`, `IAMUser`, `AssumedRole`, `FederatedUser`, `AWSService` |
| `requestParameters` | object | API call parameters (varies per API) |
| `responseElements` | object | API response (varies per API) |
| `errorCode` | string | `AccessDenied`, `UnauthorizedAccess`, etc. |
| `readOnly` | boolean | `true` = read operation, `false` = write/mutate |
| `managementEvent` | boolean | `true` = control plane, `false` = data plane |

### Management vs data events

| Type | Examples | Default logging |
|---|---|---|
| **Management events** | `CreateUser`, `RunInstances`, `PutBucketPolicy` | Logged by default |
| **Data events** | `GetObject` (S3), `Invoke` (Lambda) | NOT logged by default — must enable |

**Critical gap**: S3 object-level access (`GetObject`, `PutObject`) is NOT in CloudTrail by default. Without data event logging, S3 exfiltration is invisible.

---

## 2. IAM mechanics

### Identity types

| Type | `userIdentity.type` | Credentials | Detection relevance |
|---|---|---|---|
| **Root** | `Root` | Email + password + MFA | Root usage is always high-signal |
| **IAM user** | `IAMUser` | Access key + secret key, or console password | Long-lived credentials. Key rotation discipline. |
| **Assumed role** | `AssumedRole` | Temporary credentials from `sts:AssumeRole` | Cross-account access, privilege escalation |
| **Federated user** | `FederatedUser` | SAML/OIDC federation | External IdP trust chain |
| **AWS service** | `AWSService` | Service-linked role | `sourceIPAddress` = `AWS Internal` |

### Assume-role chains

```
IAM User (Account A) → AssumeRole → Role (Account B) → AssumeRole → Role (Account C)
```

Each hop creates a new set of temporary credentials. The `userIdentity.arn` shows the assumed role, but `userIdentity.sessionContext.sessionIssuer` reveals the original identity.

**Detection**: Unusual assume-role chains (depth > 2), cross-account role assumptions from unexpected accounts, role assumption from unexpected source IPs.

### Policy evaluation order

```
1. SCPs (Service Control Policies) — org-level deny
2. Resource-based policies — allow/deny on the resource
3. IAM permission boundaries — maximum permissions
4. Identity-based policies — user/role permissions
5. Session policies — temporary credential restrictions
```

**Detection-relevant**: An `AccessDenied` error may indicate SCP enforcement (legitimate) or privilege probing (suspicious). Correlate with the caller's expected permissions.

---

## 3. Critical detection events

### Persistence

| eventName | Service | What it means |
|---|---|---|
| `CreateUser` | IAM | New IAM user — backdoor account |
| `CreateAccessKey` | IAM | New access key for existing user — credential persistence |
| `CreateLoginProfile` | IAM | Console password added to IAM user |
| `AttachUserPolicy` / `AttachRolePolicy` | IAM | Policy attachment — privilege escalation |
| `PutUserPolicy` / `PutRolePolicy` | IAM | Inline policy — harder to audit than managed policies |
| `CreateRole` | IAM | New role — potential for assume-role abuse |
| `UpdateAssumeRolePolicy` | IAM | Trust policy modification — who can assume the role |

### Defence impairment

| eventName | Service | What it means |
|---|---|---|
| `StopLogging` / `DeleteTrail` | CloudTrail | Audit trail disabled |
| `PutEventSelectors` | CloudTrail | Logging scope reduced |
| `DeleteFlowLogs` | VPC | Network visibility removed |
| `DisableGuardDuty` / `DeleteDetector` | GuardDuty | Threat detection disabled |
| `PutBucketLogging` (disable) | S3 | Access logging disabled |

### Data exfiltration

| eventName | Service | What it means |
|---|---|---|
| `GetObject` | S3 | Object download (requires data event logging) |
| `PutBucketPolicy` (public) | S3 | Bucket made public |
| `CreateSnapshot` + `ModifySnapshotAttribute` | EC2 | EBS snapshot shared with external account |
| `CopySnapshot` | EC2 | Snapshot copied to attacker account |
| `CreateDBSnapshot` + `ModifyDBSnapshotAttribute` | RDS | Database snapshot shared externally |

---

## 4. GuardDuty finding types

GuardDuty findings follow the pattern: `ThreatPurpose:ResourceType/ThreatName`.

| Category | Example findings | Detection use |
|---|---|---|
| **Credential access** | `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` | Instance role credentials used from outside AWS |
| **Persistence** | `Persistence:IAMUser/AnomalousBehavior` | Unusual API calls for the identity |
| **Privilege escalation** | `PrivilegeEscalation:IAMUser/AdministrativePermissions` | Policy granting admin access |
| **Exfiltration** | `Exfiltration:S3/MaliciousIPCaller` | S3 access from known-bad IP |
| **Crypto mining** | `CryptoCurrency:EC2/BitcoinTool.B!DNS` | DNS queries to mining pools |
| **Stealth** | `Stealth:IAMUser/CloudTrailLoggingDisabled` | CloudTrail disabled |

---

## 5. Cross-account access patterns

| Pattern | Mechanism | Detection signal |
|---|---|---|
| **Cross-account role assumption** | `sts:AssumeRole` with external account ID | `userIdentity.accountId` != resource account |
| **Resource-based policy sharing** | S3 bucket policy, KMS key policy granting external access | `Principal` in policy contains external account |
| **Organisation access** | SCPs, delegated admin, StackSets | `userIdentity.type` = `AWSService` with org context |
| **External ID requirement** | `sts:AssumeRole` with `ExternalId` condition | Missing ExternalId = confused deputy vulnerability |

---

## 6. SIEM ingestion

| AWS source | Sentinel table | Splunk sourcetype | Notes |
|---|---|---|---|
| CloudTrail | `AWSCloudTrail` | `aws:cloudtrail` | Primary audit log |
| GuardDuty | `AWSGuardDuty` (via S3/EventBridge) | `aws:guardduty` | Threat findings |
| VPC Flow Logs | `AWSVPCFlow` | `aws:cloudwatchlogs:vpcflow` | Network telemetry |
| S3 access logs | Custom ingestion | `aws:s3:accesslogs` | Object-level access |
| CloudWatch Logs | Custom ingestion | `aws:cloudwatch` | Application/system logs |

---

## 7. Quality checklist

- [ ] CloudTrail data event logging requirement declared (S3, Lambda).
- [ ] `userIdentity.type` used to distinguish Root/IAMUser/AssumedRole.
- [ ] Assume-role chains traced via `sessionContext.sessionIssuer`.
- [ ] `sourceIPAddress` checked (`AWS Internal` = service-initiated, not user).
- [ ] `errorCode` = `AccessDenied` correlated with expected permissions.
- [ ] Defence impairment events (StopLogging, DeleteDetector) monitored.
- [ ] Cross-account access patterns documented.
- [ ] GuardDuty finding types mapped to detection coverage.
- [ ] S3 public access detections cover both bucket policy and ACL.
- [ ] Snapshot sharing detections cover EBS, RDS, and AMI.
