---
name: google-cloud-platform
description: Google Cloud Platform security telemetry for detection engineering — Cloud Audit Logs structure (Admin Activity, Data Access, System Event, Policy Denied), IAM mechanics (roles, service accounts, workload identity federation, impersonation), GCP-specific attack patterns (service account key theft, cross-project access, storage exfiltration), VPC Flow Logs, and the mapping to Google SecOps (Chronicle) YARA-L and SIEM ingestion. Use when authoring detections targeting GCP infrastructure abuse.
---

# Google Cloud Platform — detection-relevant internals

This skill covers GCP cloud infrastructure security telemetry and the internals needed to detect abuse.

---

## 1. Cloud Audit Logs

GCP generates four types of audit logs:

| Log type | What it captures | Default | Detection use |
|---|---|---|---|
| **Admin Activity** | Resource configuration changes (create, delete, modify) | Always on, cannot be disabled | Primary detection source — control plane operations |
| **Data Access** | Resource data read/write (e.g. reading a GCS object) | Off by default (must enable) | Data exfiltration detection — critical gap if not enabled |
| **System Event** | GCP-initiated system actions | Always on | Infrastructure changes by Google (maintenance, auto-scaling) |
| **Policy Denied** | Access denied by VPC Service Controls or org policies | Always on | Privilege probing, policy bypass attempts |

### Audit log structure

| Field | Description | Detection use |
|---|---|---|
| `protoPayload.methodName` | API method called (e.g. `google.iam.admin.v1.CreateServiceAccount`) | Primary event classifier |
| `protoPayload.authenticationInfo.principalEmail` | Caller identity | Who performed the action |
| `protoPayload.requestMetadata.callerIp` | Source IP | Geolocation, anomaly detection |
| `protoPayload.authorizationInfo[]` | Permissions checked and granted/denied | Privilege analysis |
| `protoPayload.serviceData` / `protoPayload.request` | Request details | Operation-specific context |
| `resource.type` | GCP resource type (e.g. `gcs_bucket`, `gce_instance`) | Resource targeting |
| `resource.labels.project_id` | Project context | Cross-project access detection |
| `severity` | `INFO`, `WARNING`, `ERROR` | Error = potential access denied |

---

## 2. IAM mechanics

### Identity types

| Type | Identifier | Credentials | Detection relevance |
|---|---|---|---|
| **Google Account** | `user:email@gmail.com` | OAuth, password + MFA | Human user access |
| **Service Account** | `serviceAccount:name@project.iam.gserviceaccount.com` | Keys (JSON/P12) or workload identity | Long-lived keys are high-risk |
| **Google Group** | `group:name@domain.com` | Membership-based | Group membership changes = privilege changes |
| **Domain** | `domain:domain.com` | All users in domain | Overly broad grants |
| **allUsers** | `allUsers` | No authentication | Public access — always high-signal |
| **allAuthenticatedUsers** | `allAuthenticatedUsers` | Any Google account | Semi-public — still high-risk |

### Service account key lifecycle

| Operation | `methodName` | Detection signal |
|---|---|---|
| Key creation | `google.iam.admin.v1.CreateServiceAccountKey` | New long-lived credential — should be rare |
| Key deletion | `google.iam.admin.v1.DeleteServiceAccountKey` | Cleanup or anti-forensics |
| Key usage from external IP | Data Access logs | SA key used from outside GCP = potential theft |

**Critical**: Service account keys are the GCP equivalent of AWS access keys. They don't expire by default and provide persistent access. Key creation should be monitored and minimised — prefer workload identity federation.

### Workload identity federation

Allows external identities (AWS roles, Azure managed identities, OIDC providers) to impersonate GCP service accounts without keys.

**Detection**: `google.iam.credentials.v1.GenerateAccessToken` with `callerIp` from external cloud provider. Monitor for unexpected federation sources.

### Service account impersonation

```
User → iam.serviceAccounts.getAccessToken → SA token → API calls as SA
```

**Detection**: `google.iam.credentials.v1.GenerateAccessToken` — who is impersonating which service account, from where.

---

## 3. Critical detection events

### Persistence

| methodName | What it means |
|---|---|
| `google.iam.admin.v1.CreateServiceAccount` | New service account — backdoor identity |
| `google.iam.admin.v1.CreateServiceAccountKey` | New key for SA — credential persistence |
| `SetIamPolicy` (on any resource) | IAM policy change — privilege escalation |
| `google.cloud.functions.v1.CreateFunction` | New Cloud Function — code execution persistence |
| `google.compute.instances.v1.SetMetadata` | Instance metadata change — startup script persistence |

### Defence impairment

| methodName | What it means |
|---|---|
| `google.logging.v2.DeleteSink` | Log sink deleted — audit trail disruption |
| `google.logging.v2.UpdateSink` (with exclusion) | Log exclusion added — selective blindness |
| `SetIamPolicy` removing security roles | Security team access removed |
| `google.cloud.securitycenter.v1.UpdateFinding` (mute) | Security Command Center finding muted |

### Data exfiltration

| methodName | What it means |
|---|---|
| `storage.objects.get` | GCS object download (requires Data Access logging) |
| `storage.buckets.setIamPolicy` (allUsers) | Bucket made public |
| `compute.snapshots.create` + `compute.snapshots.setIamPolicy` | Disk snapshot shared externally |
| `bigquery.jobs.create` (export) | BigQuery data export |
| `storage.buckets.create` (in external project) | Data copied to attacker-controlled project |

---

## 4. GCP-specific attack patterns

### Pattern 1: Service account key theft → persistent access

1. Attacker compromises a workload with SA key access
2. Downloads SA key JSON file
3. Uses key from external infrastructure
4. **Detection**: SA key usage from non-GCP IP addresses

### Pattern 2: Metadata server abuse (SSRF → credential theft)

1. SSRF vulnerability in application running on GCE
2. Attacker queries `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`
3. Obtains SA access token
4. **Detection**: Token usage from unexpected IP (not the instance's IP)

### Pattern 3: Cross-project privilege escalation

1. Attacker has access to Project A
2. Service account in Project A has roles in Project B
3. Attacker impersonates SA to access Project B resources
4. **Detection**: Cross-project `SetIamPolicy` or resource access. `resource.labels.project_id` != caller's project.

---

## 5. SIEM ingestion

| GCP source | Chronicle (YARA-L) | Sentinel table | Splunk sourcetype |
|---|---|---|---|
| Admin Activity logs | UDM events (auto-ingested) | `GCPAuditLogs` (via Pub/Sub) | `google:gcp:pubsub:audit` |
| Data Access logs | UDM events | `GCPAuditLogs` | `google:gcp:pubsub:audit` |
| VPC Flow Logs | UDM events | Custom ingestion | `google:gcp:pubsub:flow` |
| Security Command Center | UDM events | `GoogleCloudSCC` | `google:gcp:scc` |

### Chronicle / Google SecOps

GCP audit logs are natively ingested into Chronicle and normalised to UDM (Unified Data Model). Detection rules use YARA-L 2.0. Key UDM fields:

| UDM field | Maps to |
|---|---|
| `metadata.event_type` | `USER_LOGIN`, `RESOURCE_CREATION`, etc. |
| `principal.user.email_addresses` | Caller identity |
| `principal.ip` | Source IP |
| `target.resource.name` | Target resource |
| `security_result.action` | `ALLOW`, `BLOCK` |

---

## 6. Quality checklist

- [ ] Data Access logging requirement declared (not enabled by default).
- [ ] `protoPayload.methodName` used as primary event filter.
- [ ] `principalEmail` distinguished between user and service account.
- [ ] Service account key creation monitored and minimised.
- [ ] Cross-project access patterns documented.
- [ ] `allUsers` / `allAuthenticatedUsers` grants flagged as public access.
- [ ] Metadata server (169.254.169.254) abuse considered for SSRF scenarios.
- [ ] Log sink integrity monitored (deletion, exclusion addition).
- [ ] Workload identity federation sources validated.
- [ ] SIEM ingestion method documented (Pub/Sub, Chronicle native, etc.).
