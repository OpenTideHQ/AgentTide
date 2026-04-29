---
name: microsoft-azure
description: Azure cloud infrastructure security telemetry for detection engineering — Azure Activity Log and Resource Manager operations, Azure RBAC model (roles, scopes, PIM), managed identity mechanics, Key Vault access patterns, storage account security, virtual machine and compute operations, network security groups, Azure Policy and Defender for Cloud signals, and the mapping between Azure operations and Sentinel/Defender telemetry. Use when authoring detections targeting Azure resource abuse, privilege escalation, data exfiltration, or persistence at the infrastructure layer. For Entra ID identity detections, use entra-id-protection instead.
---

# Microsoft Azure — detection-relevant internals

This skill covers Azure cloud infrastructure security. For Entra ID (identity/authentication), see `entra-id-protection`. For Sentinel query mechanics, see `microsoft-sentinel`.

---

## 1. Azure Activity Log

Every Azure Resource Manager (ARM) operation generates an Activity Log entry. Key fields:

| Field | Sentinel column (`AzureActivity`) | Detection use |
|---|---|---|
| `operationName` | `OperationNameValue` | ARM operation (e.g. `Microsoft.Compute/virtualMachines/write`) |
| `caller` | `Caller` | UPN or service principal ID |
| `callerIpAddress` | `CallerIpAddress` | Source IP |
| `status` | `ActivityStatusValue` | `Started`, `Succeeded`, `Failed` |
| `category` | `CategoryValue` | `Administrative`, `Security`, `ServiceHealth`, `Policy` |
| `resourceId` | `ResourceId` | Full ARM resource path |
| `level` | `Level` | `Informational`, `Warning`, `Error`, `Critical` |
| `claims` | `Claims_d` | JWT claims including `appid`, `oid`, `tid` |

### Operation name patterns

ARM operations follow the pattern: `Microsoft.<Provider>/<resourceType>/<action>`

| Pattern | Examples | Detection use |
|---|---|---|
| `*/write` | `Microsoft.Compute/virtualMachines/write` | Resource creation/modification |
| `*/delete` | `Microsoft.Storage/storageAccounts/delete` | Resource destruction |
| `*/action` | `Microsoft.KeyVault/vaults/secrets/getSecret/action` | Privileged operations |
| `*/listKeys/action` | `Microsoft.Storage/storageAccounts/listKeys/action` | Credential access |

---

## 2. Azure RBAC

### Role hierarchy

| Scope | Example | Inheritance |
|---|---|---|
| **Management group** | `/providers/Microsoft.Management/managementGroups/mg1` | Inherits down to all subscriptions |
| **Subscription** | `/subscriptions/{sub-id}` | Inherits down to all resource groups |
| **Resource group** | `/subscriptions/{sub-id}/resourceGroups/{rg}` | Inherits down to all resources |
| **Resource** | `/subscriptions/{sub-id}/resourceGroups/{rg}/providers/...` | Specific resource only |

### Critical built-in roles

| Role | Scope | Risk | Detection signal |
|---|---|---|---|
| **Owner** | Any | Full control including RBAC | Role assignment at subscription/MG scope |
| **Contributor** | Any | Full control except RBAC | Resource creation/modification |
| **User Access Administrator** | Any | Can grant any role to anyone | Role assignment creation |
| **Key Vault Administrator** | Key Vault | Full secret/key/cert access | Secret access from unexpected principal |
| **Storage Blob Data Owner** | Storage | Full blob access bypassing ACLs | Data plane access |
| **Virtual Machine Contributor** | Compute | VM management including extensions | VM extension installation (code execution) |

### Privileged Identity Management (PIM)

PIM provides just-in-time role activation. Detection-relevant:
- `PIM` operations in `AuditLogs`: `Add member to role in PIM completed (permanent)` vs `(timebound)`
- Permanent role assignments bypass PIM controls — always alert
- Role activation from unexpected location/device

---

## 3. Managed identities

| Type | How it works | Detection relevance |
|---|---|---|
| **System-assigned** | Tied to a specific resource lifecycle | Token requests from the resource's IMDS endpoint |
| **User-assigned** | Independent lifecycle, can be shared | Can be attached to multiple resources — broader blast radius |

### Token acquisition

Managed identities acquire tokens via the Instance Metadata Service (IMDS) at `169.254.169.254`. The token is scoped to the identity's RBAC permissions.

**Detection**: Managed identity tokens used from outside Azure (IMDS is only accessible from within the VM). `CallerIpAddress` in Activity Log should be an Azure IP for managed identity operations.

---

## 4. Key Vault

| Operation | Detection signal |
|---|---|
| `SecretGet` | Secret accessed — correlate with caller identity and IP |
| `SecretSet` | Secret created/modified — potential credential storage |
| `SecretList` | Secret enumeration — reconnaissance |
| `KeySign` / `KeyDecrypt` | Cryptographic operations — potential data access |
| `CertificateGet` | Certificate accessed — potential for certificate-based auth abuse |
| `VaultAccessPolicyChange` | Access policy modified — privilege escalation |

Key Vault diagnostic logs go to `AzureDiagnostics` with `ResourceType` = `VAULTS`. Enable diagnostic settings to capture data plane operations.

---

## 5. Storage account security

| Attack vector | Mechanism | Detection |
|---|---|---|
| **Public blob access** | Container access level set to `Blob` or `Container` | `Microsoft.Storage/storageAccounts/blobServices/containers/write` with public access |
| **SAS token abuse** | Shared Access Signature with excessive permissions/lifetime | SAS token usage from unexpected IP (storage analytics logs) |
| **Storage key access** | `listKeys` operation exposes full account access | `Microsoft.Storage/storageAccounts/listKeys/action` from non-admin |
| **Cross-tenant replication** | Object replication to external account | Replication policy creation to external destination |

---

## 6. Compute operations

### VM-level attacks

| Operation | Detection signal |
|---|---|
| `Microsoft.Compute/virtualMachines/extensions/write` | VM extension installation — arbitrary code execution on the VM |
| `Microsoft.Compute/virtualMachines/runCommand/action` | Run Command — remote code execution via ARM API |
| `Microsoft.Compute/virtualMachines/write` (with custom data) | Custom script execution during VM creation |
| `Microsoft.Compute/disks/beginGetAccess/action` | Disk export — data exfiltration via disk snapshot |
| `Microsoft.Compute/snapshots/write` + `Microsoft.Compute/snapshots/beginGetAccess/action` | Snapshot creation + export |

### Serverless (Functions, Logic Apps)

| Operation | Detection signal |
|---|---|
| Function deployment with external dependencies | Supply chain risk |
| Logic App connector creation to external services | Data exfiltration channel |
| Function with managed identity accessing Key Vault | Privilege chain |

---

## 7. Network security

| Resource | Detection-relevant operations |
|---|---|
| **NSG** | Rule additions allowing inbound from `0.0.0.0/0` (any) on sensitive ports |
| **Azure Firewall** | Policy modifications reducing protection |
| **Private endpoints** | Removal of private endpoints exposing services publicly |
| **DNS zones** | Record modifications (potential for DNS hijacking) |
| **VNet peering** | New peering to unexpected VNets (lateral movement path) |

---

## 8. Defender for Cloud signals

| Signal | Source | Detection use |
|---|---|---|
| Security alerts | `SecurityAlert` table | Defender-generated threat detections |
| Recommendations | `SecurityRecommendation` | Misconfiguration indicators |
| Secure Score changes | `SecureScoreControls` | Security posture degradation |
| Regulatory compliance | `SecurityRegulatoryCompliance` | Compliance drift |

---

## 9. Telemetry mapping

| Azure operation | Sentinel table | Notes |
|---|---|---|
| ARM operations | `AzureActivity` | Control plane — always available |
| Entra ID operations | `AuditLogs`, `SigninLogs` | Identity plane |
| Key Vault operations | `AzureDiagnostics` (ResourceType=VAULTS) | Requires diagnostic settings |
| Storage operations | `StorageBlobLogs`, `AzureDiagnostics` | Requires diagnostic settings |
| NSG flow logs | `AzureNetworkAnalytics_CL` | Requires NSG flow log configuration |
| Defender alerts | `SecurityAlert` | Requires Defender for Cloud |

---

## 10. Quality checklist

- [ ] `OperationNameValue` used as primary filter (not `OperationName` which is display-friendly).
- [ ] `ActivityStatusValue` checked for `Succeeded` (not just any status).
- [ ] `Caller` distinguished between UPN (user) and GUID (service principal).
- [ ] RBAC scope considered (subscription-level role assignment is higher signal than resource-level).
- [ ] PIM activation vs permanent assignment distinguished.
- [ ] Managed identity token usage validated against expected source (Azure IP).
- [ ] Key Vault diagnostic logging requirement declared.
- [ ] Storage account data plane logging requirement declared.
- [ ] VM extension and Run Command operations monitored.
- [ ] Cross-tenant/cross-subscription operations flagged.
