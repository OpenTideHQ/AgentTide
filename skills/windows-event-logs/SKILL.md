---
name: windows-event-logs
description: Windows native event log authoring guidance for detection engineering — Security, Sysmon, PowerShell, and system event channels. Covers critical Event IDs (4624/4625/4688/4697/4720/5140/7045), Sysmon EID 1-29 with configuration discipline, PowerShell ScriptBlock/Module logging, EVTX channel routing, audit policy prerequisites, XML event data extraction, and the mapping between Windows events and Sentinel SecurityEvent / Defender DeviceEvents tables. Use when authoring detections that depend on native Windows telemetry, configuring audit policies for detection coverage, or bridging Windows events to platform-specific query skills.
---

# Windows Event Logs — detection authoring

This skill encodes the Windows-native event log knowledge required for detection content that depends on Security, Sysmon, PowerShell, or System event channels. It bridges the gap between raw Windows telemetry and the platform-specific query skills (`microsoft-sentinel`, `microsoft-defender-endpoint`).

---

## 1. Event channel landscape

| Channel | Log name | Key content |
|---|---|---|
| **Security** | `Security` | Authentication, process creation, object access, policy changes, account management |
| **Sysmon** | `Microsoft-Windows-Sysmon/Operational` | Process creation with hashes, network connections, file creation, registry, DNS, WMI, named pipes, clipboard |
| **PowerShell** | `Microsoft-Windows-PowerShell/Operational` | ScriptBlock logging (4104), Module logging (4103) |
| **System** | `System` | Service installation (7045), driver loads, system state |
| **Windows Defender** | `Microsoft-Windows-Windows Defender/Operational` | AV detections, exclusion changes, tamper events |
| **Task Scheduler** | `Microsoft-Windows-TaskScheduler/Operational` | Scheduled task creation/modification/execution |
| **WMI** | `Microsoft-Windows-WMI-Activity/Operational` | WMI subscription events |
| **AppLocker** | `Microsoft-Windows-AppLocker/*` | Application execution control |
| **NTLM** | `Microsoft-Windows-NTLM/Operational` | NTLM authentication events (requires audit policy) |

---

## 2. Critical Security Event IDs

### Authentication

| EID | Description | Detection use |
|---|---|---|
| **4624** | Successful logon | Lateral movement (Type 3/10), service logon (Type 5), interactive (Type 2) |
| **4625** | Failed logon | Brute force, password spray |
| **4648** | Explicit credential logon | Credential use with alternate identity (runas, PsExec) |
| **4634** / **4647** | Logoff | Session duration analysis |
| **4672** | Special privileges assigned | Privileged logon detection |
| **4768** | Kerberos TGT request | Kerberoasting (RC4 encryption type 0x17) |
| **4769** | Kerberos service ticket request | Kerberoasting, service access |
| **4771** | Kerberos pre-auth failed | Password spray against Kerberos |
| **4776** | NTLM credential validation | NTLM relay, pass-the-hash |

**Logon Type reference** (EID 4624/4625):

| Type | Name | Meaning |
|---|---|---|
| 2 | Interactive | Console logon |
| 3 | Network | SMB, WinRM, mapped drives |
| 4 | Batch | Scheduled tasks |
| 5 | Service | Service start |
| 7 | Unlock | Workstation unlock |
| 8 | NetworkCleartext | IIS basic auth, PowerShell remoting with CredSSP |
| 9 | NewCredentials | `runas /netonly` |
| 10 | RemoteInteractive | RDP |
| 11 | CachedInteractive | Cached domain credentials |

### Process creation

| EID | Description | Detection use |
|---|---|---|
| **4688** | Process creation | Command-line logging (requires audit policy + GPO) |

**Critical prerequisite**: Process command-line logging is **not enabled by default**. Requires:
- Audit Policy: `Audit Process Creation` → Success
- GPO: `Include command line in process creation events` → Enabled

Without this, EID 4688 contains the process name but **no command line** — most detection value is lost.

### Account management

| EID | Description | Detection use |
|---|---|---|
| **4720** | User account created | Persistence, backdoor accounts |
| **4722** | User account enabled | Re-enabled dormant accounts |
| **4724** | Password reset attempt | Credential manipulation |
| **4728** / **4732** / **4756** | Member added to security group | Privilege escalation |
| **4738** | User account changed | Account property manipulation |
| **4740** | Account locked out | Brute force indicator |

### Object access and file shares

| EID | Description | Detection use |
|---|---|---|
| **4663** | Object access attempt | File/registry access auditing |
| **5140** | Network share accessed | Lateral movement via SMB |
| **5145** | Network share object checked | Detailed share access (file-level) |

### Service and scheduled task

| EID | Description | Detection use |
|---|---|---|
| **7045** (System) | Service installed | Persistence, PsExec, lateral movement |
| **4697** (Security) | Service installed (Security log) | Same as 7045, different channel |
| **4698** | Scheduled task created | Persistence |
| **4702** | Scheduled task updated | Persistence modification |

### Policy and privilege

| EID | Description | Detection use |
|---|---|---|
| **4703** | Token right adjusted | Privilege escalation |
| **4719** | Audit policy changed | Defence impairment |
| **1102** | Audit log cleared | Anti-forensics |

---

## 3. Sysmon Event IDs

Sysmon provides richer telemetry than native Security events but requires deployment and configuration.

| EID | Description | Detection use |
|---|---|---|
| **1** | Process creation (with hashes, parent, command line) | Primary process detection |
| **2** | File creation time changed | Timestomping |
| **3** | Network connection | Outbound C2, lateral movement |
| **5** | Process terminated | Process lifecycle |
| **6** | Driver loaded | Rootkit, vulnerable driver (BYOVD) |
| **7** | Image loaded (DLL) | DLL side-loading, injection |
| **8** | CreateRemoteThread | Process injection |
| **9** | RawAccessRead | Direct disk access (credential theft) |
| **10** | ProcessAccess | LSASS access (credential dumping) |
| **11** | FileCreate | Payload drops, staging |
| **12/13/14** | Registry events | Persistence, configuration changes |
| **15** | FileCreateStreamHash | ADS (Alternate Data Streams) |
| **17/18** | Pipe created/connected | Named pipe C2 (Cobalt Strike, Metasploit) |
| **19/20/21** | WMI events | WMI persistence |
| **22** | DNS query | C2 domain resolution, DGA |
| **23** | FileDelete (archived) | Deleted file capture |
| **24** | Clipboard change | Clipboard monitoring |
| **25** | Process tampering | Process hollowing, herpaderping |
| **26** | FileDeleteDetected | File deletion without archive |
| **27** | FileBlockExecutable | Executable blocked |
| **28** | FileBlockShredding | Shredding blocked |
| **29** | FileExecutableDetected | Executable file detected |

### Sysmon configuration discipline

- **Never deploy default Sysmon config in production.** The default logs everything and overwhelms storage.
- Use community-maintained configs (SwiftOnSecurity, Olaf Hartong) as a **starting point**, then tune.
- **Exclude high-volume legitimate processes** via `<RuleGroup>` exclusions — but document every exclusion.
- **Hash algorithms**: configure `SHA256` minimum. `MD5` alone is insufficient for modern threat intel.
- **LSASS protection** (EID 10): filter `TargetImage` to `lsass.exe` only — unfiltered ProcessAccess is extremely noisy.

---

## 4. PowerShell logging

| Feature | Event ID | Channel | Prerequisite |
|---|---|---|---|
| **ScriptBlock logging** | 4104 | PowerShell Operational | GPO: `Turn on PowerShell Script Block Logging` |
| **Module logging** | 4103 | PowerShell Operational | GPO: `Turn on Module Logging` (specify modules) |
| **Transcription** | — | File-based | GPO: `Turn on PowerShell Transcription` |

**ScriptBlock logging (4104)** is the highest-value PowerShell telemetry:
- Captures the **deobfuscated** script content (after PowerShell's own parsing)
- Captures scripts loaded via `-EncodedCommand`, `Invoke-Expression`, `Add-Type`
- Warning level 3 = suspicious (automatic for known-bad patterns)

**Detection patterns**:
- Base64-decoded content containing `WebClient`, `DownloadString`, `IEX`
- AMSI bypass attempts (`AmsiUtils`, `amsiInitFailed`)
- Reflection-based .NET calls (`[System.Reflection.Assembly]::Load`)
- Credential access (`Get-Credential`, `ConvertTo-SecureString` with plaintext)

---

## 5. Audit policy prerequisites

Detection content must declare which audit policies are required. Without the correct policy, the events simply do not generate.

| Category | Subcategory | Required for |
|---|---|---|
| Account Logon | Credential Validation | 4776 (NTLM) |
| Account Logon | Kerberos Authentication Service | 4768, 4771 |
| Account Logon | Kerberos Service Ticket Operations | 4769 |
| Logon/Logoff | Logon | 4624, 4625 |
| Logon/Logoff | Special Logon | 4672 |
| Object Access | File Share | 5140, 5145 |
| Object Access | Detailed File Share | 5145 (file-level) |
| Detailed Tracking | Process Creation | 4688 |
| Account Management | User Account Management | 4720, 4722, 4724, 4738 |
| Account Management | Security Group Management | 4728, 4732, 4756 |
| Policy Change | Audit Policy Change | 4719 |
| System | Security System Extension | 4697 |

**Rule**: Every detection that depends on a specific Event ID must document the audit policy prerequisite. A detection for EID 5145 that doesn't mention "Detailed File Share auditing required" will silently fail in environments without it.

---

## 6. Platform table mapping

| Windows source | Sentinel table | Defender table | Notes |
|---|---|---|---|
| Security log | `SecurityEvent` | `DeviceLogonEvents`, `DeviceProcessEvents` | Defender normalises into typed tables |
| Sysmon | `Event` (Sysmon channel) or `SysmonEvent` | `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents` | Defender sensor provides equivalent telemetry natively |
| PowerShell 4104 | `Event` (PowerShell channel) | `DeviceEvents` (ActionType: PowerShellCommand) | |
| System 7045 | `Event` (System channel) | `DeviceEvents` (ActionType: ServiceInstalled) | |

**Key insight**: Microsoft Defender for Endpoint provides **native sensor telemetry** that overlaps with Sysmon. In Defender-managed environments, Sysmon is often redundant for process/file/network events. However, Sysmon provides unique value for:
- Named pipe events (EID 17/18) — no native Defender equivalent
- WMI subscription events (EID 19/20/21) — partial Defender coverage
- Clipboard monitoring (EID 24) — no Defender equivalent
- DNS query logging (EID 22) — Defender has `DeviceNetworkEvents` but different granularity

---

## 7. XML event data extraction (Sentinel)

Security events in Sentinel's `SecurityEvent` table store structured data in the `EventData` column as XML. Common extraction patterns:

```kql
// Extract command line from 4688
SecurityEvent
| where EventID == 4688
| extend CommandLine = tostring(parse_xml(EventData).DataItem.EventData.Data[8]["#text"])

// Better: use the pre-parsed columns when available
SecurityEvent
| where EventID == 4688
| where CommandLine has "powershell"  // Pre-parsed in newer SecurityEvent schema
```

**Note**: Sentinel's `SecurityEvent` table pre-parses many common fields (`TargetUserName`, `IpAddress`, `CommandLine`, etc.). Check the table schema before resorting to XML parsing — it's expensive.

---

## 8. Detection anti-patterns

| Anti-pattern | Description | Fix |
|---|---|---|
| **Assuming command-line logging is enabled** | Writing 4688 detections without noting the GPO prerequisite | Document the prerequisite; provide a validation query |
| **Sysmon without config declaration** | Referencing Sysmon EIDs without specifying which config rules must be active | Declare required Sysmon config rules |
| **Logon Type confusion** | Alerting on all 4624 events without filtering by Logon Type | Filter to relevant types (3, 10 for lateral movement) |
| **Machine account noise** | Not excluding `$`-suffixed accounts from authentication detections | Add `where TargetUserName !endswith "$"` |
| **Service account noise** | Not excluding known service accounts from logon anomaly detections | Maintain exclusion list with audit trail |
| **EID 4688 without parent process** | Missing the parent process context that Sysmon EID 1 provides natively | Use Sysmon EID 1 or Defender `DeviceProcessEvents` for parent chain |

---

## 9. Quality checklist

- [ ] Audit policy prerequisites documented for every Event ID used.
- [ ] Sysmon configuration requirements declared (if Sysmon EIDs referenced).
- [ ] PowerShell logging GPO requirements declared (if 4103/4104 referenced).
- [ ] Logon Type filtered appropriately for authentication detections.
- [ ] Machine accounts (`$`) excluded where appropriate.
- [ ] Platform table mapping declared (SecurityEvent vs DeviceProcessEvents vs Event).
- [ ] Command-line logging prerequisite noted for EID 4688 detections.
- [ ] XML parsing avoided when pre-parsed columns exist.
- [ ] Sysmon vs Defender native telemetry overlap considered.
- [ ] MITRE ATT&CK data components aligned with the event source.
