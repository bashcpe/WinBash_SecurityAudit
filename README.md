#  WinBASH-Audit: Local Windows Security & Hardening Engine

**WinBASH-Audit** is a modular, read-only PowerShell security assessment engine designed to evaluate Windows hosts against common local privilege escalation (LPE) vectors, credential exposure risks, and defensive misconfigurations, made as a passion project by Sebastian Castillo, in fulfillment of his Ethical Hacking and Cybersecurity course.

Built as a non-invasive auditing tool, it maps every check to the **MITRE ATT&CK® framework**, calculates a weighted **Posture Deficit Score**, and generates structured JSON telemetry for SIEM ingestion or compliance reporting.

---

##  Key Features

* **100% Read-Only & Non-Destructive:** Queries WMI/CIM, registry hives, and local policies passively without modifying system state or executing active exploits.
* **Modular 5-Domain Architecture:** Decoupled audit functions make it easy to add custom enterprise compliance checks.
* **Quantitative Risk Scoring:** Assigns weighted severity values (`Low` to `Critical`) to calculate an overall host risk rating (*Optimal*, *Low Risk*, *Moderate Risk*, *High Exposure*).
* **MITRE ATT&CK® Alignment:** Every finding includes the specific technique ID and actionable remediation guidance.
* **SIEM-Ready Output:** Exports clean console summaries alongside structured JSON reports for automated pipeline integration.

---

##  Architecture & Workflow

The script follows a decoupled collector-orchestrator pattern:

```text
[ Start-SecurityPostureAudit (Orchestrator) ]
       │
       ├──► Module 1: System & Patch Level (Invoke-SystemAndDefenseAudit)
       ├──► Module 2: Privilege Escalation (Invoke-PrivilegeEscalationAudit)
       ├──► Module 3: Credential Protection (Invoke-CredentialProtectionAudit)
       ├──► Module 4: Network Footprinting (Invoke-NetworkFootprintAudit)
       └──► Module 5: User & Group Hygiene (Invoke-UserAndGroupHygieneAudit)
       │
       ▼
[ Add-AuditFinding (Standardized Schema & Weight Calculator) ]
       │
       ▼
[ Console Dashboard Table ]  +  [ Optional JSON Telemetry Report ]
```

### Severity Weighting Model

| Severity Level | Weight | Criteria |
| :--- | :---: | :--- |
| **Critical** | `10` | Trivial privilege escalation to `SYSTEM` or cleartext credential exposure. |
| **High** | `8` | Core defensive controls disabled (Firewall, Defender, LSASS protection). |
| **Medium** | `5` | Exploitable misconfigurations requiring specific secondary conditions (e.g., Unquoted Paths). |
| **Low** | `2` | Best-practice deviations and administrative sprawl. |
| **Informational** | `0` | General telemetry and baseline state observations. |

---

##  MITRE ATT&CK® Coverage

| Check ID | Audit Domain | Misconfiguration / Check | Severity | MITRE ATT&CK ID |
| :--- | :--- | :--- | :--- | :--- |
| `SYS-01` | System & Defense | Outdated OS Patch Level (>60 Days) | Medium | `T1068` - Exploitation for Privilege Escalation |
| `SYS-02` | System & Defense | Defender Real-Time Protection Disabled | High | `T1562.001` - Impair Defenses: Disable or Modify Tools |
| `LPE-01` | Privilege Escalation | Unquoted Service Binary Paths | Medium | `T1574.009` - Hijack Execution Flow: Unquoted Path |
| `LPE-02` | Privilege Escalation | `AlwaysInstallElevated` Policy Enabled | Critical | `T1548.002` - Abuse Elevation Control Mechanism |
| `CRED-01` | Credential Protection | LSASS `RunAsPPL` Protection Disabled | High | `T1003.001` - OS Credential Dumping: LSASS Memory |
| `CRED-02` | Credential Protection | WDigest Cleartext Caching Enabled | Critical | `T1003.001` - OS Credential Dumping: LSASS Memory |
| `CRED-03` | Credential Protection | Residual Unattended Deployment Files | Medium | `T1552.001` - Unsecured Credentials: Credentials In Files |
| `NET-01` | Network Footprinting | Windows Firewall Profile Disabled | High | `T1562.004` - Disable or Modify System Firewall |
| `NET-02` | Network Footprinting | Legacy SMBv1 Protocol Enabled | High | `T1210` - Exploitation of Remote Services |
| `IAM-01` | User & Group Hygiene | User Account Control (`EnableLUA`) Disabled | High | `T1548.002` - Bypass User Account Control |
| `IAM-02` | User & Group Hygiene | UAC Admin Prompt Set to 'Elevate Without Prompting' | Medium | `T1548.002` - Bypass User Account Control |
| `IAM-03` | User & Group Hygiene | Excessive Local Administrator Accounts | Low | `T1078.003` - Valid Accounts: Local Accounts |

---

##  Getting Started

### Prerequisites
* **OS:** Windows 10 / 11 or Windows Server 2016+
* **PowerShell:** Version 5.1 or PowerShell Core (7.x)
* **Privileges:** Local Administrator privileges are recommended for complete registry and service inspection.

### Usage

1. **Clone the repository:**
   ```powershell
   git clone https://github.com/bashcpe/WinBash_SecurityAudit
   cd WinBash_SecurityAudit
   ```

2. **Bypass execution policy for the current session (if required):**
   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force
   ```

3. **Run a standard console audit:**
   ```powershell
   .\Invoke-WindowsSecurityAudit.ps1 -ExportHtml -ExportJson -LaunchHtml -Verbose
   ```

4. **Run with verbose logging and export a JSON report:**
   ```powershell
   .\Invoke-WindowsSecurityAudit.ps1 -ExportJson -OutputPath ".\reports\host_audit.json" -Verbose
   ```


##  Ethical & Legal Disclaimer

This tool is developed strictly for **educational purposes, authorized security auditing, and defensive posture hardening**. 

* Do not run this script on any system or network where you do not have explicit, written permission from the system owner.
* The author assumes no liability and is not responsible for any misuse or damage caused by this program. Always adhere to your organization's security policies and local laws.
