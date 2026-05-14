# PowerShell Encoded Command Execution

**MITRE ATT&CK Technique:** T1059.001 - Command and Scripting Interpreter: PowerShell
**Tactic:** Execution / Defense Evasion
**Severity:** High
**Data Source:** DeviceProcessEvents
**Required Connector:** Microsoft Defender for Endpoint
**Required License:** MDE Plan 1 or Plan 2
**Query Frequency:** Every 15 minutes
**Lookup Period:** Last 1 hour

---

## Description

Detects PowerShell processes launched with encoded command parameters. Attackers use Base64-encoded commands to obfuscate malicious payloads, bypass script-based detection, and avoid logging of the full command in some configurations.

The flags `-EncodedCommand`, `-enc`, and `-ec` are all valid PowerShell parameters that accept a Base64-encoded command string. Legitimate use cases exist but are uncommon in end-user environments. In server and developer environments, known automation scripts should be baselined and excluded.

---

## Detection Query

```kql
DeviceProcessEvents
| where TimeGenerated >= ago(1h)
| where FileName has_any ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-EncodedCommand", "-enc ", "-ec ", "-EnC", "-eNc")
| project 
    TimeGenerated, 
    DeviceName, 
    AccountName, 
    ProcessCommandLine, 
    InitiatingProcessFileName, 
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName,
    ReportId
| extend EncodedPayload = extract(@"(?i)-(?:EncodedCommand|enc|ec)\s+([A-Za-z0-9+/=]{20,})", 1, ProcessCommandLine)
| sort by TimeGenerated desc
```

---

## Alert Logic Settings

| Setting | Recommended Value |
|---|---|
| Query frequency | Every 15 minutes |
| Lookup period | Last 1 hour |
| Alert threshold | Greater than 0 results |
| Event grouping | Group all events into a single alert |

---

## Tuning Guidance

**Parent process exclusions:** Review the `InitiatingProcessFileName` field for known legitimate callers. Common legitimate parent processes that use encoded commands include deployment tools (SCCM, Intune), backup agents, and monitoring software. Baseline these and add exclusions:
```kql
| where InitiatingProcessFileName !in ("ccmexec.exe", "msiexec.exe")
```

**Account exclusions:** Service accounts used by automation platforms that legitimately use encoded commands should be excluded by account name:
```kql
| where AccountName !startswith "svc-"
```

Adjust prefix to match your service account naming convention.

**Decode the payload:** The `EncodedPayload` field extracts the Base64 string. To decode it during investigation, use PowerShell:
```powershell
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("PASTE_PAYLOAD_HERE"))
```

---

## False Positives

- Software deployment tools (SCCM, Intune, PDQ) that use encoded commands for package execution
- Backup and monitoring agents with PowerShell-based data collection
- Developer workstations running automated build pipelines
- Some antivirus and EDR products that use encoded PowerShell for remediation

---

## Response Actions

1. Decode the Base64 payload and review the actual command being executed
2. Identify the parent process and determine whether it is a known legitimate caller
3. Check whether the execution is consistent with the user's or device's normal behavior
4. If the decoded command contains download cradles, persistence mechanisms, or credential access functions: treat as active compromise and initiate isolation
5. Review other process events on the same device in the same time window for related activity
