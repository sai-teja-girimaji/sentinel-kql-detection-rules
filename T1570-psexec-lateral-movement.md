# PsExec Lateral Movement Detection

**MITRE ATT&CK Technique:** T1570 - Lateral Tool Transfer, T1021.002 - SMB/Windows Admin Shares
**Tactic:** Lateral Movement
**Severity:** High
**Data Source:** SecurityEvent
**Required Connector:** Windows Security Events (via AMA or MMA)
**Required Audit Policy:** Audit Security System Extension must be enabled
**Query Frequency:** Every 15 minutes
**Lookup Period:** Last 1 hour

---

## Description

Detects the installation of the PsExec service (PSEXESVC) on a Windows host, which occurs when PsExec is used to execute commands or programs on a remote system. PsExec is a legitimate Sysinternals tool that is frequently abused by attackers for lateral movement because it does not require installing a separate agent and uses SMB for transport.

This rule monitors Security Event ID 4697, which is generated when a new service is installed in the system. The PSEXESVC service name is a reliable indicator of PsExec usage.

---

## Detection Query

```kql
SecurityEvent
| where TimeGenerated >= ago(1h)
| where EventID == 4697
| where ServiceName has_any ("PSEXESVC", "psexesvc")
    or ServiceFileName has_any ("psexesvc", "PSEXESVC")
| project 
    TimeGenerated, 
    Computer, 
    ServiceName, 
    ServiceFileName, 
    SubjectUserName, 
    SubjectDomainName,
    SubjectLogonId
| extend AlertDetail = strcat(
    "PsExec service installed on ", Computer, 
    " by ", SubjectDomainName, "\\", SubjectUserName
)
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

**Legitimate PsExec use:** Some IT operations teams use PsExec for legitimate remote administration. If PsExec is approved in your environment, add exclusions for known admin accounts and source systems:
```kql
| where SubjectUserName !in ("admin-account", "helpdesk-account")
| where Computer !in ("known-admin-jump-host")
```

**Correlation with logon events:** Correlate this alert with Event ID 4624 (successful logon) on the same Computer around the same time to identify the source of the lateral movement:
```kql
let PsExecEvents = SecurityEvent
    | where EventID == 4697
    | where ServiceName has "PSEXESVC"
    | project PsExecTime = TimeGenerated, Computer, SubjectUserName;
let NetworkLogons = SecurityEvent
    | where EventID == 4624
    | where LogonType == 3
    | project LogonTime = TimeGenerated, Computer, AccountName, IpAddress;
PsExecEvents
| join kind=inner NetworkLogons on Computer
| where LogonTime between ((PsExecTime - 2m) .. (PsExecTime + 2m))
| project PsExecTime, Computer, SubjectUserName, AccountName, IpAddress
```

---

## False Positives

- IT administrators using PsExec for legitimate remote administration tasks
- Software deployment processes that use PsExec for remote installation
- Vulnerability scanners and asset management tools that use PsExec for discovery

---

## Response Actions

1. Identify the source host that initiated the PsExec connection by correlating with network logon events (Event ID 4624, LogonType 3)
2. Determine whether the user account performing the action is authorized to use PsExec
3. Review commands executed via PsExec by checking subsequent process creation events (Event ID 4688) on the target host
4. If unauthorized: isolate both the source and target hosts and initiate a lateral movement investigation
5. Check for PsExec events on other hosts in the same time window to identify the full scope of lateral movement
