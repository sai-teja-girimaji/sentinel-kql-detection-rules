# New Local Account Created and Added to Administrators Group

**MITRE ATT&CK Technique:** T1136.001 - Create Account: Local Account
**Tactic:** Persistence
**Severity:** High
**Data Source:** SecurityEvent
**Required Connector:** Windows Security Events (via AMA or MMA)
**Required Audit Policy:** Audit User Account Management must be enabled
**Query Frequency:** Every 15 minutes
**Lookup Period:** Last 1 hour

---

## Description

Detects the creation of a new local user account followed by that account being added to the local Administrators group within a 10-minute window on the same host. This compound event pattern is a strong indicator of persistence being established by an attacker who has achieved local administrator access and is creating a backdoor account.

This rule correlates Event ID 4720 (user account created) with Event ID 4732 (member added to security-enabled local group) on the same host within a defined time window.

---

## Detection Query

```kql
let LookbackWindow = 1h;
let CorrelationWindow = 10m;
let NewAccounts = SecurityEvent
    | where TimeGenerated >= ago(LookbackWindow)
    | where EventID == 4720
    | project 
        CreatedTime = TimeGenerated, 
        NewAccount = TargetUserName,
        CreatedBy = SubjectUserName,
        CreatedByDomain = SubjectDomainName,
        Computer;
let AdminGroupAdditions = SecurityEvent
    | where TimeGenerated >= ago(LookbackWindow)
    | where EventID == 4732
    | where TargetUserName =~ "Administrators"
    | project 
        AddedTime = TimeGenerated, 
        Computer,
        AddedMember = MemberName,
        AddedBy = SubjectUserName;
NewAccounts
| join kind=inner (AdminGroupAdditions) on Computer
| where AddedTime between (CreatedTime .. (CreatedTime + CorrelationWindow))
| where AddedMember contains NewAccount
| project 
    CreatedTime, 
    NewAccount, 
    CreatedBy, 
    CreatedByDomain,
    Computer, 
    AddedTime, 
    AddedBy
| sort by CreatedTime desc
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

**CorrelationWindow:** Default is 10 minutes. This is the window between account creation and group addition. Most attackers perform these steps in sequence, so 10 minutes is generous. You can reduce to 5 minutes to tighten the correlation.

**MemberName format:** The `MemberName` field in Event ID 4732 may be formatted as `DOMAIN\username` or `%{SID}`. The `contains` operator handles the domain prefix case. If you see misses, add a variant using the SID extracted from `MemberSid`.

**Exclusions for provisioning:** If your environment uses automated provisioning that creates accounts and adds them to groups, exclude the provisioning service account:
```kql
| where CreatedBy !in ("provisioning-svc", "automation-account")
```

---

## False Positives

- Automated user provisioning systems that create local accounts and configure group membership in sequence
- IT administrators manually creating local service accounts
- Software installations that create local accounts with elevated privileges

---

## Response Actions

1. Identify whether the account creation was authorized by checking with the IT team or reviewing change management records
2. Determine the source of the action by reviewing the `CreatedBy` account's recent activity
3. Review what the newly created account has done since creation by querying logon events for the new account name
4. If unauthorized: disable the new account immediately, remove it from the Administrators group, and review the host for additional persistence mechanisms
5. Investigate how the attacker obtained local administrator rights to perform this action
