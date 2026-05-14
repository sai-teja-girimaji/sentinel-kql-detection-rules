# Privileged Role Assignment in Azure AD

**MITRE ATT&CK Technique:** T1098.003 - Account Manipulation: Additional Cloud Roles
**Tactic:** Privilege Escalation / Persistence
**Severity:** Critical
**Data Source:** AuditLogs
**Required Connector:** Azure Active Directory
**Required License:** Azure AD P1 or P2
**Query Frequency:** Every 15 minutes
**Lookup Period:** Last 1 hour

---

## Description

Detects when a user, service principal, or application is assigned to a highly privileged Azure AD role. Attackers who gain initial access to an Azure AD account use privileged role assignment to escalate their access and establish persistence that survives password resets on the original compromised account.

This rule monitors Azure AD Audit Logs for the "Add member to role" operation and filters on a defined list of high-impact roles.

---

## Detection Query

```kql
AuditLogs
| where TimeGenerated >= ago(1h)
| where OperationName =~ "Add member to role"
| where Result =~ "success"
| mv-expand TargetResources
| extend 
    EntityName = tostring(TargetResources.displayName),
    EntityType = tostring(TargetResources.type),
    ModifiedProperties = TargetResources.modifiedProperties
| mv-expand ModifiedProperties
| extend PropertyName = tostring(ModifiedProperties.displayName)
| where PropertyName == "Role.DisplayName"
| extend RoleName = tostring(parse_json(tostring(ModifiedProperties.newValue)))
| where RoleName has_any (
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "Hybrid Identity Administrator",
    "User Administrator",
    "Authentication Administrator"
)
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatedByApp = tostring(InitiatedBy.app.displayName)
| project 
    TimeGenerated, 
    EntityName, 
    EntityType, 
    RoleName, 
    InitiatedByUser, 
    InitiatedByApp,
    CorrelationId
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

**Role list:** The rule includes 10 high-impact roles. Review and adjust the list based on which roles are sensitive in your specific environment. Some organizations may also want to include: Intune Administrator, Teams Administrator, Billing Administrator.

**Approved assignment workflows:** If your organization uses Privileged Identity Management (PIM) for just-in-time role assignment, most role assignments will be legitimate activations. Consider filtering to only alert on permanent (non-PIM) assignments:
```kql
| where tostring(AdditionalDetails) !has "PIM"
```

---

## False Positives

- Authorized role assignments performed by identity administrators following an approved change request
- PIM-based just-in-time role activations
- Onboarding processes that assign roles to new administrators

---

## Response Actions

1. Verify whether the assignment was authorized through a formal change request or approval process
2. Confirm the identity of the user who performed the assignment (`InitiatedByUser`)
3. If a service principal or application performed the assignment, review that application's recent activity and permissions
4. If unauthorized: remove the role assignment immediately, review what the assigned entity did with the elevated privileges, and initiate a full account compromise investigation
5. Enable PIM for all privileged roles to require approval and time-limiting for role activations
