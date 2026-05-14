# Azure Mass Resource Deletion

**MITRE ATT&CK Technique:** T1578.003 - Modify Cloud Compute Infrastructure: Delete Cloud Instance
**Tactic:** Impact / Defense Evasion
**Severity:** Critical
**Data Source:** AzureActivity
**Required Connector:** Azure Activity
**Required License:** None (free connector)
**Query Frequency:** Every 30 minutes
**Lookup Period:** Last 1 hour

---

## Description

Detects a high volume of successful Azure resource deletion operations performed by a single identity within a 30-minute window. This pattern is consistent with destructive attacks targeting cloud infrastructure, an attacker covering their tracks by deleting evidence, or a compromised privileged account being used to cause service disruption.

AzureActivity logs all control plane operations across an Azure subscription. Unlike data plane events, resource deletions are always logged regardless of diagnostic settings.

---

## Detection Query

```kql
let DeletionThreshold = 10;
AzureActivity
| where TimeGenerated >= ago(1h)
| where OperationNameValue has "delete"
| where ActivityStatusValue =~ "Success"
| where isnotempty(Caller)
| summarize 
    DeletionCount = count(),
    ResourceTypes = make_set(ResourceProviderValue),
    ResourceGroups = make_set(ResourceGroup),
    Operations = make_set(OperationNameValue),
    FirstDeletion = min(TimeGenerated),
    LastDeletion = max(TimeGenerated)
    by Caller, bin(TimeGenerated, 30m)
| where DeletionCount >= DeletionThreshold
| extend DurationMinutes = datetime_diff('minute', LastDeletion, FirstDeletion)
| project 
    FirstDeletion, 
    Caller, 
    DeletionCount, 
    DurationMinutes,
    ResourceTypes, 
    ResourceGroups, 
    Operations,
    LastDeletion
| sort by DeletionCount desc
```

---

## Tuning Guidance

**DeletionThreshold:** Default is 10 deletions per 30 minutes. Adjust based on your environment. Environments that regularly run infrastructure-as-code pipelines (Terraform destroy, ARM deployments) may see legitimate bulk deletions from service principals. Identify those service principals and exclude them, then tighten the threshold for human callers.

**Service principal exclusions:** Exclude known infrastructure automation service principals:
```kql
| where Caller !in ("terraform-sp@domain.com", "pipeline-sp@domain.com")
```

**Sensitive resource type focus:** Narrow to high-impact resource types:
```kql
| where ResourceTypes has_any ("microsoft.compute", "microsoft.storage", "microsoft.keyvault", "microsoft.network")
```

---

## False Positives

- Terraform or ARM pipeline service principals running destroy operations as part of a deployment cycle
- Scheduled cleanup jobs that remove expired or unused resources
- Developers deleting their own test resource groups
- Infrastructure decommissioning operations

---

## Response Actions

1. Identify the Caller identity and determine whether they are authorized to perform bulk deletions
2. Check whether the deletions are associated with a known change request or deployment pipeline run
3. Review the deleted resource types: deletion of key vaults, virtual machines, and storage accounts simultaneously is a critical signal
4. If unauthorized: revoke the caller's Azure RBAC assignments immediately and initiate an incident
5. Assess whether deleted resources can be restored from Azure Backup or soft-delete features
