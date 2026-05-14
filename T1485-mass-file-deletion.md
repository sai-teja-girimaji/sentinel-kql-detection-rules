# Mass File Deletion Detection

**MITRE ATT&CK Technique:** T1485 - Data Destruction / T1486 - Data Encrypted for Impact
**Tactic:** Impact
**Severity:** Critical
**Data Source:** DeviceFileEvents
**Required Connector:** Microsoft Defender for Endpoint
**Required License:** MDE Plan 1 or Plan 2
**Query Frequency:** Every 5 minutes
**Lookup Period:** Last 1 hour

---

## Description

Detects a high volume of file deletions on a single device within a short time window, which is consistent with ransomware pre-encryption cleanup, destructive malware, or an attacker performing data destruction before exfiltration. The rule uses a 5-minute tumbling window to catch rapid deletion bursts.

---

## Detection Query

```kql
let DeletionThreshold = 100;
DeviceFileEvents
| where TimeGenerated >= ago(1h)
| where ActionType == "FileDeleted"
| extend FileExtension = tostring(extract(@"\.([^.]+)$", 1, FileName))
| summarize 
    DeletionCount = count(),
    FileExtensions = make_set(FileExtension),
    FolderPaths = make_set(FolderPath),
    FirstDeletion = min(TimeGenerated),
    LastDeletion = max(TimeGenerated)
    by DeviceName, AccountName, bin(TimeGenerated, 5m)
| where DeletionCount >= DeletionThreshold
| extend DurationSeconds = datetime_diff('second', LastDeletion, FirstDeletion)
| project 
    FirstDeletion, 
    DeviceName, 
    AccountName, 
    DeletionCount, 
    DurationSeconds, 
    FileExtensions, 
    FolderPaths
| sort by DeletionCount desc
```

---

## Tuning Guidance

**DeletionThreshold:** Default is 100 deletions per 5 minutes. In environments with active cleanup scripts or log rotation processes, review the normal deletion rate per device and set the threshold above the highest legitimate baseline. Starting at 100 is appropriate for most end-user workstations.

**File extension enrichment:** Add a filter to prioritize alerts involving document and data file extensions over temp file or log file deletions:
```kql
| where FileExtensions has_any ("docx", "xlsx", "pdf", "pptx", "sql", "mdb", "bak")
```

---

## False Positives

- Log rotation scripts that delete large numbers of log files in bulk
- Cleanup scripts triggered by software updates or patch management
- Antivirus remediation that deletes multiple infected files simultaneously
- Backup software that removes old backup files during rotation

---

## Response Actions

1. Immediately isolate the device if the deletion pattern is consistent with ransomware (documents, user data folders)
2. Check whether any ransomware note files were created in the same time window
3. Review running processes on the device at the time of deletions
4. Assess whether files are recoverable from VSS snapshots or backup
5. Investigate the account performing the deletions for compromise indicators
