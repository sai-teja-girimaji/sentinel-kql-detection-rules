# Brute Force Sign-in Detection

**MITRE ATT&CK Technique:** T1110 - Brute Force
**Tactic:** Credential Access
**Severity:** High
**Data Source:** SigninLogs
**Required Connector:** Azure Active Directory
**Required License:** Azure AD P1 or P2
**Query Frequency:** Every 30 minutes
**Lookup Period:** Last 1 hour

---

## Description

Detects a high volume of failed sign-in attempts against a single user account within a defined time window. This pattern is consistent with password spray, credential stuffing, and traditional brute force attacks targeting Azure AD accounts.

This rule looks at failed authentication attempts (ResultType not equal to 0) and alerts when the failure count for a single user exceeds the defined threshold within the lookback period.

---

## Detection Query

```kql
let FailureThreshold = 10;
SigninLogs
| where TimeGenerated >= ago(1h)
| where ResultType != "0"
| summarize 
    FailureCount = count(),
    IPAddresses = make_set(IPAddress),
    Locations = make_set(Location),
    AppTargets = make_set(AppDisplayName),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by UserPrincipalName
| where FailureCount >= FailureThreshold
| extend DurationMinutes = datetime_diff('minute', LastAttempt, FirstAttempt)
| project 
    UserPrincipalName, 
    FailureCount, 
    DurationMinutes, 
    IPAddresses, 
    Locations, 
    AppTargets, 
    FirstAttempt, 
    LastAttempt
| sort by FailureCount desc
```

---

## Alert Logic Settings

| Setting | Recommended Value |
|---|---|
| Query frequency | Every 30 minutes |
| Lookup period | Last 1 hour |
| Alert threshold | Greater than 0 results |
| Event grouping | Group all events into a single alert |

---

## Tuning Guidance

**FailureThreshold:** Default is 10. In high-volume environments with shared accounts or service accounts that frequently retry authentication, increase to 20 or 30 to reduce false positives. In environments with strict lockout policies, reduce to 5.

**Time window:** The 1-hour lookback is appropriate for most environments. For slower brute force attacks designed to stay under lockout thresholds, consider extending to 4 hours with a proportionally higher threshold.

**Exclusions:** Add a filter to exclude known service accounts or automation accounts that may generate legitimate authentication failures:
```kql
| where UserPrincipalName !in ("serviceaccount@domain.com", "automation@domain.com")
```

---

## False Positives

- Users who forget their password and repeatedly attempt to sign in
- Service accounts with expired or incorrect credentials configured in applications
- Shared accounts used across multiple automated processes
- Legacy authentication flows that do not handle errors gracefully

---

## Response Actions

1. Confirm whether a successful sign-in followed the failed attempts (join with ResultType == "0")
2. Check the originating IP addresses against threat intelligence
3. Verify whether the account is under an active lockout policy
4. Contact the user to confirm whether the attempts were legitimate
5. If malicious: reset the account password, revoke active sessions, and review the account's recent activity
