# MFA Fatigue Attack Detection

**MITRE ATT&CK Technique:** T1621 - Multi-Factor Authentication Request Generation
**Tactic:** Credential Access
**Severity:** High
**Data Source:** SigninLogs
**Required Connector:** Azure Active Directory
**Required License:** Azure AD P1 or P2
**Query Frequency:** Every 15 minutes
**Lookup Period:** Last 1 hour

---

## Description

Detects repeated MFA authentication failures for a single user within a short time window. MFA fatigue attacks work by bombarding the target user with push notification requests, betting that the user will eventually approve one to stop the notifications.

This rule focuses on authentication failures specifically related to MFA challenges, including push notification denials and strong authentication failures. It is distinct from general brute force in that the attacker already has valid credentials and is attempting to bypass the MFA layer.

---

## Detection Query

```kql
let MFAFailureThreshold = 5;
SigninLogs
| where TimeGenerated >= ago(1h)
| where ResultType in ("500121", "50074", "50076")
    or ResultDescription has_any ("MFA", "multi-factor authentication", "strong authentication")
| summarize 
    FailureCount = count(),
    ResultTypes = make_set(ResultType),
    IPAddresses = make_set(IPAddress),
    Locations = make_set(Location),
    AppTargets = make_set(AppDisplayName),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by UserPrincipalName
| where FailureCount >= MFAFailureThreshold
| extend DurationMinutes = datetime_diff('minute', LastAttempt, FirstAttempt)
| project 
    UserPrincipalName, 
    FailureCount, 
    DurationMinutes, 
    ResultTypes, 
    IPAddresses, 
    Locations, 
    AppTargets,
    FirstAttempt, 
    LastAttempt
| sort by FailureCount desc
```

---

## ResultType Reference

| ResultType | Meaning |
|---|---|
| 500121 | Authentication failed during strong authentication request |
| 50074 | Strong authentication is required |
| 50076 | User has to perform multi-factor authentication |

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

**MFAFailureThreshold:** Default is 5. MFA fatigue attacks typically involve rapid repeated pushes, so 5 failures in 1 hour is a strong signal. Lowering to 3 increases sensitivity but may increase false positives from users who deny accidental push prompts.

**Time window:** The 1-hour lookback is appropriate. Attackers who know their target is monitoring may slow down the cadence. Consider adding a longer-window variant at 24 hours with a threshold of 10 to catch slow-burn attempts.

**Correlation with successful sign-in:** Enrich this alert by checking whether a successful sign-in followed the MFA failures. If yes, the account is likely compromised:
```kql
| join kind=leftouter (
    SigninLogs
    | where ResultType == "0"
    | project UserPrincipalName, SuccessTime = TimeGenerated, SuccessIP = IPAddress
) on UserPrincipalName
| where SuccessTime > FirstAttempt
```

---

## False Positives

- Users who repeatedly deny push notifications due to confusion or accidental dismissal
- Conditional Access policies that require re-authentication frequently
- Users switching between devices and repeatedly triggering MFA prompts

---

## Response Actions

1. Immediately check whether any MFA approval followed the failures
2. Contact the user directly and confirm they did not approve any recent MFA prompts
3. If the user received unexpected MFA prompts: the attacker has the user's password. Initiate password reset and session revocation immediately.
4. Review the originating IP for the failed attempts against threat intelligence
5. Enforce number matching and additional context on MFA push notifications to prevent approval of unexpected requests
