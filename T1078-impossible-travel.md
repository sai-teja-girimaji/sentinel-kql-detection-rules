# Impossible Travel Detection

**MITRE ATT&CK Technique:** T1078 - Valid Accounts
**Tactic:** Initial Access / Defense Evasion
**Severity:** High
**Data Source:** SigninLogs
**Required Connector:** Azure Active Directory
**Required License:** Azure AD P1 or P2
**Query Frequency:** Every 1 hour
**Lookup Period:** Last 24 hours

---

## Description

Detects successful sign-ins from two or more different countries within a 2-hour window for the same user account. This pattern indicates either compromised credentials being used from a foreign location, or a VPN or proxy being used to obscure the true sign-in location.

This rule does not attempt to calculate physical travel distance. It uses country-level geolocation from Azure AD sign-in logs to identify sign-ins that would require the user to be physically present in two countries within an implausibly short time window.

---

## Detection Query

```kql
SigninLogs
| where TimeGenerated >= ago(24h)
| where ResultType == "0"
| extend Country = tostring(LocationDetails.countryOrRegion)
| where isnotempty(Country)
| summarize 
    SignInCount = count(),
    Countries = make_set(Country),
    IPAddresses = make_set(IPAddress),
    Apps = make_set(AppDisplayName),
    FirstSignIn = min(TimeGenerated),
    LastSignIn = max(TimeGenerated)
    by UserPrincipalName, bin(TimeGenerated, 2h)
| extend CountryCount = array_length(Countries)
| where CountryCount >= 2
| extend TimespanMinutes = datetime_diff('minute', LastSignIn, FirstSignIn)
| project 
    UserPrincipalName, 
    Countries, 
    CountryCount, 
    IPAddresses, 
    Apps,
    FirstSignIn, 
    LastSignIn, 
    TimespanMinutes, 
    SignInCount
| sort by CountryCount desc
```

---

## Alert Logic Settings

| Setting | Recommended Value |
|---|---|
| Query frequency | Every 1 hour |
| Lookup period | Last 24 hours |
| Alert threshold | Greater than 0 results |
| Event grouping | Group all events into a single alert |

---

## Tuning Guidance

**Time window (bin):** The 2-hour bin is the primary control. Narrow to 1 hour for higher sensitivity. Widen to 4 hours only if your user population regularly uses VPNs that exit in different countries.

**Country exclusions for known VPN exits:** If your organization uses a split-tunnel VPN or a specific country as a VPN exit node, add an exclusion:
```kql
| where not (Countries has "Netherlands" and array_length(Countries) == 2 and Countries has "India")
```

Adjust to match your specific VPN exit countries.

**Trusted country pairs:** Exclude country pairs that are legitimate for your organization (e.g., US and Canada for organizations with offices in both):
```kql
| extend SortedCountries = array_sort_asc(Countries)
| where not (SortedCountries == dynamic(["Canada", "United States"]))
```

---

## False Positives

- Users with corporate VPNs that exit in different countries
- Shared or service accounts used by team members in different geographic locations
- Users who use privacy-focused browsers or VPN services for personal reasons
- Cloud-based automation accounts that route traffic through multiple regions

---

## Response Actions

1. Confirm the user's known location at the time of both sign-ins
2. Determine whether the user has a business reason to be in both countries
3. Check whether the sign-in IP addresses are associated with known VPN or proxy providers
4. If no legitimate explanation: revoke the user's active sessions, reset the password, and initiate an account compromise investigation
5. Review all activity performed by the account during and after the suspicious sign-in period
