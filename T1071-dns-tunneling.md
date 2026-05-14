# DNS Tunneling Detection

**MITRE ATT&CK Technique:** T1071.004 - Application Layer Protocol: DNS
**Tactic:** Command and Control / Exfiltration
**Severity:** Medium
**Data Source:** DnsEvents
**Required Connector:** DNS Analytics (Windows DNS Server solution)
**Required Configuration:** DNS Debug Logging must be enabled on Windows DNS servers
**Query Frequency:** Every 1 hour
**Lookup Period:** Last 1 hour

---

## Description

Detects potential DNS tunneling by identifying hosts that generate an unusually high volume of DNS queries or queries with abnormally long names within a short time window. DNS tunneling encodes data inside DNS query and response payloads, using a controlled domain as a relay. It is used for both command and control communication and data exfiltration because DNS traffic is rarely blocked at the perimeter.

Two detection signals are used in combination:

1. **High query volume:** A host generating significantly more DNS queries than baseline indicates automated beaconing or data transfer activity.
2. **Long query names:** DNS tunneling tools encode data in subdomain labels, resulting in queries significantly longer than legitimate domain names.

---

## Detection Query

```kql
let LongQueryThreshold = 50;
let HighVolumeThreshold = 100;
DnsEvents
| where TimeGenerated >= ago(1h)
| where SubType == "LookupQuery"
| where isnotempty(Name)
| extend QueryLength = strlen(Name)
| extend SubdomainDepth = array_length(split(Name, "."))
| summarize 
    QueryCount = count(),
    MaxQueryLength = max(QueryLength),
    AvgQueryLength = avg(QueryLength),
    MaxSubdomainDepth = max(SubdomainDepth),
    SampleQueries = make_set(Name, 5)
    by Computer, ClientIP, bin(TimeGenerated, 10m)
| where QueryCount >= HighVolumeThreshold 
    or MaxQueryLength >= LongQueryThreshold
| project 
    TimeGenerated, 
    Computer, 
    ClientIP, 
    QueryCount, 
    MaxQueryLength, 
    AvgQueryLength, 
    MaxSubdomainDepth, 
    SampleQueries
| sort by QueryCount desc
```

---

## Alert Logic Settings

| Setting | Recommended Value |
|---|---|
| Query frequency | Every 1 hour |
| Lookup period | Last 1 hour |
| Alert threshold | Greater than 0 results |
| Event grouping | Group all events into a single alert |

---

## Tuning Guidance

**LongQueryThreshold:** Default is 50 characters. Legitimate domain names are typically under 30 characters. Common CDN and analytics providers may use longer subdomains. Baseline your environment and set this above the 99th percentile of your legitimate query lengths.

**HighVolumeThreshold:** Default is 100 queries per 10 minutes. Adjust based on your DNS volume baseline. Hosts running software update checks or telemetry agents may legitimately generate high query volumes. Baseline those hosts and add exclusions.

**Known CDN exclusions:** Some CDN providers use long randomized subdomains for cache busting. Identify these patterns in your environment:
```kql
| where Name !endswith ".cloudfront.net"
| where Name !endswith ".akamaiedge.net"
```

**Entropy analysis (advanced):** DNS tunneling subdomain labels typically have high character entropy compared to human-readable domains. This can be added as an additional signal using custom functions.

---

## False Positives

- CDN providers that use long randomized subdomain labels
- Software update services that check in frequently with telemetry data
- Security tools that use DNS for certificate validation or threat intelligence lookups
- Some video conferencing and collaboration platforms with high DNS lookup frequency

---

## Response Actions

1. Review the sample queries in the `SampleQueries` field: tunneling queries typically look like random strings of characters as subdomains
2. Identify whether the destination domains are known DNS tunneling infrastructure (check against threat intelligence)
3. Capture a full packet trace from the affected host to confirm DNS payload sizes are abnormally large
4. If confirmed: isolate the host, terminate all outbound DNS connections, and initiate a compromise investigation
5. Review all data that may have been exfiltrated by estimating the data volume from the DNS query count and average payload size
