# MITRE ATT&CK Coverage Map

> Quick reference for detection coverage in this repository

---

## Coverage by Tactic

| Tactic | Technique | Rule | Severity |
|---|---|---|---|
| Initial Access | T1078 - Valid Accounts (Impossible Travel) | [T1078-impossible-travel.md](./T1078-impossible-travel.md) | High |
| Execution | T1059.001 - PowerShell Encoded Command | [T1059-powershell-encoded-command.md](./T1059-powershell-encoded-command.md) | High |
| Persistence | T1136.001 - Create Local Account | [T1136-new-local-admin-creation.md](./T1136-new-local-admin-creation.md) | High |
| Privilege Escalation | T1098.003 - Additional Cloud Roles | [T1098-privileged-role-assignment.md](./T1098-privileged-role-assignment.md) | Critical |
| Credential Access | T1110 - Brute Force | [T1110-brute-force-signin.md](./T1110-brute-force-signin.md) | High |
| Credential Access | T1621 - MFA Request Generation | [T1621-mfa-fatigue.md](./T1621-mfa-fatigue.md) | High |
| Lateral Movement | T1570 - Lateral Tool Transfer (PsExec) | [T1570-psexec-lateral-movement.md](./T1570-psexec-lateral-movement.md) | High |
| Command and Control | T1071.004 - DNS Tunneling | [T1071-dns-tunneling.md](./T1071-dns-tunneling.md) | Medium |
| Impact | T1485 - Data Destruction | [T1485-mass-file-deletion.md](./T1485-mass-file-deletion.md) | Critical |
| Impact | T1578.003 - Delete Cloud Instance | [T1578-azure-mass-resource-deletion.md](./T1578-azure-mass-resource-deletion.md) | Critical |

---

## Coverage Gaps (Planned)

| Tactic | Technique | Status |
|---|---|---|
| Defense Evasion | T1562.001 - Disable Security Tools | Planned |
| Exfiltration | T1048 - Exfiltration Over Alternative Protocol | Planned |
| Reconnaissance | T1595 - Active Scanning | Planned |
| Collection | T1530 - Data from Cloud Storage | Planned |
| Persistence | T1078.004 - Cloud Account | Planned |

---

## ATT&CK Navigator Layer

An ATT&CK Navigator layer file covering the above techniques is planned for the next release. This will allow you to visualize coverage directly on the ATT&CK matrix.
