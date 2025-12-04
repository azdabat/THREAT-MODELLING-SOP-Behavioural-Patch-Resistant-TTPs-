# Threat Modelling SOP (Behaviour–First, Patch-Agnostic)
Author: **Ala Dabat**  
Purpose: Build long-term hunting logic for advanced adversaries whose attacks **cannot be solved with patching** and **evade traditional engineering rules**.

---

# 1. Threat Modelling Methodology  
This SOP uses a repeatable, senior-level framework:

1. **Define the Adversary Class**  
   - Ransomware crews with human operators (Black Basta, BlackSuit, Medusa, Akira, LockBit successors)  
   - Cloud/identity abuse actors (Muddled Libra, Storm-xxxx families)  
   - Fileless / stego loader actors (XWorm, AgentTesla hybrids, modern loaders)  
   - Web-to-host pivot crews (GoAnywhere, SharePoint, Ivanti-style RCE chains)  
   *We ignore single CVEs unless they create meaningful host telemetry.*

2. **List All Attack Phases (MITRE)**  
   - Initial Access → Execution → Priv Esc → Persistence → Recon → Lateral → Collection → Exfiltration → Impact  
   *Map each step to host, cloud, and identity signals.*

3. **Model the Attack From the Hacker’s Perspective**  
   - What tools do they prefer?  
   - What do they avoid?  
   - How do they blend into legitimate admin activity?  
   - What gaps in monitoring do they exploit?  

4. **Extract the Behavioural Anchors**  
   Behaviour that remains even after:  
   - Patching  
   - IOCs rotated  
   - Infrastructure replaced  
   - Loaders rewritten  
   - Malware obfuscated  
   These anchors form the basis of **core hunts**.

5. **Produce the Detection Hypothesis**  
   “If an attacker performs X (behaviour), then Y (telemetry pattern) must appear.”

6. **Create a Hunting Flow**  
   - Required tables  
   - Required joins  
   - Required enrichments (OrgPrevalence, rare path, etc.)  
   - Indicators of malicious sequence (not artifacts)

7. **Build the Detection**  
   - Behaviour-first KQL  
   - Scoring or sequence-based  
   - HunterDirectives for triage  
   - MITRE mapping  
   - Pivot tables for analysts

---

# 2. Adversary Class #1 – HUMAN-OPERATED RANSOMWARE (BLACK BASTA CLASS)

## 2.1 Hacker’s View – Realistic Chain (2025)
### Phase 1 — Initial Access
- Phishing with HTML smuggling, ISO/STL containers  
- No malware files — JS/VBS + LOLBins

### Phase 2 — Establish Foothold  
- Inject into explorer.exe  
- Steal browser tokens  
- Harvest RDP creds  
- Enumerate AD quietly during 9–5 hours

### Phase 3 — Privilege Escalation  
- Abuse misconfigured service accounts  
- Kerberoast  
- Token impersonation  
- PrintSpoofer/LPE

### Phase 4 — Lateral Movement  
- PsExec, AnyDesk, ScreenConnect  
- RDP auditing bypass  
- WMI batch spreads  
- Shadow copy deletions

### Phase 5 — Impact  
- Mass encryption  
- Backup deletion  
- Domain-wide scheduled tasks

## 2.2 MITRE Mapping (High Fidelity)
| Phase | Technique | Detail |
|-------|-----------|--------|
| Init | T1566.001 | HTML + JS loaders |
| Exec | T1059 | PowerShell/VBS |
| PrivEsc | T1068 | Token manipulation |
| Cred Access | T1003.* | LSASS/NTDS |
| Lateral | T1021.002 | SMB admin shares |
| Impact | T1486 | Encryption ops |

## 2.3 Behavioural Anchors (Always Present)
- Low-priv user → high-priv → PsExec within 4 hours  
- LSASS access + VSS deletion within same hour  
- RMM tools installed where previously unseen  
- Sudden multi-host share enumeration

## 2.4 Detection Hypotheses
- “No admin should install AnyDesk during business hours.”  
- “Legitimate admins do not enumerate DC shares immediately after MFA reset.”  
- “LSASS access + shadow deletion = hostile.”

---

# 3. Adversary Class #2 – IDENTITY TAKEOVER (MUDDLED LIBRA STYLE)

## 3.1 Hacker’s View – Real Attack (2025)
- Use voice phishing or Teams phishing  
- Trick helpdesk into MFA reset  
- Log in from residential IP with stolen session token  
- Enumerate O365 and Azure apps  
- Backdoor with malicious OAuth app  
- Modify inbox rules  
- Move into on-prem via hybrid identity trust

## 3.2 MITRE Mapping
| Phase | Technique |
|------|-----------|
| Initial Access | T1566.004 (Teams phishing) |
| Persistence | T1098.003 OAuth backdoor |
| Credential Access | T1556 MFA reset abuse |
| Lateral Movement | T1134 Access token abuse |

## 3.3 Behavioural Anchors
- MFA reset followed by successful login in <20 minutes  
- A newly created OAuth app granting:  
  - `Mail.ReadWrite`, `Directory.ReadWrite.All`  
- App consent from non-admin user (impossible in legit scenario)

## 3.4 Detection Hypothesis
“If a user’s MFA is reset AND login happens from a new device AND OAuth app is created → malicious.”

---

# 4. Adversary Class #3 – STEGO LOADERS / IMAGE-BASED STAGERS

## 4.1 Hacker’s View
- Payload embedded in PNG/JPEG metadata  
- Delivered via HTML smuggling (Word/Outlook bypass)  
- Extracted in-memory by JS/.NET loader  
- Payload executed via PowerShell or rundll32  
- C2 via WebSocket → indistinguishable from HTTPS

## 4.2 MITRE Mapping
| Phase | Technique |
|-------|----------|
| Initial Access | T1566 + HTML smuggling |
| Defense Evasion | T1027 (obfuscated data in image) |
| Exec | T1218 (mshta/rundll32) |
| C2 | T1071.001 |

## 4.3 Behavioural Anchors
- Image file → scripting engine → LOLBin → network-active process  
- .NET process reading image files from Downloads/Temp  
- WebSocket traffic shortly after image opened

## 4.4 Detection Hypothesis
“If Office or browser spawns PowerShell within 5 minutes of image creation = suspicious.”

---

# 5. Adversary Class #4 – WEB-TO-HOST PIVOTS (GOANYWHERE / SHAREPOINT / API RCEs)

## 5.1 Hacker’s View
- Exploit web app → gain service account  
- Drop webshell or run commands in-memory  
- Use app identity to access SQL/file shares  
- Move laterally to adjacent hosts  
- Exfiltrate archives disguised as backups

## 5.2 MITRE Mapping
| Phase | Technique |
|-------|----------|
| Initial Access | T1190 Exploit public-facing app |
| Exec | T1059.x |
| Persistence | T1505 (webshells) |
| Recon | T1087 |
| Exfil | T1041 |

## 5.3 Behavioural Anchors
- Web process spawning PowerShell/cmd  
- Sudden new .aspx or .ps1 files under web directories  
- Unusual outbound connections from service accounts

## 5.4 Detection Hypothesis
“If a web worker process spawns a shell → treat as compromise.”

---

# 6. Core Behavioural Patterns Across All Attackers
These are the universal, **patch-resistant** signals:

| Behaviour Pattern | Meaning |
|-------------------|---------|
| LOLBin chain (wscript → mshta → PowerShell) | Loader activity |
| Service account spawning cmd.exe | RCE / pivot |
| Admin tool installed unexpectedly | Human-operated attack |
| MFA reset + login + OAuth app | Identity takeover |
| Shadow copy deletion + LSASS access | Ransomware prep |
| Office → image → PowerShell | Steganographic loader |
| Web worker → shell → network scan | Post-RCE pivot |

These patterns form your **core hunts**.

---

# 7. Base MITRE Table for All 4 Adversary Classes

| Adversary | Initial Access | Exec | PrivEsc | Persistence | Recon | Lateral | Exfil | Impact |
|-----------|----------------|------|---------|-------------|--------|---------|--------|--------|
| Black Basta | T1566 | T1059 | T1068 | T1053 | T1087 | T1021 | T1041 | T1486 |
| Identity Attackers | T1566.004 | T1059 | T1556 | T1098.003 | T1087 | T1134 | T1041 | – |
| Stego Loaders | T1566 | T1059/T1218 | – | – | – | – | T1071 | – |
| Web-to-Host RCE | T1190 | T1059 | – | T1505 | T1087 | T1021 | T1041 | T1486 |

---

# 8. Pivot Table — What an Analyst Should Check

| Signal | Table | Description |
|--------|--------|-------------|
| LSASS access | DeviceProcessEvents | Classic credential theft |
| RMM deployment | DeviceRegistryEvents + DeviceProcessEvents | Persistence vector |
| New OAuth app | AuditLogs | Identity abuse |
| MFA reset | SigninLogs + AuditLogs | Social engineering success |
| Image → LOLBin | DeviceFileEvents + DeviceProcessEvents | Loader chain |
| Webshell | DeviceFileEvents + DeviceProcessEvents | RCE pivot |
| Shadow copy deletion | DeviceProcessEvents | Ransomware staging |

---

# 9. Summary – How to Use This SOP  
**complete attacker-first threat model** for a few major behavioural threat categories in 2025:

- Human-operated ransomware  
- Identity takeover  
- Stego/image loaders  
- Web-to-host RCE pivots  

Each includes:

- Full kill chain  
- Hacker tradecraft  
- MITRE mapping  
- Behavioural anchors  
- Detection hypotheses  
- Pivot tables for hunts  

see: **core hunt pack** and **advanced scoring-based engine**.
