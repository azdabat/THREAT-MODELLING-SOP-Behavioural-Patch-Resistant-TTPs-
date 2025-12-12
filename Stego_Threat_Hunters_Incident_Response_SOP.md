# Wide-Scope Threat Hunting Playbook  
## Steganography-Based Loaders & HTML Smuggling Chains  
**Author:** Ala Dabat  
**Version:** 2025-12  
**Classification:** Threat Hunting (Wide-Scope / Analyst-Directed)  
**Platform:** Microsoft Sentinel / MDE  
**Purpose:**  
This playbook provides a wide-scope methodology for hunting *image-based payload loaders*, *HTML smuggling chains*, and *browser/Office-run stego loaders*.  
The scope is intentionally broad enough to detect *advanced operators who deliberately evade folder-, parent-, and process-based constraints* that production rules rely on for low-noise operation.

This document is aligned with MITRE ATT&CK, IR frameworks, and SOC SOP patterns, and is intended for use by threat hunters performing deep-dive behavioural hunts in Sentinel.

---

# 1. Threat Model Overview

Modern steganography-based loaders increasingly use:
- User-facing lures (email, office docs, HTML + JS)
- Script/LOLBin interpreters (PowerShell, mshta, rundll32, wscript)
- Image file reads with embedded instructions or shellcode
- Short-delayed outbound HTTPS communications
- Memory-only payload execution

This playbook detects these chains through **sequence-based hunting**, **behavioural correlation**, and **org-rarity analysis**, rather than simple matching on predefined folders or parent processes.

### Key Attack Classes Covered
1. HTML Smuggling delivering JS/HTA → mshta → image decode → HTTPS C2  
2. Office/Browser → PowerShell → PNG/JPEG decode → loader execution  
3. Custom droppers avoiding Downloads/Temp (Pictures, Desktop, AppData, bespoke folders)  
4. Sideloaded EXEs spawning script hosts reading image payloads  
5. Image-based payloads used by commodity loaders and RAT stagers  
6. Stego-based configurations (Lumma, XWorm, AgentTesla variants)  
7. Uncommon TLS C2 patterns (fresh domains, rare IPs, suspicious JA3/JA4)  

---

# 2. MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|--------|-----------|-------------|
| Initial Access | T1566.001 | Spearphishing Attachment (Office/PDF lures) |
| Initial Access | T1189 / T1190 | Browser Delivered Payloads / HTML Smuggling |
| Execution | T1059 | Script interpreters (PowerShell, JS, HTA, VBS) |
| Execution | T1218 | Signed binary proxy execution (rundll32, mshta, wscript) |
| Defense Evasion | T1027.003 | Steganography: malicious payloads hidden in images |
| Defense Evasion | T1564 | Obfuscated/hidden artifacts in user folders |
| Persistence | T1547 / T1053 | Scheduled tasks or DLL proxy loads (rare, secondary) |
| C2 | T1071.001 | HTTPS-based command and control |
| Discovery | T1083 | File discovery, initial staging of payloads |
| Credential Access | T1003.003 | Memory scraping in later stages (RATs) |

---

# 3. Core vs Wide-Scope Detection Philosophy

### Core Production Rule (Narrow)
- Requires UserFacingParents (Office/browsers)  
- Requires image reads from Downloads/Temp  
- Requires immediate HTTPS connection  
- Low volume, high confidence, deployable as a detection rule

### Wide-Scope Hunting Rule (This Playbook)
- **No restriction** on parent process  
- **No restriction** on folder paths  
- **No fixed assumption** about image location  
- **No dependency** on suspicious TLD/IP lists  
- Adds:
  - OrgSeen counters  
  - Sequence correlation  
  - Rare parent-child execution combinations  
  - Rare network destinations  
  - Graph-based pivots  
- Operates at analyst-level, not alert-level  
- Intended for deep hunts and purple-team simulations  

---

# 4. Detection Strategy  
The wide-scope strategy uses **behaviour-first** detection composed of:

1. **Process Chain Anchoring**  
   Identify suspicious script/LOLBin executions with minimal assumptions about the parent.  
   Focus: mshta, rundll32, wscript, cscript, powershell, pwsh.

2. **Image Access Behaviour**  
   Scripts reading image files in any location.  
   Distinguish UI-driven reads (Explorer/UI apps) from scripted reads.

3. **Network Activity Correlation**  
   Outbound traffic shortly after image reads (0–5 minutes).  
   Weight by rarity and TLS metadata.

4. **Temporal Sequence Correlation**  
   User interaction → Script host → Image access → Network communication.

5. **Org Rarity and Statistical Weighting**  
   Reduce noise by measuring how common the behaviour is across the enterprise.

6. **Graph-Based Hunting**  
   Understand process lineage beyond parent only (grandparent, sibling processes, lateral chains).

---

# 5. Wide-Scope KQL Playbooks

## 5.1 Identify Script/LOLBin Hosts (No Parent Restriction)

```kusto
let lookback = 7d;
let ScriptHosts = dynamic(["powershell.exe","pwsh.exe","mshta.exe","rundll32.exe","wscript.exe","cscript.exe"]);

DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in~ (ScriptHosts)
| project Timestamp, DeviceId, DeviceName, AccountName,
         ScriptHost = FileName,
         ScriptCommand = ProcessCommandLine,
         ParentImage = InitiatingProcessFileName,
         ParentCommand = InitiatingProcessCommandLine,
let lookback = 7d;
let ImageExt = dynamic([".png",".jpg",".jpeg",".bmp",".gif",".webp"]);

DeviceFileEvents
| where Timestamp >= ago(lookback)
| extend FileExt = tolower(strcat(".", split(FileName, ".")[-1]))
| where FileExt in~ (ImageExt)
| where InitiatingProcessFileName in~ (dynamic(["powershell.exe","pwsh.exe","mshta.exe","rundll32.exe","wscript.exe","cscript.exe"]))
| project ImageReadTime = Timestamp, DeviceId, InitiatingProcessId,
         ImageFile = FileName, ImageFolder = FolderPath
         ProcessId, InitiatingProcessId

```

# 5.2 Image Read Activity by These Processes (Any Folder)

```
let lookback = 7d;
let ImageExt = dynamic([".png",".jpg",".jpeg",".bmp",".gif",".webp"]);

DeviceFileEvents
| where Timestamp >= ago(lookback)
| extend FileExt = tolower(strcat(".", split(FileName, ".")[-1]))
| where FileExt in~ (ImageExt)
| where InitiatingProcessFileName in~ (dynamic(["powershell.exe","pwsh.exe","mshta.exe","rundll32.exe","wscript.exe","cscript.exe"]))
| project ImageReadTime = Timestamp, DeviceId, InitiatingProcessId,
         ImageFile = FileName, ImageFolder = FolderPath

```
# 5.3 Correlate Script Execution
~~~
let lookback = 7d;
let ScriptHosts = dynamic(["powershell.exe","pwsh.exe","mshta.exe","rundll32.exe","wscript.exe","cscript.exe"]);
let ImageExt = dynamic([".png",".jpg",".jpeg",".bmp",".gif",".webp"]);

let ScriptEvents =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in~ (ScriptHosts)
| project ScriptTime = Timestamp, DeviceId, ProcessId,
         ScriptFile = FileName, ScriptCommand = ProcessCommandLine,
         ParentImage = InitiatingProcessFileName;

let ImageReads =
DeviceFileEvents
| where Timestamp >= ago(lookback)
| extend FileExt = tolower(strcat(".", split(FileName, ".")[-1]))
| where FileExt in~ (ImageExt)
| project ImageReadTime = Timestamp, DeviceId, InitiatingProcessId,
         ImageFile = FileName, ImageFolder = FolderPath;

ScriptEvents
| join kind=inner (
    ImageReads
) on DeviceId, $left.ProcessId == $right.InitiatingProcessId
| where ImageReadTime between (ScriptTime .. ScriptTime + 5m)
 Image Read (No Folder Restriction)
~~~

# 5.4 Correlate Image Read → Outbound Network Communication

~~~
let lookback = 7d;
let NetEvents =
DeviceNetworkEvents
| where Timestamp >= ago(lookback)
| where RemotePort in (80,443)
| project NetTime = Timestamp, DeviceId, InitiatingProcessId,
         RemoteIP, RemoteUrl, RemotePort, RemoteIPType;

let ImageToNet =
ImageReads
| join kind=inner NetEvents on DeviceId, $left.InitiatingProcessId == $right.InitiatingProcessId
| where NetTime between (ImageReadTime .. ImageReadTime + 5m);
~~~

# 5.5 Org Rarity Enrichment (URL, IP, Parent, Folder)
~~~
let lookback = 30d;

let UrlFreq =
DeviceNetworkEvents
| summarize OrgSeenRemoteUrlCount = dcount(DeviceId) by RemoteUrl;

let IpFreq =
DeviceNetworkEvents
| summarize OrgSeenRemoteIpCount = dcount(DeviceId) by RemoteIP;

let ParentFreq =
DeviceProcessEvents
| summarize OrgSeenParentCount = count() by InitiatingProcessFileName;

let FolderFreq =
DeviceFileEvents
| summarize OrgSeenFolderCount = count() by FolderPath;
~~~

5.5 Org Rarity Enrichment (URL, IP, Parent, Folder)

~~~
let lookback = 30d;

let UrlFreq =
DeviceNetworkEvents
| summarize OrgSeenRemoteUrlCount = dcount(DeviceId) by RemoteUrl;

let IpFreq =
DeviceNetworkEvents
| summarize OrgSeenRemoteIpCount = dcount(DeviceId) by RemoteIP;

let ParentFreq =
DeviceProcessEvents
| summarize OrgSeenParentCount = count() by InitiatingProcessFileName;

let FolderFreq =
DeviceFileEvents
| summarize OrgSeenFolderCount = count() by FolderPath;
~~~

# 5.6 Combine Wide-Correlation + Rarity Model (Primary Hunt Output)

~~~
ImageToNet
| join kind=leftouter UrlFreq on RemoteUrl
| join kind=leftouter IpFreq on RemoteIP
| join kind=leftouter ParentFreq on ParentImage
| join kind=leftouter FolderFreq on ImageFolder
| extend SuspicionScore =
    40
    + iif(OrgSeenRemoteUrlCount <= 2, 15, 0)
    + iif(OrgSeenRemoteIpCount <= 2, 15, 0)
    + iif(OrgSeenParentCount <= 5, 10, 0)
    + iif(OrgSeenFolderCount <= 10, 5, 0)
    + iif(ScriptFile in~ (dynamic(["mshta.exe","rundll32.exe"])), 10, 0)
| extend RiskLevel = case(
    SuspicionScore >= 75, "Critical",
    SuspicionScore >= 60, "High",
    SuspicionScore >= 50, "Medium",
    "Low"
)
| order by SuspicionScore desc

~~~

# 6. Graph-Based Hunting Approach
Process Lineage (Grandparent → Parent → Child)

~~~

DeviceProcessEvents
| where ProcessId == <PID or list>
| project Timestamp, DeviceName, ProcessId, FileName, ProcessCommandLine,
         InitiatingProcessId, InitiatingProcessFileName
~~~

UserApp → ScriptHost → ImageRead → NetConnect

Key indicators:

Parent not normally associated with script execution

Script hosts with non-traditional parents (updater.exe, service.exe, electron apps)

Repeated image reads by same PID before network communication

# 7. Investigation Playbook (Analyst SOP)

Confirm the Process Chain

Identify parent → script host → image read → outbound network.

Validate that image reads were not UI-driven (Explorer, Photos app).

Validate Image Access Pattern

Multiple reads of the same image suggest stego extraction loops.

Odd file locations (program directories, hidden folders, app-specific paths).

Investigate Network Endpoints

Check if TLS fingerprints (JA3/JA4) match known malware families.

Validate domain/IP rarity across enterprise.

Check Memory Structures

Look for in-memory .NET assembly loads.

Look for PowerShell “reflection load” indicators.

Map to User Activity

Identify emails opened.

Identify browser tabs visited before event.

Check for downloads around same timestamp.

Check For Lateral Movement Indicators

If payload executed: new services, scheduled tasks, registry modifications.

# 8. Incident Response Flow (Mapped to IR Frameworks)
Preparation

Baseline parent-child execution frequencies

Baseline folder access patterns

Identification

Use hunt queries to find suspicious sequences

Prioritise by rarity and scoring

Containment

Isolate device if malicious:

Strange loader chain

Unknown outbound domain

Stego-based payload staging

Eradication

Remove staged payloads from Temp/Pictures/AppData

Kill processes associated with mshta/rundll32/PowerShell loaders

Block C2 domains/IPs

Recovery

Verify no persistence mechanisms dropped

Validate system file integrity

Lessons Learned

Add custom suppressions or enhancements for recurring benign automation

Tune scoring thresholds for unique environment

# 9. Tuning Guidance for Sentinel

Keep wide-scope queries in notebooks or scheduled hunts, not alert rules.

Add suppression lists for:

Known automation parents

Enterprise applications that read images programmatically

Maintain per-environment rarity thresholds

Use Microsoft Sentinel Watchlists to manage:

Safe domains

Safe folders

Safe parent processes

# 10. Summary

This wide-scope playbook provides a comprehensive hunting methodology that:

Detects adversaries intentionally avoiding Downloads/Temp folders

Detects stego loaders run from non-user-facing parents

Uses rarity scoring to control noise

Uses sequence logic to reveal hidden loader chains

Enables deep analyst-driven investigations

Aligns to MITRE and SOC IR frameworks

Complements but does not replace the core rule

This document is suitable for publication in a GitHub portfolio as a full hunting reference.






