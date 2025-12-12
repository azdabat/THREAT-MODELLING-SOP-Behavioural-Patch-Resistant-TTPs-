# SilverFox / ValleyRAT – Stego Loader, DLL Sideloading & BYOVD Kill Chain  
**Author:** Ala Dabat  
**Domain:** Threat Research • Detection Engineering • DFIR  
**Threat Focus:** SilverFox / ValleyRAT-style loaders (steganography, DLL sideloading, BYOVD, EDR tamper, polymorphic payloads)

---

## 0. Purpose & Audience

This repository documents a **full kill chain** used by modern SilverFox / ValleyRAT-style intrusions and provides:

- A **clear attacker-view attack chain** (end-to-end).
- A **defender-view mapping** to telemetry, MITRE ATT&CK, and IR lifecycles.
- **Representative KQL detection snippets** for:
  - Script stagers
  - Stego image loader behaviour
  - DLL sideloading + BYOVD
  - Registry-based persistence
- **Mermaid diagrams** for the kill chain and timeline.
- **IOA/IOC mapping** (with malicious payloads redacted but described).

It is written for **L2 and L3 SOC analysts, Incident Responders, and Threat Hunters** and is suitable as a **GitHub portfolio artefact** for senior detection engineering / IR interviews.

---

## Table of Contents

1. [High-Level Overview](#1-high-level-overview)  
2. [Full Kill-Chain Diagram (Mermaid)](#2-full-kill-chain-diagram-mermaid)  
3. [Attack Chain – Attacker Perspective](#3-attack-chain--attacker-perspective)  
4. [Attack Chain – Defender Perspective](#4-attack-chain--defender-perspective)  
5. [Steganography & Image Payloads Explained](#5-steganography--image-payloads-explained)  
6. [Stager Type Comparison](#6-stager-type-comparison)  
7. [MITRE ATTACK Mapping per Stage](#7-mitre-attack-mapping-per-stage)  
8. [IOAs, IOCs & Payload Description](#8-ioas-iocs--payload-description)  
9. [Representative KQL Detection Snippets](#9-representative-kql-detection-snippets)  
10. [IR Playbook (NIST 800-61 + SANS PICERL)](#10-ir-playbook-nist-800-61--sans-picerl)  
11. [Diamond Model View](#11-diamond-model-view)  
12. [Detection Strategy & Usage Notes](#12-detection-strategy--usage-notes)  

---

## 1. High-Level Overview

SilverFox / ValleyRAT-style campaigns use a **multi-stage, behaviourally evasive kill chain**:

1. **User-triggered stager**  
   - LNK / HTML / JavaScript / HTA / fake installer EXE.
2. **Image-based stego payload**  
   - PNG/JPEG/BMP used as a **container** for encrypted shellcode or .NET payloads.
3. **Reflective in-memory execution**  
   - Shellcode or .NET assembly executed directly in memory (no obvious EXE on disk).
4. **DLL Search Order Hijacking (sideloading)**  
   - Legitimate signed EXE + malicious DLL placed in the same directory.
5. **BYOVD (Bring Your Own Vulnerable Driver)**  
   - A signed but vulnerable driver is loaded to gain kernel read/write and blind EDR.
6. **EDR tampering, credential theft, and exfiltration**  
   - LSASS access; registry and service persistence; HTTPS-based C2 and exfil.

Key point for analysts:

> The **image never executes itself**. It is a **payload container**. The actual execution is done by a **stager** (script/LOLBin/signed EXE) that reads and decrypts the payload from the image, then executes it in memory.

---

## 2. Full Kill-Chain Diagram (Mermaid)

### 2.1 End-to-End Attack Flow

~~~mermaid
flowchart TD

A[User opens lure<br>LNK / HTML / JS / HTA / Fake Installer] --> B[Stager executes<br>PowerShell / WScript / MSHTA / Signed EXE]
B --> C[Image retrieval<br>Download or extract PNG/JPG/BMP]
C --> D[Stego payload extraction<br>Encrypted shellcode/.NET read from image bytes]
D --> E[Reflective execution<br>VirtualAlloc / WriteProcessMemory / CreateThread]
E --> F[DLL sideloading<br>Signed EXE loads malicious DLL from same folder]
F --> G[BYOVD driver installed<br>Vulnerable .sys loaded via SC / PnP / Services key]
G --> H[EDR/AV tampering<br>Filter unload, exclusions, sensor blinding]
H --> I[Credential access<br>LSASS read, comsvcs.dll, MiniDump patterns]
I --> J[Command and Control<br>HTTPS C2, tasking, staging]
J --> K[Data staging and exfiltration<br>7z/rar + curl/wget/bitsadmin]
~~~

---

## 3. Attack Chain – Attacker Perspective

This section explains the chain **from the adversary’s point of view**.

### 3.1 Initial Access

- Delivery via:
  - Spearphishing attachments (`.zip`, `.iso`, `.lnk`, `.hta`, `.js`, `.vbs`).
  - HTML smuggling.
  - Fake installers / “updates”.
- Objective:
  - Achieve **one user-triggered execution event**.
- There is **no zero-click** behaviour here: the user must open/run something.

### 3.2 Stager Execution

- Executed as:
  - `powershell.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, or a signed EXE.
- Responsibilities:
  - Download or unpack the image file containing steganographic payload.
  - Read that file as **raw bytes**, not as an image.
  - Extract and decrypt the hidden payload.

### 3.3 Stego Payload Extraction

- Image types: `.png`, `.jpg`, `.jpeg`, `.bmp`, `.gif`.
- Payload location:
  - Embedded in pixel data (LSB changes).
  - Stored in PNG chunks.
  - Appended after the file’s logical end (EOF).
- Payload type (redacted high-level description):
  - Encrypted shellcode blob (**[REDACTED_SHELLCODE_PAYLOAD]**).
  - Encrypted .NET assembly (**[REDACTED_DOTNET_LOADER]**).

The attacker writes custom decode logic so only their stager knows how to reconstruct the payload.

### 3.4 Reflective Execution (In-Memory Loader)

- Decrypted payload contains:
  - A .NET loader that uses `Assembly.Load(byte[])` and reflection, or
  - Raw shellcode that uses standard Windows APIs for process injection.
- Typical API usage:
  - `VirtualAlloc(…)`
  - `WriteProcessMemory(…)`
  - `CreateRemoteThread(…)`
- Goal:
  - Avoid dropping a recognisable artefact to disk.
  - Blend into legitimate tooling if possible.

### 3.5 DLL Search Order Hijacking (Sideloading)

- Attacker plants:
  - `legit.exe` – a signed, trusted binary.
  - `legit.dll` – malicious DLL with the same name as the expected library.
- Because Windows searches the **EXE directory first**, the malicious DLL is loaded instead of or in addition to the legitimate one.
- This does not rely on an exploit: it abuses Windows DLL search order.

### 3.6 BYOVD – Bring Your Own Vulnerable Driver

- Attacker selects an **old, signed, but vulnerable driver** (`vuln.sys`).
- Driver is loaded via:
  - `sc.exe create/start`  
  - `pnputil.exe`  
  - Direct registry writes to `HKLM\SYSTEM\CurrentControlSet\Services\...`.
- After load, the attacker:
  - Gains arbitrary kernel read/write.
  - Removes or patches kernel callbacks used by EDR.
  - Potentially disables event providers or filter drivers.

Outcome: **EDR looks “green” but is blind.**

### 3.7 Tampering, Credential Theft & Exfiltration

- Tampering:
  - `fltmc unload <driver>`
  - `Stop-Service WinDefend`
  - `Add-MpPreference -ExclusionPath ...`
- Credential theft:
  - `lsass.exe` memory reads via standard or custom tooling.
  - `comsvcs.dll!MiniDump` invocation.
- Exfiltration:
  - Archive via `7z.exe a`, `rar.exe a`.
  - Upload via `curl`, `wget`, `bitsadmin` over HTTPS.

---

## 4. Attack Chain – Defender Perspective

### 4.1 Behavioural View per Stage

| Stage | What You See (Telemetry) | Detection Opportunity |
|------|---------------------------|------------------------|
| Initial Access | Office/Browser/Explorer spawns script host or unusual EXE | Parent-child relationships (Email/Browser → Script) |
| Stager Execution | `powershell.exe` / `wscript.exe` / `mshta.exe` with download commands | Script stager detection (download + write) |
| Image Retrieval | Script process reads PNG/JPG/BMP from Downloads/Temp | Image read by non-viewer process |
| Stego Extraction | Same process later allocates memory / spawns child with reflective patterns | In-memory loader / .NET reflection IOAs |
| DLL Sideload | Signed EXE in user-writable path loads DLL from same folder | Sideloading pattern: signed loader + DLL in writable path |
| BYOVD | `.sys` driver dropped and loaded shortly after sideload | Driver drop + service/registry-based load |
| Tamper | Commands affecting EDR/AV filter drivers and services | Tool tampering / sensor sabotage detection |
| Cred Theft | Non-standard LSASS access, suspicious tooling | LSASS access from unusual processes |
| Exfiltration | 7z/rar + HTTP(S) uploads from non-admin context | Staging + exfil via scripting binaries |

### 4.2 Timeline Diagram (Attacker vs Defender)

~~~mermaid
sequenceDiagram
    participant U as User
    participant ST as Stager (PS/WSH/EXE)
    participant IMG as Stego Image
    participant LD as Loader (In-Memory)
    participant OS as OS/Kernel
    participant SOC as SOC/EDR

    U->>ST: Opens lure (LNK/HTML/Installer)
    ST->>IMG: Downloads/reads image bytes
    ST->>LD: Decrypts and passes payload
    LD->>OS: VirtualAlloc / WriteProcessMemory / CreateThread
    LD->>OS: Starts signed EXE + malicious DLL (sideload)
    LD->>OS: Drops & loads vulnerable driver (BYOVD)
    OS->>SOC: Partial telemetry (until blind)
    LD->>OS: Accesses LSASS, stages data, exfiltrates
    SOC->>SOC: Correlates stager + image read + sideload + driver load
~~~

---

## 5. Steganography & Image Payloads Explained

### 5.1 Key Principle

> The **image is a container**, not an exploit. It cannot execute code by itself.

Payload is hidden in:

- Pixel data (least significant bits).
- PNG chunks.
- Appended binary blob after the end-of-image marker.

The stager:

1. Reads the image as bytes.
2. Extracts hidden data using attacker-defined logic.
3. Decrypts the payload with an embedded or derived key.
4. Executes the payload in memory.

### 5.2 Why Images?

- Commonly allowed through email and web filters.
- “Safe” extensions: harder to block globally.
- Can be blended to keep entropy “normal”.
- Eliminates simple hash-based detection (payload differs per infection).

---

## 6. Stager Type Comparison

| Stager Type | Runs As | User Perception | Typical Use | Notes |
|-------------|--------|-----------------|-------------|-------|
| `.lnk` | `explorer.exe` → script/PS | “Shortcut to document” | Phishing attachments, zipped lures | Easy to disguise as PDF/Doc |
| `.hta` | `mshta.exe` | Low visibility | HTML smuggling, JS loaders | Executes full HTML/JS with ActiveX |
| `.js / .jse / .vbs` | `wscript.exe` / `cscript.exe` | “Script file” | Mass campaigns, simple loaders | Heavily abused; noisy but common |
| `.ps1` | `powershell.exe` | Often hidden window | Targeted loaders, reflective execution | Strongest flexibility, high detection value |
| Fake “installer” EXE | Signed or repacked EXE | “Legit installer” | Sideloading and bundles | Good for persistence and trust abuse |
| HTML smuggling | Browser → disk | “View invoice/portal” | Delivery of EXE/JS containers | Bypasses some mail filters |

---

## 7. MITRE ATT&CK Mapping per Stage

| Stage | Tactic(s) | Technique(s) |
|-------|-----------|-------------|
| Initial Access | TA0001 Initial Access | T1566.001 Spearphishing Attachment, T1204.002 User Execution: Malicious File |
| Stager Execution | TA0002 Execution | T1059 Command & Scripting Interpreter, T1218 Signed Binary Proxy Execution |
| Stego Delivery | TA0005 Defense Evasion, TA0002 Execution | T1027.003 Steganography, T1059.x Interpreter Variants |
| In-Memory Loader | TA0002 Execution, TA0005 Defense Evasion | T1620 Reflective Code Loading (sub-tech of in-memory), T1055 Process Injection |
| DLL Sideloading | TA0003 Persistence, TA0005 Defense Evasion | T1574.002 DLL Search Order Hijacking |
| BYOVD | TA0004 Privilege Escalation, TA0005 Defense Evasion | T1068 Exploitation for Privilege Escalation (driver), T1562.001 Disable or Modify Tools |
| Tamper | TA0005 Defense Evasion | T1562.001 Disable Security Tools |
| Credential Theft | TA0006 Credential Access | T1003.001 LSASS Memory, T1003.003 DMP artefacts |
| C2 | TA0011 Command & Control | T1071 Web Protocols |
| Exfiltration | TA0010 Exfiltration | T1041 Exfiltration Over Web Services, T1567 Exfiltration Over Web Services |

---

## 8. IOAs, IOCs & Payload Description

### 8.1 Indicators of Attack (IOAs)

High-value behavioural IOAs:

- Script host (`powershell.exe`, `wscript.exe`, `mshta.exe`) spawned by Outlook/Word/Browser.
- The same script process:
  - Reads `.png/.jpg/.bmp/.gif` from `Downloads`, `%TEMP%`, `AppData\Local\Temp`.
  - Shortly afterwards establishes HTTP/HTTPS connections.
- Signed EXE located in a **user-writable path** that loads DLLs from that same directory.
- Driver file (`.sys`) written into `ProgramData`, `Temp`, or user profile paths and then loaded as a service.
- Non-administrative or unusual processes accessing `lsass.exe` memory.
- Quick sequence of: script → image read → in-memory execution APIs → sideload → driver → tampering.

### 8.2 Indicators of Compromise (IOCs)

Deliberately **redacted but described** (example patterns):

- **Domains (patterned):**  
  - `cdn-*.xyz`, `assets-*.top`, `update-*.cfd`  
  - Short-lived domains using low-reputation TLDs.
- **File naming patterns:**  
  - `icon.png`, `banner.jpg`, `bg.bmp`, `wallpaper.png` used repeatedly in `Temp/Downloads`.
  - `updater.exe`, `helper.exe`, `launcher.exe` in user profile folders.
- **Driver names:**  
  - Old vendor names (GIGABYTE, ASUS, antivirus vendors) with outdated version numbers.  
  - Example pattern **[REDACTED_VULN_DRIVER.sys]**.
- **Payloads (redacted):**  
  - Encrypted shellcode blocks **[REDACTED_SHELLCODE_BLOB]**.  
  - Encrypted .NET assemblies **[REDACTED_DOTNET_ASSEMBLY]**.

Note: **Hash-based IOCs are weak** due to polymorphism (builder changes file contents per infection).

---

## 9. Representative KQL Detection Snippets

> These are **representative** and aligned to the described behaviours. They are not the full rulepack.

### 9.1 Script Stager with Download Behaviour

Tracks script engines used as downloaders that drop EXE/DLL into user-writable paths.

~~~kusto
// Script-based Stager → Payload Drop (Representative Snippet)

let Lookback = 48h;
let WritablePaths = dynamic([
    "\\Users\\","\\Downloads\\","\\Desktop\\","\\Temp\\",
    "\\ProgramData\\","\\Public\\","\\AppData\\"
]);

let ScriptEvents =
DeviceProcessEvents
| where Timestamp > ago(Lookback)
| where FileName in~ (
    "powershell.exe","pwsh.exe",
    "wscript.exe","cscript.exe",
    "mshta.exe","certutil.exe","bitsadmin.exe"
)
| where ProcessCommandLine has_any (
    "Invoke-WebRequest","Invoke-RestMethod","iwr",
    "DownloadFile","DownloadString","Net.WebClient",
    "Start-BitsTransfer","urlcache","ADODB.Stream","XMLHTTP"
)
| project
    DeviceId,
    ScriptTime = Timestamp,
    ScriptPid  = ProcessId,
    ScriptName = FileName,
    ScriptCmd  = ProcessCommandLine,
    ScriptParent = InitiatingProcessFileName;

let FileDrops =
DeviceFileEvents
| where Timestamp > ago(Lookback)
| where FileName has_any (".exe",".dll")
| where FolderPath has_any (WritablePaths)
| project
    DeviceId,
    DropTime = Timestamp,
    DroppedFile = FileName,
    DropPath    = FolderPath,
    DropperPid  = InitiatingProcessId;

ScriptEvents
| join kind=inner (FileDrops) on DeviceId
| where DropTime between (ScriptTime .. ScriptTime + 10m)
| where DropperPid == ScriptPid
| summarize
    FirstSeen    = min(ScriptTime),
    LastSeen     = max(DropTime),
    ScriptName   = any(ScriptName),
    ScriptParent = any(ScriptParent),
    ScriptCmd    = any(ScriptCmd),
    DroppedFiles = make_set(DroppedFile, 10),
    DropPaths    = make_set(DropPath, 10)
  by DeviceId
| extend Severity = "High"
| extend HunterDirective = strcat(
    "HIGH: Script-based stager detected. ",
    ScriptName, " (parent: ", ScriptParent,
    ") downloaded and dropped payload(s) ",
    tostring(DroppedFiles), " to ", tostring(DropPaths),
    ". Review ScriptCmd and pivot into follow-on execution."
)
~~~

---

### 9.2 Stego Loader Behaviour (Image Read + Network)

Representative core hunt for image-based loader behaviour.

~~~kusto
// Stego Loader Behaviour (User-Facing App → Script → Image → Network)

let lookback = 7d;
let TimeWindowMinutes = 5;

let UserFacingParents = dynamic([
    "outlook.exe","winword.exe","excel.exe","powerpnt.exe",
    "chrome.exe","msedge.exe","iexplore.exe","firefox.exe"
]);

let ScriptHosts = dynamic([
    "powershell.exe","pwsh.exe",
    "wscript.exe","cscript.exe",
    "mshta.exe","rundll32.exe"
]);

let ImageExt = dynamic([".png",".jpg",".jpeg",".bmp",".gif"]);

let ScriptFromUserApps =
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in~ (ScriptHosts)
| where InitiatingProcessFileName in~ (UserFacingParents)
| project
    ScriptTime    = Timestamp,
    DeviceId,
    DeviceName,
    AccountName,
    ScriptFile    = FileName,
    ScriptCommand = ProcessCommandLine,
    ParentImage   = InitiatingProcessFileName,
    ProcessId;

let ImageReadsByScript =
DeviceFileEvents
| where Timestamp >= ago(lookback)
| where ActionType in ("FileRead","FileCreated","FileModified")
| extend FileExt = tolower(strcat(".", split(FileName, ".")[-1]))
| where FileExt in~ (ImageExt)
| where FolderPath has_any ("\\Downloads\\","\\Download\\","\\Temp\\","\\AppData\\Local\\Temp\\")
| project
    ImageReadTime = Timestamp,
    DeviceId,
    InitiatingProcessId,
    ImageFile   = FileName,
    ImageFolder = FolderPath;

let NetFromScript =
DeviceNetworkEvents
| where Timestamp >= ago(lookback)
| where RemotePort in (80,443)
| project
    NetTime          = Timestamp,
    DeviceId,
    InitiatingProcessId,
    RemoteIP,
    RemoteUrl,
    RemotePort;

ScriptFromUserApps
| join kind=inner (ImageReadsByScript) on DeviceId, $left.ProcessId == $right.InitiatingProcessId
| where ImageReadTime between (ScriptTime - 2m .. ScriptTime + TimeWindowMinutes * 1m)
| join kind=inner (NetFromScript) on DeviceId, $left.ProcessId == $right.InitiatingProcessId
| where NetTime between (ImageReadTime .. ImageReadTime + TimeWindowMinutes * 1m)
| summarize
    FirstSeen       = min(ScriptTime),
    LastSeen        = max(NetTime),
    ParentImage     = any(ParentImage),
    ScriptFile      = any(ScriptFile),
    ScriptCommand   = any(ScriptCommand),
    DeviceName      = any(DeviceName),
    AccountName     = any(AccountName),
    ImageFiles      = make_set(ImageFile, 10),
    ImageFolders    = make_set(ImageFolder, 10),
    RemoteIPs       = make_set(RemoteIP, 10),
    RemoteUrls      = make_set(RemoteUrl, 10),
    RemotePorts     = make_set(RemotePort, 10)
  by DeviceId
| extend HunterDirective = strcat(
    "Stego-like chain: ",
    ParentImage, " spawned ", ScriptFile,
    " which read image(s) from ", tostring(ImageFolders),
    " then connected to ", tostring(RemoteUrls),
    ". Review process tree, content source (email/web), and memory for loaders."
)
~~~

---

### 9.3 DLL Sideloading + BYOVD Chain (Condensed)

Representative snippet to show signed loader + driver behaviour.

~~~kusto
// Signed Loader (User Path) → DLL Sideload → Driver Drop → Service Load

let Lookback = 24h;
let WritablePaths = dynamic(["\\Temp\\","\\ProgramData\\","\\Users\\","\\Public\\","\\Desktop\\","\\Downloads\\"]);

let SideloadEvents =
DeviceImageLoadEvents
| where Timestamp > ago(Lookback)
| where FileName endswith ".dll"
| where InitiatingProcessFolderPath has_any (WritablePaths)
| where FolderPath has_any (WritablePaths)
| where InitiatingProcessSignatureStatus == "Signed"
| project
    DeviceId,
    SideloadTime = Timestamp,
    LoaderName   = InitiatingProcessFileName,
    LoaderPath   = InitiatingProcessFolderPath,
    LoaderPid    = InitiatingProcessId,
    LoadedDll    = FileName,
    LoadedDllPath = FolderPath;

let DriverDrops =
DeviceFileEvents
| where Timestamp > ago(Lookback)
| where FileName has_any (".sys",".dat",".tmp")
| where FolderPath has_any (WritablePaths)
| project
    DeviceId,
    DropTime    = Timestamp,
    DriverFile  = FileName,
    DriverFolder = FolderPath;

let ServiceEvents =
union
(
    DeviceProcessEvents
    | where Timestamp > ago(Lookback)
    | where FileName in~ ("sc.exe","pnputil.exe")
    | where ProcessCommandLine has ".sys"
    | project DeviceId, SvcTime = Timestamp, SvcCmd = ProcessCommandLine
),
(
    DeviceRegistryEvents
    | where Timestamp > ago(Lookback)
    | where RegistryKey has "System\\CurrentControlSet\\Services"
    | where RegistryValueName == "ImagePath" and RegistryValueData has ".sys"
    | project DeviceId, SvcTime = Timestamp, SvcCmd = RegistryValueData
);

SideloadEvents
| join kind=inner (DriverDrops) on DeviceId
| where DropTime between (SideloadTime .. SideloadTime + 45m)
| join kind=inner (ServiceEvents) on DeviceId
| where SvcTime between (DropTime .. DropTime + 15m)
| summarize
    FirstSeen      = min(SideloadTime),
    LastSeen       = max(SvcTime),
    LoaderName     = any(LoaderName),
    LoaderPath     = any(LoaderPath),
    LoadedDlls     = make_set(LoadedDll, 10),
    DriverFiles    = make_set(DriverFile, 10),
    ServiceTargets = make_set(SvcCmd, 10)
  by DeviceId
| extend Severity = "High"
| extend HunterDirective = strcat(
    "HIGH: Signed loader ", LoaderName, " running from ", LoaderPath,
    " sideloaded DLL(s) ", tostring(LoadedDlls),
    " then dropped driver(s) ", tostring(DriverFiles),
    " and created kernel service(s) ", tostring(ServiceTargets),
    ". Investigate host for BYOVD and EDR blind spots."
)
~~~

---

### 9.4 Registry Persistence – Signal-Based (Extract)

Condensed version focusing on Run/Services keys and suspicious content.

~~~kusto
// Registry Persistence Signals (Run/Services Keys, Suspicious Content)

let lookback = 14d;

let PersistenceKeys = dynamic([
  @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
  @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
  @"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
  @"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
  @"HKLM\SYSTEM\CurrentControlSet\Services",
  @"HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
  @"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
]);

let BadStrings = dynamic([
  "-encodedcommand","-enc","-ep bypass","invoke-expression","frombase64string",
  "invoke-webrequest","downloadstring","start-bitstransfer",
  "rundll32","regsvr32","mshta","certutil"
]);

DeviceRegistryEvents
| where Timestamp >= ago(lookback)
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (PersistenceKeys)
| extend ValueData = tostring(RegistryValueData),
         ValueName = tostring(RegistryValueName),
         LowerData = tolower(ValueData)
| extend
    HasBadString  = LowerData has_any (BadStrings),
    PointsToExe   = LowerData matches regex @"(?i)\.exe\b",
    PointsToUserPath = LowerData matches regex @"(?i)^[a-z]:\\(users|public|programdata|temp|downloads|appdata)\\"
| summarize
    FirstSeen = min(Timestamp),
    LastSeen  = max(Timestamp),
    Events    = count(),
    AnyBadString = max(tobool(HasBadString)),
    AnyExe   = max(tobool(PointsToExe)),
    AnyUserPath = max(tobool(PointsToUserPath)),
    ExampleValue = any(ValueData)
  by DeviceName, RegistryKey, ValueName
| extend Severity = case(
    AnyBadString and AnyUserPath, "Critical",
    AnyExe and AnyUserPath,       "High",
    AnyExe,                       "Medium",
    "Low"
)
| extend HunterDirective = strcat(
    Severity, ": Registry persistence detected at ", RegistryKey,
    " (", ValueName, "). Value = ", ExampleValue,
    ". Check whether the referenced binary is legitimate or part of a loader chain."
)
~~~

---

## 10. IR Playbook (NIST 800-61 + SANS PICERL)

### 10.1 Preparation

- Ensure logging is enabled for:
  - `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceImageLoadEvents`,
  - `DeviceRegistryEvents`, `DeviceNetworkEvents`, `DeviceEvents` (for LSASS access).
- Maintain:
  - Driver reputation lists (e.g. known vulnerable drivers).
  - Allowlists of legitimate signed apps that may write drivers.
- Pre-define:
  - Host isolation procedures.
  - Memory acquisition runbooks for suspected in-memory loaders.

### 10.2 Identification

Key signals for declaring an incident:

- Script host, spawned from email or browser, reading images from Downloads/Temp.
- Follow-on suspicious outbound HTTP(S) to low-reputation TLDs or fresh domains.
- Signed EXE in user-writable path loading DLL from that same path.
- New driver file written and loaded as a service shortly afterward.
- Abrupt LSASS access from non-standard tooling.
- EDR telemetry suddenly dropping for that host (potential BYOVD success).

### 10.3 Containment

Short-term containment:

- Isolate affected host(s) from the network.
- Stop suspicious services associated with the dropped driver.
- Kill known malicious processes (sideloaded loaders, suspicious script hosts).

Medium-term containment:

- Block observed C2 domains/IPs at proxy/firewall.
- Invalidate or rotate exposed credentials.
- Scope the campaign by hunting for:
  - Similar sideload patterns.
  - Similar stego-loader behaviours.
  - Similar registry persistence keys.

### 10.4 Eradication

- Remove:
  - Malicious DLLs and binaries in user-writable paths.
  - Vulnerable drivers used for BYOVD.
  - Malicious registry entries and services.
- Restore:
  - EDR agents and kernel callbacks if impacted.
  - Group Policy settings around AV and Defender.
- Confirm:
  - No residual persistence or unusual scheduled tasks.
  - No additional backdoors deployed.

### 10.5 Recovery

- Reconnect hosts in a phased manner.
- Monitor intensively for:
  - Re-appearance of image-based loader patterns.
  - Re-creation of persistence keys.
  - Attempts to re-load vulnerable drivers.

### 10.6 Lessons Learned

- Update detection rules to:
  - Tighten image-based loader detection (balancing FP/TP).
  - Cover newly observed driver names/paths.
- Train SOC staff on:
  - Recognising stego-based loader chains.
  - Escalation criteria for LSASS access and driver loads.

---

## 11. Diamond Model View

| Diamond Axis | Observation |
|--------------|------------|
| **Adversary** | Likely Chinese-nexus / APT-style operator using SilverFox / ValleyRAT ecosystem, comfortable with BYOVD and steganography. |
| **Capability** | Image-based loaders, DLL search order hijacking, reflective in-memory loaders, BYOVD for kernel tamper, HTTPS C2 and stealth exfiltration. |
| **Infrastructure** | Short-lived domains on low-reputation TLDs; commodity VPS hosting; polymorphic payload distribution. |
| **Victim** | Windows endpoints with email/web-based access, EDR deployment across fleet, and standard office applications. |

Use this perspective to formulate hunting hypotheses (e.g. “same infrastructure hitting multiple tenants”, or “shared loader families across campaigns”).

---

## 12. Detection Strategy & Usage Notes

Key strategic points:

- **Do not rely on hashes.** Polymorphism makes them effectively worthless beyond very short-term blocking.
- Focus on **chains of behaviour**, not single events:
  - Parent/child process relationships.
  - Sequence: stager → image read → network → loader → sideload → driver → tamper.
- Identify **fixed anchors**:
  - Scripts reading images in `Downloads/Temp`.
  - Signed binaries running from user-writable paths.
  - Driver loads from non-standard locations.
- Use your KQL rules to:
  - Produce **low-volume, high-context** hunting outputs.
  - Surface suspicious kill chain segments even when the full chain is not yet complete.
- Integrate with **IR workflows**:
  - Every hit from the **sideload + BYOVD** analytic should be treated as at least “High”.
  - Every combination of **stego loader + LSASS access** should be prioritised as “Critical”.

---

**End of README**

This file is intended as both a **training artefact** and a **live reference** for threat hunting, IR, and detection engineering against SilverFox / ValleyRAT-style loader chains.
