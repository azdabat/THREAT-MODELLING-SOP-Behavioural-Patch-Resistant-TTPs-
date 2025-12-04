# THREAT MODELLING SOP  
## Behavioural, Patch-Resistant TTPs (2025)

### Author: Ala Dabat  
### Repository Purpose  
This repository documents a complete, analyst-facing **Threat Modelling Standard Operating Procedure (SOP)** for modern, patch-resistant, behaviour-driven attacks observed across 2024–2025.  
The objective is to provide a mature, repeatable methodology for modelling threats, understanding their operational tradecraft, and producing **core behavioural hunts** that map directly to real adversary workflows, not isolated events.

Most enterprise detection strategies revolve around signatures, IOCs, and individual CVEs. Those no longer provide meaningful defence against long-term, iterative adversaries such as ransomware crews, identity-centric attackers, and modern loader ecosystems.  
This SOP shifts the focus to **behavioural kill-chain modelling** and **sequence-based analytics**, enabling organisations to detect the attacker’s method rather than their toolset.

---

# 1. Mission Statement

**To model, understand, and detect modern adversaries through their behaviour, not their payloads.  
To provide SOC, IR, and Threat Hunting teams with a reusable methodology that captures adversary intent, tradecraft, and kill-chain progression across all common attack ecosystems.**

Our mission is threefold:

1. **Threat Modelling** – break attacks down into behavioural stages observable across endpoint, identity, network, and cloud telemetry.  
2. **Core Hunt Development** – produce patch-resistant behavioural hunts that surface the earliest detectable stages across multiple attack families.  
3. **Operational Alignment** – give analysts repeatable playbooks, MITRE mappings, and pivot paths that reduce investigation time and improve detection confidence.

This SOP reflects real adversarial behaviour seen in the wild and is intended for senior analysts, IR responders, and detection engineers seeking depth, clarity, and long-term defensive strategy.

---

# 2. Methodology Overview

Our methodology is grounded in four principles:

## 2.1 Behaviour Over Indicators
Threat actors routinely change payloads, hosting providers, infrastructure, and loaders.  
What they cannot easily change are their **behaviours**:

- Credential access
- Lateral movement patterns
- Process chains
- Backup destruction
- Data staging and exfiltration
- Abuse of legitimate administrative tools (PsExec, RMMs, WMI, RDP)
- Cloud & identity impersonation sequences

The SOP focuses on modelling these immutable behavioural anchors.

---

## 2.2 Kill-Chain & Pattern-Centric Modelling
Every attack—regardless of tooling—follows a detectable pattern:

- A valid account misused outside normal hours  
- A host enumerating AD shortly after a new login  
- Backup deletion pre-ransomware  
- Admin tools deployed to multiple hosts in a short window  
- A user-facing process spawning a script → LOLBin → network beacon

We map these patterns using:

- MITRE ATT&CK  
- Lockheed Cyber Kill Chain  
- Behavioural sequences over time (hours/days)  
- Cross-surface telemetry (endpoint + identity + cloud + network)

---

## 2.3 Patch-Resistant Threat Modelling
Some attack ecosystems are not solvable through patching:

- **Black Basta–style ransomware**
- **Identity-first intrusions (helpdesk coercion, token abuse)**
- **Steganographic loaders & image-based stagers**
- **Living-off-the-land post-exploitation**
- **Post-RCE behaviours common across all major CVEs**
- **MFT exploitation & trusted data-transfer abuse**

These threats evolve around behaviour, not vulnerabilities.  
Our modelling reflects this reality.

---

## 2.4 Multi-Surface Observability
Attack chains must be mapped across:

| Surface | Purpose |
|--------|----------|
| **Endpoint (MDE)** | Process chains, LOLBins, file events, LSASS access, encryption patterns |
| **Identity (Entra ID)** | MFA reset, token abuse, valid credentials, anomalous logon paths |
| **Network** | C2 beaconing, lateral movement, data staging, exfiltration |
| **Cloud Apps** | App impersonation, consent abuse, service principal creation |
| **Perimeter Logs** | Reverse proxy signals, webshell indicators, unusual POST patterns |

Cross-joining these surfaces is where high-value detection emerges.

---

# 3. Threat Modelling Framework (SOP)

This SOP uses a structured workflow:

---

## 3.1 Step 1 — Define the Attack Ecosystem
Each adversarial ecosystem is analysed as its own category:

- **Ransomware ecosystems (e.g., Black Basta, BlackSuit, Medusa)**
- **Identity-centric intrusions (MFA fatigue, helpdesk coercion, valid account abuse)**
- **Steganographic loaders (XWorm, .NET image-based loaders)**
- **Post-RCE behaviours (app frameworks, SharePoint, GoAnywhere)**
- **Living-off-the-land lateral movement chains**

---

## 3.2 Step 2 — Map Each Stage to MITRE (Not Just Techniques)
MITRE mapping is performed holistically:

- **Tactic → Technique → Sub-Technique**  
- Associated process characteristics  
- Expected telemetry tables  
- Pivot fields  
- Sequence context  
- Time windows

Example (Black Basta ecosystem):

| Stage | MITRE | Behaviour |
|-------|--------|------------|
| Credential Access | T1003.* | LSASS access, comsvcs.dll MiniDump, procdump chains |
| Lateral Movement | T1021.*, T1077 | PsExec, RDP, AnyDesk services |
| Impact | T1486 | Rapid rename spikes, encryption staging |

---

## 3.3 Step 3 — Determine Observable Telemetry
For each attack stage:

- Which logs exist?  
- Which often do NOT exist?  
- What gaps can be compensated using behaviour?

Example:  
Image-based malware may not write a file → but it **must**:

- have a browser/Office parent  
- load image bytes  
- spawn a script engine  
- initiate network activity

---

## 3.4 Step 4 — Build Behavioural Anchors
Anchors = non-negotiable behaviours that occur regardless of payload variation.

Examples:

- **LSASS access** always precedes domain escalation.  
- **Backup deletion** always precedes ransomware.  
- **New RMM agent installation** always precedes operator hands-on-keyboard.  
- **User-facing process → script → LOLBin** always precedes in-memory payload delivery.  

Anchors become the root of core detection logic.

---

## 3.5 Step 5 — Construct Core Hunts Around Anchors
Core hunts focus on:

- High-signal, low-noise behaviours  
- Multi-table correlation  
- Sequences within 30–120 minutes  
- Anomaly relative to the organisation’s baseline  
- Process and identity lineage

These hunts are defensive baselines for every modern attack model.

---

## 3.6 Step 6 — Validate Against Real Attack Chains
Each core hunt is validated against:

- Operator workflow timing  
- Required tools  
- Evasion patterns  
- Host-to-host traversal  
- Known post-exploitation frameworks  
- Steganographic loader behaviour  
- Identity abuse sequences  
- Backup/snapshot interference  
- Data staging patterns

This ensures models remain true to in-the-wild behaviour.

---

# 4. Threat Ecosystems Covered (Initial Release)

This SOP covers the following behavioural ecosystems:

1. **Black Basta / BlackSuit Ransomware Pattern**  
   - Patch-resistant  
   - Lives on behavioural chains  
   - Multi-day intrusion patterns  

2. **Identity Intrusions (Helpdesk, MFA Reset, Valid Accounts)**  
   - No malware required  
   - Purely human-driven intrusions  

3. **Steganographic Loaders (PNG/JPG + HTML smuggling)**  
   - Image-embedded payload execution  
   - Memory-only loaders  

4. **GoAnywhere / MFT Behavioural Abuse**  
   - Trusted transfer mechanisms  
   - Post-exploitation data staging  

5. **SharePoint Hybrid Abuse (Token & App Impersonation)**  
   - Webshell-less compromise  
   - Privileged service impersonation  

(React/Node RCE omitted intentionally due to limited native telemetry coverage.)

---

# 5. Outputs

This repository will produce:

- **Core Hunts Pack** (behavioural baselines across all ecosystems)  
- **Attack Chain Modelling Documents** (adversary perspective)  
- **MITRE Mappings & Pivot Tables**  
- **Analyst Investigative Guides**  
- **Advanced Scoring Engine (Extended Pack)**  
- **Kill-Chain Correlation Framework**  
- **Organisation-Ready Detection Artefacts**

All documents are written for practical use in SOC, Threat Hunting, and IR environments.

---

# 6. Target Audience

- Senior SOC Analysts  
- Incident Responders  
- Threat Hunters  
- Detection Engineers  
- Red Teamers seeking defensive insight  

The SOP is designed to meet expectations at a senior professional level and demonstrate deep understanding of modern adversarial behaviour.

---

# 7. Roadmap

| Phase | Deliverable |
|-------|-------------|
| Phase 1 | Core Hunts for All Behavioural Ecosystems |
| Phase 2 | Advanced Behavioural Packs (scoring, chained sequences) |
| Phase 3 | Full Kill-Chain Correlation Framework |
| Phase 4 | Identity & Cloud Threat Expansion (OAuth, token abuse) |
| Phase 5 | Cross-Surface Analytics (endpoint + identity + cloud) |

---

# 8. Repository Structure

```plaintext
THREAT-MODELLING-SOP/
│
├── README.md
├── /Core-Hunts/
│     ├── BlackBasta_Core.md
│     ├── Identity-Abuse_Core.md
│     ├── StegoLoader_Core.md
│     ├── GoAnywhere_Core.md
│     └── SharePoint_Core.md
│
├── /Attack-Models/
│     ├── BlackBasta_AttackChain.md
│     ├── IdentityAbuse_AttackChain.md
│     ├── StegoLoader_AttackChain.md
│     ├── GoAnywhere_AttackChain.md
│     └── SharePoint_AttackChain.md
│
└── /MITRE-Mapping/
      └── MITRE_MasterTable.md
