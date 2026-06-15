# Hunt Query — NodeJS_RCE_ChildProcess_Hunt

**Architecture:** 4 — Hunt Query (PEAK/TAHITI)  
**Author:** Ala Dabat | MTDF 2026  
**MITRE ATT&CK:** T1059.007  
**Platform:** MDE Advanced Hunting  
**PEAK Type:** E — Entity (Intel-Driven)  
**Lifecycle:** Single investigation — not for production deployment  

---

> ⚠️ **HUNT MODE — NOT FOR PRODUCTION DEPLOYMENT**  
> This query has no production threshold. All results require analyst review.

---

## Purpose

Proactive threat hunt to validate the hypothesis: *"Is Node.js being abused to spawn shell processes with reverse shell or remote execution primitives in our environment?"*

Use this when:
- New threat intelligence reports Node.js RCE campaigns
- A composite sensor fires and you want to scope the full blast radius
- Quarterly proactive hunt cadence
- Post-incident retroactive investigation

---

## Hypothesis

```
I hypothesise that Node.js is being abused to spawn shell processes
with reverse shell or remote execution primitives, which would be visible
as node → [shell/downloader/interpreter] with RCE command-line content
in DeviceProcessEvents.
```

---

## Hunt Signal Tags

Every result row is tagged with signal descriptors so the analyst can prioritise without a threshold gate:

| Tag | Meaning | Priority |
|-----|---------|----------|
| `[REVERSE_SHELL]` | `/dev/tcp/` or socket reverse shell pattern | 🔴 CRITICAL — escalate immediately |
| `[PIPE_TO_SHELL]` | `\| bash` / `\| sh` pipe pattern | 🔴 HIGH — download-and-execute chain |
| `[WIN_CRADLE]` | PowerShell IEX/DownloadString | 🔴 HIGH — Windows RCE |
| `[REMOTE_URL]` | External URL in command line | 🟡 MEDIUM — staging indicator |
| `[ENCODED_CMD]` | Base64 encoded payload | 🟡 MEDIUM — obfuscation |
| `[SHELL]` | Shell child type (bash/sh etc.) | ℹ️ Context |
| `[DOWNLOADER]` | Download tool (curl/wget etc.) | ℹ️ Context |
| `[INTERPRETER]` | Interpreter child (python/perl etc.) | ℹ️ Context |
| `[BUILD_SERVER]` | Known CI/CD path detected | 🟢 Likely legitimate — verify |

---

## How to Use Results

### High Priority — Investigate Immediately
```
[REVERSE_SHELL] — almost certainly malicious
[PIPE_TO_SHELL] + [REMOTE_URL] — confirmed download-and-execute
[WIN_CRADLE] — confirmed PowerShell execution from Node
```

### Medium Priority — Investigate in Context
```
[REMOTE_URL] alone — check if internal or external
[ENCODED_CMD] alone — check if DevOps automation
[DOWNLOADER] without [REMOTE_URL] — check command line manually
```

### Low Priority — Verify
```
[BUILD_SERVER] — confirm CI/CD job context
[SHELL] without any other tags — likely test runner
```

---

## Pivot Recommendations

| Finding | Pivot Action |
|---------|-------------|
| `[REVERSE_SHELL]` confirmed | Pivot `DeviceNetworkEvents` on `DeviceId` + Timestamp → find C2 IP/port |
| Any malicious finding | Pivot `DeviceFileEvents` on `ChildSHA256` → find dropped payload files |
| Account scope needed | Pivot `DeviceLogonEvents` on `AccountName` → lateral movement scope |
| Application identity | Use `ParentFolder` to identify the specific Node.js application path |

---

## TAHITI Lifecycle

```
T1 Trigger      : Threat intel / new CVE / incident response
T2 Hypothesis   : node spawning shells with RCE primitives
T3 Data         : MDE DeviceProcessEvents confirmed healthy
T4 Analysis     : Run this query (you are here)
T5 Iterate      : Refine time window, narrow to server devices if needed
T6 Outcome      :
    True Positive  → Generate Promotion Package → NodeJS_Bash_RCE composite
    False Positive → Document noise profile → Update IsManagedEnv allowlist
    No Findings    → Document gap → Confirm DeviceProcessEvents coverage
    Refined        → New hypothesis generated → New hunt initiated
```

---

## Promotion Trigger

If any row tagged `[REVERSE_SHELL]` or `[PIPE_TO_SHELL]` + `[REMOTE_URL]` is confirmed malicious:

1. Generate Promotion Package
2. Paste into MTDF Engineering Copilot
3. Build dedicated composite: `NodeJS_Bash_RCE` or `NodeJS_Downloader_RCE`
4. Update router rule decomposition tracker
5. Retire that technique from the router once composite is ADX-validated
