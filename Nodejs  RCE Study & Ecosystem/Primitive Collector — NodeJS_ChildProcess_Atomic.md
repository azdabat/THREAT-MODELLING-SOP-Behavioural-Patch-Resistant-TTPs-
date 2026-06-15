# Primitive Collector — NodeJS_ChildProcess_Atomic

**Architecture:** 6 — Primitive Collector  
**Author:** Ala Dabat | MTDF 2026  
**MITRE ATT&CK:** T1059.007 — JavaScript / Node.js  
**Platform:** MDE Advanced Hunting  
**Lifecycle:** Permanent — silent 30-day rolling index  

---

## Purpose

Silent baseline index of every Node.js child process event across the estate. Zero inference. Zero scoring. All rows preserved.

This is the forensic foundation — not an alert. It exists to enable retrospective incident stitching when a composite sensor fires and the analyst needs to reconstruct the full attack timeline going back 30 days.

---

## What It Captures

Every instance of `node.exe` or `node` spawning a child process that is not a known-legitimate Node.js toolchain binary (npm, yarn, git, webpack etc.).

```
node.exe → bash          ← indexed
node.exe → curl          ← indexed
node.exe → python        ← indexed
node.exe → powershell    ← indexed
node.exe → npm           ← NOT indexed (known-legitimate)
node.exe → node          ← NOT indexed (known-legitimate)
```

---

## When It Is Useful

| Scenario | How this collector helps |
|----------|------------------------|
| Composite sensor fires today | Retrieve 30-day history for DeviceId — when did the attacker first establish access? |
| Hunt query finds a reverse shell | Scope how long the attacker has been active — first seen in primitive index |
| New composite being built | Pre-existing 30-day index means zero detection gap on deployment |
| Incident reconstruction | Timeline of all Node.js children in sequence — full attack narrative |

---

## Entity Keys

| Key | Use |
|-----|-----|
| `DeviceId` | Stitch to composite sensor, network events, file events |
| `AccountName` | Identity thread — lateral movement scope |
| `ChildSHA256` | Artefact thread — dropped payload search |
| `ParentSHA256` | Node.js application identity — which app was exploited |

---

## MTDF Rules Applied

- **No `summarise`** — all rows preserved for timeline reconstruction
- **No `arg_max`** — no deduplication, every event is a data point
- **No threshold** — zero inference, zero gating
- **`sort by Timestamp asc`** — ascending for incident stitching
- **30-day lookback fixed** — never 7 days, always 30

---

## Composite Backing

This collector backs: **NodeJS_SuspiciousChildProcesses** (Architecture 1 Composite)

When the composite fires, the analyst pivots to this collector using `DeviceId` to retrieve the full 30-day context.
