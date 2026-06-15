# Composite Sensor — PHP_exec_Abuse

**Architecture:** 1 — Composite Sensor  
**Author:** Ala Dabat | MTDF 2026  
**MITRE ATT&CK:** T1059.004 — Unix Shell  
**Platform:** MDE Advanced Hunting — Linux + Windows  
**Lifecycle:** Production-Candidate (ADX validation pending)  
**Base Score:** 55 · **Threshold:** ≥ 75  
**Anchoring:** Intent-First  

---

## Purpose

High-confidence production alert for PHP application RCE via child process abuse. Fires when a PHP process (`php`, `php-fpm`, `php-cgi`) spawns a shell, downloader, or interpreter — the telemetric footprint common to webshell execution, command injection, and deserialisation attacks.

---

## Why Composite and Not Router Rule

PHP child process abuse has a **single noise domain**: web server worker processes.

Apache/Nginx spawn PHP via FastCGI — they do not spawn shells. `php-fpm` workers handle HTTP requests — they do not spawn downloaders. The suppression model is consistent: local dev environments (XAMPP, WAMP) and known development accounts receive a soft penalty. There is no second noise domain requiring separate composite sensors.

**Single noise domain → composite, not router.**

Compare this to Java (router rule) where Tomcat, Kafka, Elasticsearch, and Jenkins all have different legitimate child process profiles requiring separate suppression models.

---

## Attack Vectors Covered

| Attack Type | Example | Telemetry |
|-------------|---------|-----------|
| Webshell via file upload | `system($_GET['cmd'])` in uploaded `.php` | php-fpm → bash |
| Command injection via `exec()` | `exec('ping ' . $_GET['host'])` | php → bash with user input |
| LFI → RCE | Log poisoning → include malicious PHP | php → curl |
| PHP deserialisation | `unserialize()` with crafted object | php → bash |
| RFI (Remote File Inclusion) | `include($_GET['page'])` with http:// | php-fpm → bash |

---

## Unique Signal — `HasWebshellArg`

This composite includes a PHP-specific signal not present in the Node.js or Python rules:

```
HasWebshellArg — PHP superglobal in parent command line
Triggers on: system($_GET, exec($_POST, passthru($_REQUEST
```

When the PHP parent process command line contains PHP superglobals (`$_GET`, `$_POST`, `$_REQUEST`) alongside dangerous functions (`system()`, `exec()`, `passthru()`), this is a webshell execution pattern. This signal scores +20 and provides a direct connection between the child process and the exploit mechanism.

---

## Scoring

| Signal | Score | Why |
|--------|-------|-----|
| Base (minimum truth) | +55 | php-fpm → shell = structural RCE truth |
| Reverse shell pattern | +30 | `/dev/tcp/` = near-certain C2 |
| Windows PowerShell cradle | +30 | IEX from PHP = Windows IIS RCE |
| Pipe-to-shell | +25 | Download-and-execute chain |
| Remote URL | +20 | External staging |
| Webshell superglobal arg | +20 | PHP-specific webshell indicator |
| Base64/encoded payload | +15 | Obfuscation |
| Dev environment (XAMPP/WAMP) | -20 | Soft penalty |

---

## When It Fires

- `php-fpm` spawns `bash` with `/dev/tcp/` in the command line → **CRITICAL (85)**
- `php` spawns `curl` with a remote URL → **MEDIUM (75)**
- `php` spawns `bash` with `| sh` in the command line → **HIGH (80)**
- `php.exe` spawns `powershell.exe` with `IEX DownloadString` → **CRITICAL (85)**

---

## Post-Alert Investigation

```
1. Search web root for recently modified .php files
   DeviceFileEvents | where FileName endswith ".php" | where ActionType == "FileModified"

2. Check web server access logs for the exploit request
   Look for $_GET/POST parameters containing shell commands

3. Pivot DeviceNetworkEvents on DeviceId to find C2 connections

4. Search for dropped payloads
   DeviceFileEvents | where SHA256 == [ChildSHA256]
```

---

## Noise Sources

| Source | Description | Mitigation |
|--------|-------------|------------|
| XAMPP/WAMP local dev | Developers spawn shells from PHP | -20 soft penalty via `IsDevContext` |
| PHP CLI scripts | Admin scripts using `exec()` | Scope by `AccountName` in Q10 |
| Package installation | Composer post-install scripts | Covered by `LegitPHPChildren` |

---

## Ecosystem Position

```
Web Application Runtime RCE Family:
NodeJS_SuspiciousChildProcesses  ✅
PHP_exec_Abuse                   ✅ (this rule)
Python_subprocess_Abuse          ✅
Java_Runtime_Exec_Abuse          🔴 Router → 4 pending composites
```
