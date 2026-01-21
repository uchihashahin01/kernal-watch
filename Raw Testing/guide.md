# Kernel-Watch Demonstration Guide
## Supervisor Presentation

---

## 📋 Overview

This guide provides step-by-step instructions for demonstrating the Kernel-Watch security monitoring system.

### System Architecture

| Layer | Technology | Function |
|-------|------------|----------|
| **Kernel** | eBPF/C | Real-time syscall monitoring & blocking |
| **Backend** | Node.js | Event processing, AI analysis, database |
| **Frontend** | React | Real-time security dashboard |
| **AI** | Groq/Llama 3.3 | Automated threat analysis |

---

## 🚀 STEP 1: Start the System

```bash
cd /home/uchiha/Desktop/kernel-watch-new
./start_all.sh
```

Wait for: `eBPF loaded. Sentinel Agent Active.`

---

## 🌐 STEP 2: Open Dashboard

Navigate to: `http://localhost:5173`

---

## 🎮 STEP 3: Run Interactive Demo

```bash
cd "/home/uchiha/Desktop/kernel-watch-new/Raw Testing"
python3 demo.py
```

---

## 📌 Demo 1: Reverse Shell Detection (BLOCKED)

**Attack:** Web server (python3) spawns shell (bash)

**How it's blocked:**
> `monitor.c:133` — Checks if shell is spawned by network service → sends SIGKILL

**Explanation to Supervisor:**
> "The eBPF program monitors process lineage. When Python spawns bash, this matches the reverse shell pattern. The kernel sends SIGKILL before the shell can execute any commands."

---

## 📌 Demo 2: Fileless Malware (DETECTED)

**Attack:** Create executable in RAM using memfd_create

**How it's detected:**
> `monitor.c:166` — Hooks `memfd_create` syscall → logs as SUSPICIOUS

**Explanation to Supervisor:**
> "memfd_create() creates an anonymous file in memory. Malware uses this to run code without touching the disk. Traditional antivirus can't see it, but we hook this syscall at the kernel level."

---

## 📌 Demo 3: /tmp Execution (BLOCKED)

**Attack:** Execute payload from /tmp directory

**How it's blocked:**
> `monitor.c:138` — Path check for `/tmp/` prefix → sends SIGKILL

**Explanation to Supervisor:**
> "Attackers download payloads to /tmp because it's world-writable. We block ALL execution from /tmp at the kernel level. The process is killed before it can run."

---

## 📌 Demo 4: /dev/shm Execution (BLOCKED)

**Attack:** Execute from RAM filesystem (truly fileless)

**How it's blocked:**
> `monitor.c:145` — Path check for `/dev/shm` prefix → sends SIGKILL

**Explanation to Supervisor:**
> "/dev/shm is tmpfs - it lives entirely in RAM. There's no disk trace at all. This is the ultimate fileless attack, but we still block it."

---

## 📌 Demo 5: Renamed Binary (DETECTED)

**Attack:** Rename netcat to 'update-checker'

**How it's detected:**
> `server.js:82` — `checkBinaryHash()` computes SHA-256 → matches known signatures

**Explanation to Supervisor:**
> "Attackers rename dangerous tools to evade detection. We don't rely on filenames - we compute the SHA-256 hash and compare against known signatures. Even renamed, netcat is identified."

---

## 📌 Demo 6: LOLBins (DETECTED)

**Attack:** Use curl/wget/nmap for malicious purposes

**How it's detected:**
> `server.js:239` — `SUSPICIOUS_BINARIES` array → AI analysis triggered

**Explanation to Supervisor:**
> "Living off the Land Binaries are legitimate tools abused by attackers. We don't block them (that would break system updates), but we flag them for AI analysis. The AI explains the risk and recommends action."

---

## 📌 Demo 7: Node.js Injection (BLOCKED)

**Attack:** Node.js spawns bash (command injection)

**How it's blocked:**
> `monitor.c:103+133` — `is_network_service("node")` + shell spawn → SIGKILL

**Explanation to Supervisor:**
> "This is a classic web app vulnerability. When an attacker exploits command injection, Node.js tries to spawn a shell. The eBPF program detects this lineage and kills the shell instantly."

---

## 📊 STEP 4: Show the AI Analysis

1. Click on any **SUSPICIOUS** or **CRITICAL** event
2. The modal shows: Risk Score, Verdict, MITRE ATT&CK ID, Recommendation

**Explanation to Supervisor:**
> "The AI acts as a virtual SOC analyst. It takes raw event data and provides human-readable explanations. Junior analysts don't need deep technical knowledge - the AI guides them."

---

## 🎯 Quick Reference

| Attack | File:Line | How Blocked/Detected |
|--------|-----------|----------------------|
| Reverse Shell | `monitor.c:133` | Lineage check → SIGKILL |
| Fileless | `monitor.c:166` | memfd_create hook → LOG |
| /tmp Exec | `monitor.c:138` | Path check → SIGKILL |
| /dev/shm Exec | `monitor.c:145` | Path check → SIGKILL |
| Renamed Binary | `server.js:82` | SHA-256 hash → FLAG |
| LOLBins | `server.js:239` | Pattern match → AI |
| Node Injection | `monitor.c:103` | Lineage check → SIGKILL |

---

## 🛑 Stopping the System

Press `Ctrl+C` in the terminal running `start_all.sh`.

---

*Generated for Kernel-Watch Supervisor Demonstration*
