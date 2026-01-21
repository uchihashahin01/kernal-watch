# Kernel-Watch Demonstration Guide
## Supervisor Presentation

---

## 📋 Overview

This guide provides step-by-step instructions for demonstrating the Kernel-Watch security monitoring system. Each demonstration shows a different attack category and how the system detects or blocks it.

### What This System Does

| Layer | Technology | Function |
|-------|------------|----------|
| **Kernel** | eBPF/C | Real-time syscall monitoring & blocking |
| **Backend** | Node.js | Event processing, AI analysis, database |
| **Frontend** | React | Real-time security dashboard |
| **AI** | Groq/Llama 3.3 | Automated threat analysis |

---

## 🚀 STEP 1: Start the System

Open a terminal and run:

```bash
cd /home/uchiha/Desktop/kernel-watch-new
./start_all.sh
```

**Wait for these messages:**
```
[✓] Backend running
[✓] Frontend running
eBPF loaded. Sentinel Agent Active.
```

**Enter your sudo password when prompted** (eBPF requires root).

---

## 🌐 STEP 2: Open the Dashboard

Open your web browser and navigate to:

```
http://localhost:5173
```

**You should see:**
- "SYSTEM ONLINE" (green badge)
- "Backend: Connected"
- Live event stream on the left

**Keep this dashboard visible during all demonstrations.**

---

## 🧪 STEP 3: Run the Demonstrations

Open a **second terminal** for running the test scripts.

### Demo Categories

| # | File | Attack Type | Expected Result |
|---|------|-------------|-----------------|
| 1 | `1_reverse_shell.py` | Reverse Shell | **BLOCKED** (SIGKILL) |
| 2 | `2_fileless_malware.py` | Fileless Malware | **DETECTED** (memfd) |
| 3 | `3_tmp_execution.py` | /tmp Execution | **BLOCKED** (SIGKILL) |
| 4 | `4_devshm_execution.py` | /dev/shm Execution | **BLOCKED** (SIGKILL) |
| 5 | `5_renamed_binary.py` | Renamed Binary | **DETECTED** (Hash) |
| 6 | `6_lolbins.py` | LOLBins | **DETECTED** (AI) |
| 7 | `7_nodejs_injection.py` | Command Injection | **BLOCKED** (SIGKILL) |

---

## 📌 Demo 1: Reverse Shell Detection

**What it demonstrates:** Detection of network service spawning a shell.

**Attack Pattern:**
```
Web Server (python3) → Shell (bash)
```

**Run the test:**
```bash
cd "/home/uchiha/Desktop/kernel-watch-new/Raw Testing"
python3 1_reverse_shell.py
```

**Expected Output:**
```
[✓] SUCCESS: Shell process was KILLED by eBPF!
```

**On Dashboard:**
- Event Type: `EXEC`
- Process: `bash`
- Parent: `python3`
- Badge: **CRITICAL** (Red)

**Explanation to Supervisor:**
> "The eBPF program monitors process lineage. When Python spawns bash, this matches the reverse shell pattern. The kernel sends SIGKILL before the shell can execute any commands."

---

## 📌 Demo 2: Fileless Malware Detection

**What it demonstrates:** Detection of `memfd_create` syscall abuse.

**Attack Pattern:**
```
Create executable in RAM → Execute without disk trace
```

**Run the test:**
```bash
python3 2_fileless_malware.py
```

**Expected Output:**
```
[!] memfd_create succeeded: fd=X
[✓] SUCCESS: eBPF should have logged this event
```

**On Dashboard:**
- Event Type: `MEMFD`
- Process: `python3`
- Badge: **SUSPICIOUS** (Yellow)

**Explanation to Supervisor:**
> "memfd_create() creates an anonymous file in memory. Malware uses this to run code without touching the disk. Traditional antivirus can't see it, but we hook this syscall at the kernel level."

---

## 📌 Demo 3: /tmp Execution Blocking

**What it demonstrates:** Blocking execution from world-writable directories.

**Attack Pattern:**
```
Download payload to /tmp → Execute it
```

**Run the test:**
```bash
python3 3_tmp_execution.py
```

**Expected Output:**
```
[✓] SUCCESS: Process was KILLED by eBPF!
    Execution from /tmp is blocked at kernel level.
```

**On Dashboard:**
- Path: `/tmp/malware_payload.sh`
- Badge: **CRITICAL** (Red)
- Status: BLOCKED

**Explanation to Supervisor:**
> "Attackers download payloads to /tmp because it's world-writable. We block ALL execution from /tmp at the kernel level. The process is killed before it can run."

---

## 📌 Demo 4: /dev/shm Execution Blocking

**What it demonstrates:** Blocking execution from RAM filesystem.

**Attack Pattern:**
```
Create payload in RAM → Execute (truly fileless)
```

**Run the test:**
```bash
python3 4_devshm_execution.py
```

**Expected Output:**
```
[✓] SUCCESS: Process was KILLED by eBPF!
    Execution from /dev/shm is blocked at kernel level.
```

**On Dashboard:**
- Path: `/dev/shm/stealth_payload.sh`
- Badge: **CRITICAL** (Red)

**Explanation to Supervisor:**
> "/dev/shm is tmpfs - it lives entirely in RAM. There's no disk trace at all. This is the ultimate fileless attack, but we still block it."

---

## 📌 Demo 5: Renamed Binary Detection

**What it demonstrates:** SHA-256 hash-based detection of renamed tools.

**Attack Pattern:**
```
Rename 'netcat' to 'update-checker' → Evade name-based detection
```

**Run the test:**
```bash
python3 5_renamed_binary.py
```

**Expected Output:**
```
[✓] SUCCESS: Binary ran, but backend detected it!
    The SHA-256 hash matches known netcat signature.
```

**On Dashboard:**
- Path: `/home/uchiha/update-checker`
- Badge: **CRITICAL** (Red)

**Explanation to Supervisor:**
> "Attackers rename dangerous tools to evade detection. We don't rely on filenames - we compute the SHA-256 hash and compare against known signatures. Even renamed, netcat is identified."

---

## 📌 Demo 6: LOLBins Detection

**What it demonstrates:** Detection of legitimate tools abused for attacks.

**Attack Pattern:**
```
Use curl/wget/nmap for malicious purposes
```

**Run the test:**
```bash
python3 6_lolbins.py
```

**Expected Output:**
```
[✓] Executed - Check dashboard for SUSPICIOUS event
```

**On Dashboard:**
- Process: `curl`, `wget`, `nmap`
- Badge: **SUSPICIOUS** (Yellow)
- AI Analysis provided

**Explanation to Supervisor:**
> "Living off the Land Binaries are legitimate tools abused by attackers. We don't block them (that would break system updates), but we flag them for AI analysis. The AI explains the risk and recommends action."

---

## 📌 Demo 7: Node.js Command Injection

**What it demonstrates:** Web application vulnerability exploitation.

**Attack Pattern:**
```
Node.js server → execSync('bash') → Command execution
```

**Run the test:**
```bash
python3 7_nodejs_injection.py
```

**Expected Output:**
```
[✓] SUCCESS: Shell spawned by Node.js was blocked!
```

**On Dashboard:**
- Process: `bash`
- Parent: `node`
- Badge: **CRITICAL** (Red)

**Explanation to Supervisor:**
> "This is a classic web app vulnerability. When an attacker exploits command injection, Node.js tries to spawn a shell. The eBPF program detects this lineage and kills the shell instantly."

---

## 📊 STEP 4: Show the AI Analysis

1. Click on any **SUSPICIOUS** or **CRITICAL** event in the dashboard
2. The modal shows AI analysis including:
   - **Risk Score:** 1-10
   - **Verdict:** SAFE/SUSPICIOUS/MALICIOUS
   - **MITRE ATT&CK:** Technique ID (e.g., T1059.004)
   - **Recommendation:** Action to take

**Explanation to Supervisor:**
> "The AI acts as a virtual SOC analyst. It takes raw event data and provides human-readable explanations. Junior analysts don't need deep technical knowledge - the AI guides them."

---

## 📜 STEP 5: Show Event History

1. Click the **Database icon** in the top navigation
2. Shows paginated history of all events
3. Filter by severity or type
4. Export to CSV for SIEM integration

**Explanation to Supervisor:**
> "Every event is persisted to SQLite. If an incident happened yesterday, we can trace the full attack chain. CSV export allows integration with enterprise SIEMs."

---

## ⚙️ STEP 6: Show Dynamic Whitelist

1. Click **Settings** gear icon
2. Go to **Whitelist Configuration**
3. Show adding/removing processes

**Explanation to Supervisor:**
> "If there's a false positive, analysts can whitelist it instantly without restarting the system. Changes take effect immediately."

---

## 🔄 Run All Tests at Once

For a complete demonstration of all categories:

```bash
cd /home/uchiha/Desktop/kernel-watch-new/threat_tests
python3 run_all_tests.py
```

This runs **26 tests** across 6 categories and generates a comprehensive report.

---

## 📈 Key Statistics to Mention

| Metric | Value |
|--------|-------|
| Total Tests | 26 |
| Detection Rate | **92.3%** |
| Processes Blocked | 2-4 (depending on test) |
| MITRE Techniques Covered | 6 |

---

## 🎯 Summary of Capabilities

| Threat Category | Detection Method | Action |
|-----------------|------------------|--------|
| Reverse Shell | Process Lineage | **BLOCKED** |
| Fileless Malware | memfd_create Hook | DETECTED |
| /tmp Execution | Path Check | **BLOCKED** |
| /dev/shm Execution | Path Check | **BLOCKED** |
| Renamed Binary | SHA-256 Hash | DETECTED |
| LOLBins | Pattern + AI | DETECTED |
| Command Injection | Process Lineage | **BLOCKED** |

---

## 🛑 Stopping the System

When finished, press `Ctrl+C` in the terminal running `start_all.sh`.

---

*Generated for Kernel-Watch Supervisor Demonstration*
