# Kernel-Watch

**Kernel-Watch** is a real-time eBPF security monitoring tool with AI-powered threat analysis.

## Features
- 🔍 **eBPF Monitoring**: Tracks process execution and network connections
- 🛡️ **Threat Defense**: Automatically blocks malicious /tmp executions
- 🤖 **AI Analysis**: Groq Llama 3 70B analyzes suspicious commands
- 🖥️ **Live Dashboard**: Cyberpunk-themed React UI with real-time updates

## Quick Start

### 1. Install Dependencies

```bash
# System dependencies (run once)
./setup_env.sh

# Backend (Node.js)
cd backend && npm install && cd ..

# Frontend (React)
cd frontend && npm install && cd ..
```

### 2. Launch Everything

```bash
./start_all.sh
```

This will:
1. Start the Node.js backend on port 3000
2. Start the React frontend on port 5173
3. Ask for sudo and start the eBPF agent

### 3. Open Dashboard

Visit: **http://localhost:5173**

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   eBPF Agent    │────▶│  Node.js Brain  │────▶│  React Frontend │
│  (watcher.py)   │     │   (server.js)   │     │   (Dashboard)   │
│                 │     │    + Groq AI    │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
     Kernel           HTTP POST + Socket.io      WebSocket
```

## Test the Defense

```bash
# This will be KILLED instantly
/tmp/malware.sh
```

## License
MIT
