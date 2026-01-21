#!/usr/bin/env python3
from bcc import BPF
import os
import requests
import socket
import struct
import json
import time

# Configuration
INGEST_URL = "http://localhost:3000/api/ingest"

# Helpers
def int_to_ip(ip_int):
    return socket.inet_ntoa(struct.pack("I", ip_int))

def send_to_server(event_data):
    try:
        response = requests.post(INGEST_URL, json=event_data, timeout=1)
    except requests.exceptions.RequestException as e:
        pass

# Initialize BPF
print("Loading eBPF program from monitor.c...")
print("=" * 50)
print("  KERNEL-WATCH // SENTINEL AGENT v2.0")
print("=" * 50)
print("  Features Active:")
print("  ✓ Process Execution Monitoring")
print("  ✓ Network Connection Tracking")
print("  ✓ Fileless Malware Detection (memfd_create)")
print("  ✓ Process Lineage Verification")
print("  ✓ /tmp, /dev/shm, /var/tmp Detection")
print("=" * 50)

try:
    b = BPF(src_file="monitor.c")
except Exception as e:
    print(f"Error compiling eBPF: {e}")
    exit(1)

# Attach probes
execve_fn = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fn, fn_name="syscall__execve")

print("eBPF loaded. Sentinel Agent Active.")
print("Reporting to:", INGEST_URL)
print("-" * 50)

# Event Type Constants
EVENT_EXEC = 1
EVENT_NET = 2
EVENT_MEMFD = 3

# Threat Level Constants
THREAT_SAFE = 0
THREAT_SUSPICIOUS = 1
THREAT_CRITICAL = 2

# Colors for terminal output
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"

def print_event(cpu, data, size):
    event = b["events"].event(data)
    
    evt_json = {
        "pid": event.pid,
        "ppid": event.ppid,
        "comm": event.comm.decode('utf-8', 'replace'),
        "parent_comm": event.parent_comm.decode('utf-8', 'replace'),
        "timestamp": time.time()
    }

    if event.type == EVENT_EXEC:
        evt_json["type"] = "EXEC"
        evt_json["fname"] = event.fname.decode('utf-8', 'replace')
        evt_json["threat_level"] = event.threat_level
        
        if event.threat_level == THREAT_CRITICAL:
            # Check if it's a lineage kill (shell from network service)
            parent = evt_json['parent_comm']
            child = evt_json['comm']
            if child in ['bash', 'sh', 'zsh', 'dash'] and parent in ['node', 'nginx', 'apache', 'php', 'python', 'ruby', 'perl', 'java']:
                print(f"{RED}[!!!] REVERSE SHELL BLOCKED: {parent} → {child} (PID {event.pid}) KILLED{RESET}")
            else:
                print(f"{RED}[!!!] CRITICAL: Process {event.pid} executed {evt_json['fname']} (KILLED){RESET}")
        elif event.threat_level == THREAT_SUSPICIOUS:
            print(f"{YELLOW}[!] SUSPICIOUS: Process {event.pid} executed {evt_json['fname']}{RESET}")
        else:
            print(f"[*] EXEC: {event.pid} {evt_json['comm']} {evt_json['fname']}")

    elif event.type == EVENT_MEMFD:
        evt_json["type"] = "MEMFD"
        evt_json["fname"] = event.fname.decode('utf-8', 'replace')
        evt_json["threat_level"] = event.threat_level
        
        if event.threat_level == THREAT_CRITICAL:
            print(f"{RED}[!!!] FILELESS MALWARE BLOCKED: memfd_create by {evt_json['comm']} (parent: {evt_json['parent_comm']}) KILLED{RESET}")
        else:
            print(f"{MAGENTA}[!] MEMFD: Process {event.pid} ({evt_json['comm']}) created memory file: {evt_json['fname']}{RESET}")

    elif event.type == EVENT_NET:
        evt_json["type"] = "NET"
        evt_json["dst_ip"] = int_to_ip(event.daddr)
        evt_json["dst_port"] = event.dport
        evt_json["threat_level"] = event.threat_level
        print(f"{CYAN}[*] NET: {event.pid} {evt_json['comm']} -> {evt_json['dst_ip']}:{evt_json['dst_port']}{RESET}")

    # Send to backend
    send_to_server(evt_json)

# Start Polling
b["events"].open_perf_buffer(print_event)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nDetaching and exiting...")
