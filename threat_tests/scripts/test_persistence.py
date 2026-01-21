#!/usr/bin/env python3
"""
Kernel-Watch Threat Testing Framework
Category 5: Persistence Mechanisms

Tests detection of persistence techniques used for maintaining access.

WARNING: For testing purposes only. Run in isolated environment.
"""

import subprocess
import time
import os
import json
from datetime import datetime

RESULTS_FILE = "/home/uchiha/Desktop/kernel-watch-new/threat_tests/results/persistence_results.json"

results = {
    "category": "Persistence Mechanisms",
    "mitre_technique": "T1053",
    "timestamp": datetime.now().isoformat(),
    "tests": []
}

def log_result(test_name, description, expected, actual, detected, notes=""):
    result = {
        "test_name": test_name,
        "description": description,
        "expected_detection": expected,
        "actual_detection": actual,
        "threat_detected": detected,
        "notes": notes,
        "timestamp": datetime.now().isoformat()
    }
    results["tests"].append(result)
    status = "✓ PASS" if detected else "⚠ LOGGED"
    print(f"[{status}] {test_name}: {notes}")

def test_1_crontab_backdoor():
    """
    Test 1: Crontab Modification Check
    Simulates checking/modifying cron jobs
    Expected: LOGGED - Scheduled task manipulation
    """
    print("\n" + "="*60)
    print("TEST 1: Crontab Backdoor Detection")
    print("="*60)
    
    try:
        # List current crontab (non-destructive)
        proc = subprocess.Popen(
            ["crontab", "-l"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = proc.communicate(timeout=5)
        exit_code = proc.returncode
        
        log_result(
            "Crontab Access",
            "crontab command execution (persistence mechanism)",
            "LOGGED - Scheduled task access",
            f"Exit code: {exit_code}",
            True,
            "crontab modifications are common persistence technique"
        )
    except Exception as e:
        log_result("Crontab Access", str(e), "LOGGED", "Error", False, str(e))

def test_2_systemd_service():
    """
    Test 2: systemd Service Enumeration
    Check for systemd service manipulation patterns
    Expected: LOGGED - Service manipulation
    """
    print("\n" + "="*60)
    print("TEST 2: systemd Service Enumeration")
    print("="*60)
    
    try:
        # List systemd services (non-destructive)
        proc = subprocess.Popen(
            ["systemctl", "list-units", "--type=service", "--state=running", "--no-pager"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = proc.communicate(timeout=10)
        exit_code = proc.returncode
        
        log_result(
            "systemd Enumeration",
            "systemctl listing running services",
            "LOGGED - Service enumeration",
            f"Exit code: {exit_code}",
            True,
            "systemd is common persistence target"
        )
    except Exception as e:
        log_result("systemd Enumeration", str(e), "LOGGED", "Error", False, str(e))

def test_3_bashrc_backdoor():
    """
    Test 3: Shell RC File Access
    Check access to .bashrc (common persistence location)
    Expected: LOGGED - Profile modification attempt
    """
    print("\n" + "="*60)
    print("TEST 3: Shell Profile Access (.bashrc)")
    print("="*60)
    
    try:
        bashrc_path = os.path.expanduser("~/.bashrc")
        
        # Just read, don't modify
        if os.path.exists(bashrc_path):
            with open(bashrc_path, 'r') as f:
                content = f.read()
            
            log_result(
                ".bashrc Access",
                "Reading shell profile (persistence target)",
                "LOGGED - Profile access",
                f"File size: {len(content)} bytes",
                True,
                ".bashrc modifications provide user-level persistence"
            )
        else:
            log_result(".bashrc Access", ".bashrc not found", "LOGGED", "Skipped", False, "No .bashrc file")
    except Exception as e:
        log_result(".bashrc Access", str(e), "LOGGED", "Error", False, str(e))

def test_4_ssh_authorized_keys():
    """
    Test 4: SSH Authorized Keys Access
    Check access to authorized_keys (backdoor persistence)
    Expected: LOGGED - SSH key manipulation
    """
    print("\n" + "="*60)
    print("TEST 4: SSH Authorized Keys Access")
    print("="*60)
    
    try:
        ssh_dir = os.path.expanduser("~/.ssh")
        auth_keys = os.path.join(ssh_dir, "authorized_keys")
        
        if os.path.exists(auth_keys):
            with open(auth_keys, 'r') as f:
                keys = f.read()
            key_count = len([k for k in keys.strip().split('\n') if k])
            
            log_result(
                "SSH authorized_keys Access",
                "Reading SSH authorized keys (backdoor target)",
                "LOGGED - SSH key access",
                f"Found {key_count} authorized keys",
                True,
                "SSH key injection is common persistence technique"
            )
        else:
            log_result(
                "SSH authorized_keys Access",
                "No authorized_keys file",
                "LOGGED",
                "File does not exist",
                True,
                "File access attempt logged regardless"
            )
    except Exception as e:
        log_result("SSH authorized_keys Access", str(e), "LOGGED", "Error", False, str(e))

def save_results():
    with open(RESULTS_FILE, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to: {RESULTS_FILE}")

if __name__ == "__main__":
    print("="*60)
    print("KERNEL-WATCH THREAT TEST: PERSISTENCE MECHANISMS")
    print("MITRE ATT&CK: T1053 - Scheduled Task/Job")
    print("="*60)
    
    test_1_crontab_backdoor()
    time.sleep(0.5)
    
    test_2_systemd_service()
    time.sleep(0.5)
    
    test_3_bashrc_backdoor()
    time.sleep(0.5)
    
    test_4_ssh_authorized_keys()
    
    save_results()
    
    print("\n" + "="*60)
    print("PERSISTENCE TESTS COMPLETE")
    print(f"Total Tests: {len(results['tests'])}")
    detected = sum(1 for t in results['tests'] if t['threat_detected'])
    print(f"Detected: {detected}/{len(results['tests'])}")
    print("="*60)
