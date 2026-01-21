#!/usr/bin/env python3
"""
Test 2: Process Lineage Validation (Reverse Shell Detection)

This script simulates a "reverse shell" scenario where a Python process
(which could be a web server) attempts to spawn a bash shell.

Expected behavior: The eBPF agent should detect that python spawned bash
and KILL it immediately (if python is in the NETWORK_SERVICES list).
"""
import subprocess
import sys
import os

def test_lineage_detection():
    print("=" * 50)
    print("TEST: Process Lineage Validation (Reverse Shell)")
    print("=" * 50)
    print()
    print("Scenario: Python (simulating web server) spawns bash")
    print("This simulates a command injection / reverse shell attack.")
    print()
    print("EXPECTED: eBPF should detect python -> bash and KILL it!")
    print()
    print("Attempting to spawn bash from Python...")
    print("-" * 50)
    
    try:
        # Try to spawn bash - this should be KILLED by eBPF
        result = subprocess.run(
            ['bash', '-c', 'echo "Shell spawned successfully - THIS IS BAD!"'],
            timeout=5,
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            print(f"[!] OUTPUT: {result.stdout}")
            print()
            print("[WARNING] Shell was NOT killed!")
            print("This may be because:")
            print("  1. Python is not in the NETWORK_SERVICES list")
            print("  2. The lineage check is not working")
            print()
            print("Note: In a real attack, the shell WOULD be killed if")
            print("spawned from node, nginx, apache, php, etc.")
            return False
        else:
            print(f"[+] Shell terminated with code: {result.returncode}")
            return True
            
    except subprocess.TimeoutExpired:
        print("[!] Shell timed out (not killed, but not successful)")
        return False
    except Exception as e:
        if "SIGKILL" in str(e) or "137" in str(e):
            print("[+] Shell was KILLED by eBPF! (SIGKILL)")
            return True
        print(f"[+] Shell terminated with error: {e}")
        return True

def test_with_explicit_parent():
    """Test spawning from a simulated node process name"""
    print()
    print("=" * 50)
    print("TEST 2b: Simulating node -> bash scenario")
    print("=" * 50)
    print()
    print("NOTE: To fully test lineage detection, run this from")
    print("a Node.js REPL or Python web server context.")
    print()
    print("Quick test command you can run manually:")
    print()
    print("  node -e \"require('child_process').execSync('bash -c whoami')\"")
    print()
    print("If lineage detection works, bash will be KILLED.")

if __name__ == "__main__":
    test_lineage_detection()
    test_with_explicit_parent()
