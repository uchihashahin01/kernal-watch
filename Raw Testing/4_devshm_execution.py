#!/usr/bin/env python3
"""
DEMO 4: /dev/shm Execution Blocking
====================================
This demonstrates blocking execution from RAM-based filesystem.

Attack Pattern: Truly fileless - execute from RAM (no disk trace)
Detection: eBPF checks execution path and blocks /dev/shm/*

Expected Result: The script in /dev/shm will be KILLED.
"""
import subprocess
import os

print("="*60)
print("DEMO 4: /dev/shm EXECUTION BLOCKING (RAM-BASED)")
print("="*60)
print()
print("Attack: Executing from /dev/shm (RAM filesystem)")
print("This leaves NO trace on disk - truly fileless!")
print()
print("-"*60)

# Create a test script in /dev/shm
test_script = "/dev/shm/stealth_payload.sh"
try:
    with open(test_script, 'w') as f:
        f.write("#!/bin/bash\necho 'Executing from RAM!'\n")
    os.chmod(test_script, 0o755)
    
    print(f"Created: {test_script}")
    print("Attempting to execute...")
    print()
    
    result = subprocess.run([test_script], capture_output=True, timeout=5)
    
    if result.returncode == -9:
        print("[✓] SUCCESS: Process was KILLED by eBPF!")
        print("    Execution from /dev/shm is blocked at kernel level.")
    else:
        print(f"[!] Exit code: {result.returncode}")
        print(f"    Output: {result.stdout.decode()}")
        
except Exception as e:
    print(f"Error: {e}")
finally:
    # Cleanup
    if os.path.exists(test_script):
        os.remove(test_script)
        print(f"\nCleanup: Removed {test_script}")

print()
print("-"*60)
print("Check the dashboard for a CRITICAL event with:")
print("  - Path: /dev/shm/stealth_payload.sh")
print("  - Threat Level: CRITICAL (Red)")
print("  - Status: BLOCKED")
print("="*60)
