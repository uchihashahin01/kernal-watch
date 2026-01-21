#!/usr/bin/env python3
"""
DEMO 3: /tmp Execution Blocking
================================
This demonstrates blocking execution from world-writable directories.

Attack Pattern: Attacker downloads payload to /tmp and executes it
Detection: eBPF checks execution path and blocks /tmp/*

Expected Result: The script in /tmp will be KILLED.
"""
import subprocess
import os

print("="*60)
print("DEMO 3: /tmp EXECUTION BLOCKING")
print("="*60)
print()
print("Attack: Executing a script from /tmp directory")
print("Attackers use /tmp because it's world-writable")
print()
print("-"*60)

# Create a test script in /tmp
test_script = "/tmp/malware_payload.sh"
try:
    with open(test_script, 'w') as f:
        f.write("#!/bin/bash\necho 'Malware running from /tmp!'\n")
    os.chmod(test_script, 0o755)
    
    print(f"Created: {test_script}")
    print("Attempting to execute...")
    print()
    
    result = subprocess.run([test_script], capture_output=True, timeout=5)
    
    if result.returncode == -9:
        print("[✓] SUCCESS: Process was KILLED by eBPF!")
        print("    Execution from /tmp is blocked at kernel level.")
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
print("  - Path: /tmp/malware_payload.sh")
print("  - Threat Level: CRITICAL (Red)")
print("  - Status: BLOCKED")
print("="*60)
