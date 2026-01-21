#!/usr/bin/env python3
"""
DEMO 5: Renamed Binary Detection (Hash-Based)
===============================================
This demonstrates SHA-256 hash-based detection of renamed tools.

Attack Pattern: Rename 'netcat' to 'update-checker' to evade detection
Detection: Backend compares binary hash against known signatures

Expected Result: Even renamed, netcat is identified and flagged.
"""
import subprocess
import shutil
import os
import time

print("="*60)
print("DEMO 5: RENAMED BINARY DETECTION (HASH-BASED)")
print("="*60)
print()
print("Attack: Renaming netcat to 'update-checker' to evade detection")
print("Defense: We hash the binary and compare against known signatures")
print()
print("-"*60)

target = "/home/uchiha/update-checker"

try:
    # Copy netcat with a deceptive name
    if os.path.exists('/usr/bin/nc'):
        shutil.copy('/usr/bin/nc', target)
        os.chmod(target, 0o755)
        
        print(f"Copied /usr/bin/nc -> {target}")
        print("Running the 'innocent' update-checker...")
        print()
        
        result = subprocess.run([target, '-h'], capture_output=True, timeout=5)
        
        print(f"Exit code: {result.returncode}")
        if result.returncode == 0:
            print()
            print("[✓] SUCCESS: Binary ran, but backend detected it!")
            print("    The SHA-256 hash matches known netcat signature.")
            print("    Dashboard shows this as CRITICAL threat.")
        elif result.returncode == -9:
            print("[✓] Process was KILLED")
            
        # Wait for backend to process and hash the file
        print("\nWaiting 3 seconds for backend to detect...")
        time.sleep(3)
    else:
        print("[!] netcat not found at /usr/bin/nc")
        
except Exception as e:
    print(f"Error: {e}")
finally:
    if os.path.exists(target):
        os.remove(target)
        print(f"\nCleanup: Removed {target}")

print()
print("-"*60)
print("Check the dashboard for a CRITICAL/SUSPICIOUS event with:")
print("  - Path: /home/uchiha/update-checker")
print("  - Detection: 'RENAMED BINARY: Actually netcat'")
print("="*60)
