#!/usr/bin/env python3
"""
Test renamed binary detection.
Copies netcat to a different name and runs it.
"""
import subprocess
import shutil
import os
import time

print("="*60)
print("TEST: Renamed Binary Detection")
print("="*60)
print()
print("Copying /usr/bin/nc to /tmp/update-checker...")

try:
    # Copy netcat to a different name
    shutil.copy('/usr/bin/nc', '/tmp/update-checker')
    os.chmod('/tmp/update-checker', 0o755)
    
    print("Running /tmp/update-checker --version...")
    print("(which is actually netcat in disguise)")
    print()
    
    # Try to run it - should be detected as netcat by hash AND blocked from /tmp
    result = subprocess.run(['/tmp/update-checker', '--version'], 
                          capture_output=True, timeout=5)
    
    print(f"Exit code: {result.returncode}")
    if result.returncode == -9:
        print("[✓] BLOCKED by eBPF (execution from /tmp)")
    else:
        print(f"Output: {result.stderr.decode()[:100]}")
    
except FileNotFoundError:
    print("[!] netcat not found on system")
except Exception as e:
    print(f"Error: {e}")
finally:
    # Cleanup
    try:
        os.remove('/tmp/update-checker')
        print("\nCleanup: removed /tmp/update-checker")
    except:
        pass

print()
print(">>> Check the backend logs for: RENAMED TOOL DETECTED <<<")
print(">>> The system should identify it as netcat by hash <<<")
