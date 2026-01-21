#!/usr/bin/env python3
"""
DEMO 1: Reverse Shell Detection
================================
This demonstrates the core feature: detecting when a network service spawns a shell.

Attack Pattern: Web server (Python/Node.js) -> Shell (bash/sh)
Detection: eBPF monitors process lineage and sends SIGKILL

Expected Result: The bash process will be KILLED immediately.
"""
import subprocess
import os

print("="*60)
print("DEMO 1: REVERSE SHELL DETECTION")
print("="*60)
print()
print("Attack: Simulating a web server spawning a shell")
print("This mimics command injection or reverse shell attack")
print()
print("Command: python3 -c 'import os; os.system(\"bash -c echo pwned\")'")
print()
print("-"*60)

# Simulate: Python (acting as web server) spawning bash
try:
    result = subprocess.run(
        ["python3", "-c", "import os; os.system('bash -c \"echo If you see this, shell was NOT blocked\"')"],
        capture_output=True,
        timeout=5
    )
    
    if result.returncode == -9:
        print("[✓] SUCCESS: Shell process was KILLED by eBPF!")
        print("    The kernel detected python3 -> bash lineage")
        print("    and sent SIGKILL before the shell could execute.")
    else:
        print(f"[!] Exit code: {result.returncode}")
        print(f"    Output: {result.stdout.decode()}")
        
except Exception as e:
    print(f"Error: {e}")

print()
print("-"*60)
print("Check the dashboard for a CRITICAL event with:")
print("  - Process: bash")
print("  - Parent: python3")
print("  - Threat Level: CRITICAL (Red)")
print("="*60)
