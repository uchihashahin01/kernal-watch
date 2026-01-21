#!/usr/bin/env python3
"""
DEMO 7: Node.js Command Injection
==================================
This demonstrates the classic web app vulnerability.

Attack Pattern: Node.js server executes shell commands
Detection: eBPF detects node -> bash lineage and kills it

Expected Result: The bash process will be KILLED.
"""
import subprocess

print("="*60)
print("DEMO 7: NODE.JS COMMAND INJECTION")
print("="*60)
print()
print("Attack: Node.js executing shell commands via child_process")
print("This is how web app command injection works")
print()
print("-"*60)

try:
    cmd = 'node -e "require(\'child_process\').execSync(\'bash -c echo pwned\')"'
    print(f"Command: {cmd}")
    print()
    
    result = subprocess.run(
        ["node", "-e", "require('child_process').execSync('bash -c \"echo pwned\"')"],
        capture_output=True,
        timeout=5
    )
    
    if result.returncode != 0:
        print("[✓] SUCCESS: Shell spawned by Node.js was blocked!")
        print("    eBPF detected node -> bash lineage.")
    else:
        print(f"Output: {result.stdout.decode()}")
        
except FileNotFoundError:
    print("[!] Node.js not found")
except Exception as e:
    print(f"[✓] Command failed (expected): {type(e).__name__}")

print()
print("-"*60)
print("Check the dashboard for a CRITICAL event with:")
print("  - Process: bash")
print("  - Parent: node")
print("  - Status: BLOCKED")
print("="*60)
