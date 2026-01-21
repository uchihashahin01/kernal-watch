#!/usr/bin/env python3
"""
DEMO 6: LOLBins Detection (Living off the Land)
=================================================
This demonstrates detection of legitimate tools abused by attackers.

Attack Pattern: Use curl/wget/nmap for malicious purposes
Detection: Backend pattern matching + AI analysis

Expected Result: Events flagged as SUSPICIOUS with AI analysis.
"""
import subprocess

print("="*60)
print("DEMO 6: LOLBINS (LIVING OFF THE LAND BINARIES)")
print("="*60)
print()
print("Attack: Using legitimate tools for malicious purposes")
print("These tools are not blocked, but flagged for analysis")
print()
print("-"*60)

tests = [
    ("curl", ["curl", "-s", "http://example.com", "-o", "/dev/null"]),
    ("wget", ["wget", "-q", "http://example.com", "-O", "/dev/null"]),
    ("nmap", ["nmap", "--version"]),
]

for name, cmd in tests:
    print(f"\n[*] Testing: {name}")
    print(f"    Command: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=10)
        print(f"    Exit code: {result.returncode}")
        print(f"    [✓] Executed - Check dashboard for SUSPICIOUS event")
    except FileNotFoundError:
        print(f"    [!] {name} not found - skipping")
    except Exception as e:
        print(f"    Error: {e}")

print()
print("-"*60)
print("Check the dashboard for SUSPICIOUS events with:")
print("  - Process: curl, wget, or nmap")
print("  - AI Analysis explaining the risk")
print("  - These are logged, NOT blocked (legitimate use cases)")
print("="*60)
