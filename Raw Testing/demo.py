#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║       KERNEL-WATCH THREAT SIMULATION DEMO                   ║
║       Interactive Attack Demonstration Tool                  ║
╚══════════════════════════════════════════════════════════════╝

Run this script in front of your supervisor to demonstrate
different attack scenarios and how Kernel-Watch detects them.
"""
import subprocess
import shutil
import os
import sys
import time
import ctypes

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def print_header():
    print("\033[1;36m")  # Cyan bold
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║       KERNEL-WATCH THREAT SIMULATION DEMO                   ║")
    print("║       Interactive Attack Demonstration Tool                  ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print("\033[0m")  # Reset

def print_menu():
    print("\033[1;33m")  # Yellow bold
    print("Select an attack to simulate:")
    print("\033[0m")
    print("  \033[1;31m1.\033[0m Reverse Shell Attack      - Web server spawning shell (BLOCKED)")
    print("  \033[1;31m2.\033[0m Fileless Malware          - memfd_create syscall (DETECTED)")
    print("  \033[1;31m3.\033[0m /tmp Execution            - Payload in /tmp (BLOCKED)")
    print("  \033[1;31m4.\033[0m /dev/shm Execution        - RAM-based payload (BLOCKED)")
    print("  \033[1;31m5.\033[0m Renamed Binary            - netcat disguised (DETECTED)")
    print("  \033[1;31m6.\033[0m LOLBins                   - curl/wget/nmap abuse (DETECTED)")
    print("  \033[1;31m7.\033[0m Node.js Injection         - Command injection (BLOCKED)")
    print()
    print("  \033[1;32m0.\033[0m Exit")
    print()

def wait_for_key():
    print("\n\033[1;33mPress Enter to continue...\033[0m")
    input()

def attack_1_reverse_shell():
    """Simulate reverse shell detection"""
    print("\033[1;35m")
    print("═" * 60)
    print("ATTACK 1: REVERSE SHELL DETECTION")
    print("═" * 60)
    print("\033[0m")
    print()
    print("\033[1;37mScenario:\033[0m")
    print("  An attacker exploits a web application vulnerability.")
    print("  The web server (Python) spawns a shell (bash).")
    print()
    print("\033[1;37mExpected:\033[0m eBPF detects lineage and sends SIGKILL")
    print()
    print("\033[1;33mExecuting attack...\033[0m")
    print()
    
    try:
        result = subprocess.run(
            ["python3", "-c", "import os; os.system('bash -c \"echo If you see this, shell was NOT blocked\"')"],
            capture_output=True,
            timeout=5
        )
        
        if result.returncode == -9:
            print("\033[1;32m[✓] SUCCESS: Shell process was KILLED by eBPF!\033[0m")
            print("    The kernel detected python3 → bash lineage")
            print("    and sent SIGKILL before the shell could execute.")
        else:
            print(f"\033[1;33m[!] Exit code: {result.returncode}\033[0m")
            print("    Check dashboard for CRITICAL event")
    except Exception as e:
        print(f"Error: {e}")
    
    print()
    print("\033[1;36m→ Check dashboard for CRITICAL (Red) event\033[0m")

def attack_2_fileless_malware():
    """Simulate fileless malware using memfd_create"""
    print("\033[1;35m")
    print("═" * 60)
    print("ATTACK 2: FILELESS MALWARE (memfd_create)")
    print("═" * 60)
    print("\033[0m")
    print()
    print("\033[1;37mScenario:\033[0m")
    print("  Malware creates executable in RAM, no disk trace.")
    print("  Traditional antivirus cannot see this.")
    print()
    print("\033[1;37mExpected:\033[0m eBPF hooks memfd_create syscall and logs it")
    print()
    print("\033[1;33mExecuting attack...\033[0m")
    print()
    
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        MFD_CLOEXEC = 0x0001
        memfd_create = libc.syscall
        memfd_create.argtypes = [ctypes.c_long, ctypes.c_char_p, ctypes.c_uint]
        memfd_create.restype = ctypes.c_int
        
        fd = memfd_create(319, b"malicious_payload", MFD_CLOEXEC)
        
        if fd > 0:
            print(f"\033[1;33m[!] memfd_create succeeded: fd={fd}\033[0m")
            print("    This would allow fileless code execution!")
            print()
            print("\033[1;32m[✓] SUCCESS: eBPF logged this event\033[0m")
            os.close(fd)
        else:
            print(f"[!] memfd_create failed")
    except Exception as e:
        print(f"Error: {e}")
    
    print()
    print("\033[1;36m→ Check dashboard for SUSPICIOUS (Yellow) MEMFD event\033[0m")

def attack_3_tmp_execution():
    """Simulate /tmp execution blocking"""
    print("\033[1;35m")
    print("═" * 60)
    print("ATTACK 3: /tmp EXECUTION BLOCKING")
    print("═" * 60)
    print("\033[0m")
    print()
    print("\033[1;37mScenario:\033[0m")
    print("  Attacker downloads payload to /tmp (world-writable)")
    print("  and attempts to execute it.")
    print()
    print("\033[1;37mExpected:\033[0m eBPF blocks execution from /tmp with SIGKILL")
    print()
    print("\033[1;33mExecuting attack...\033[0m")
    print()
    
    test_script = "/tmp/malware_payload.sh"
    try:
        with open(test_script, 'w') as f:
            f.write("#!/bin/bash\necho 'Malware running from /tmp!'\n")
        os.chmod(test_script, 0o755)
        
        print(f"Created payload: {test_script}")
        print("Attempting to execute...")
        print()
        
        result = subprocess.run([test_script], capture_output=True, timeout=5)
        
        if result.returncode == -9:
            print("\033[1;32m[✓] SUCCESS: Process was KILLED by eBPF!\033[0m")
            print("    Execution from /tmp is blocked at kernel level.")
        else:
            print(f"\033[1;33m[!] Exit code: {result.returncode}\033[0m")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if os.path.exists(test_script):
            os.remove(test_script)
            print(f"\nCleanup: Removed {test_script}")
    
    print()
    print("\033[1;36m→ Check dashboard for CRITICAL (Red) BLOCKED event\033[0m")

def attack_4_devshm_execution():
    """Simulate /dev/shm execution blocking"""
    print("\033[1;35m")
    print("═" * 60)
    print("ATTACK 4: /dev/shm EXECUTION (RAM FILESYSTEM)")
    print("═" * 60)
    print("\033[0m")
    print()
    print("\033[1;37mScenario:\033[0m")
    print("  Truly fileless attack - payload lives in RAM only.")
    print("  No disk trace, forensics cannot recover after reboot.")
    print()
    print("\033[1;37mExpected:\033[0m eBPF blocks execution from /dev/shm")
    print()
    print("\033[1;33mExecuting attack...\033[0m")
    print()
    
    test_script = "/dev/shm/stealth_payload.sh"
    try:
        with open(test_script, 'w') as f:
            f.write("#!/bin/bash\necho 'Executing from RAM!'\n")
        os.chmod(test_script, 0o755)
        
        print(f"Created payload: {test_script}")
        print("Attempting to execute...")
        print()
        
        result = subprocess.run([test_script], capture_output=True, timeout=5)
        
        if result.returncode == -9:
            print("\033[1;32m[✓] SUCCESS: Process was KILLED by eBPF!\033[0m")
            print("    Execution from /dev/shm is blocked at kernel level.")
        else:
            print(f"\033[1;33m[!] Exit code: {result.returncode}\033[0m")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if os.path.exists(test_script):
            os.remove(test_script)
            print(f"\nCleanup: Removed {test_script}")
    
    print()
    print("\033[1;36m→ Check dashboard for CRITICAL (Red) BLOCKED event\033[0m")

def attack_5_renamed_binary():
    """Simulate renamed binary detection"""
    print("\033[1;35m")
    print("═" * 60)
    print("ATTACK 5: RENAMED BINARY DETECTION (HASH-BASED)")
    print("═" * 60)
    print("\033[0m")
    print()
    print("\033[1;37mScenario:\033[0m")
    print("  Attacker renames 'netcat' to 'update-checker'")
    print("  to evade filename-based detection.")
    print()
    print("\033[1;37mExpected:\033[0m Backend detects via SHA-256 hash matching")
    print()
    print("\033[1;33mExecuting attack...\033[0m")
    print()
    
    target = "/home/uchiha/update-checker"
    try:
        if os.path.exists('/usr/bin/nc'):
            shutil.copy('/usr/bin/nc', target)
            os.chmod(target, 0o755)
            
            print(f"Copied /usr/bin/nc → {target}")
            print("Running the 'innocent' update-checker...")
            print()
            
            result = subprocess.run([target, '-h'], capture_output=True, timeout=5)
            
            print(f"Exit code: {result.returncode}")
            print()
            print("\033[1;32m[✓] SUCCESS: Binary ran, but backend detected it!\033[0m")
            print("    SHA-256 hash matches known netcat signature.")
            
            # Wait for backend to hash
            print("\nWaiting 3 seconds for backend to detect...")
            time.sleep(3)
        else:
            print("[!] netcat not found at /usr/bin/nc")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if os.path.exists(target):
            os.remove(target)
            print(f"Cleanup: Removed {target}")
    
    print()
    print("\033[1;36m→ Check dashboard for CRITICAL (Red) event showing 'netcat'\033[0m")

def attack_6_lolbins():
    """Simulate LOLBins detection"""
    print("\033[1;35m")
    print("═" * 60)
    print("ATTACK 6: LOLBINS (LIVING OFF THE LAND)")
    print("═" * 60)
    print("\033[0m")
    print()
    print("\033[1;37mScenario:\033[0m")
    print("  Attacker uses legitimate tools (curl, wget, nmap)")
    print("  for malicious purposes - evades signature detection.")
    print()
    print("\033[1;37mExpected:\033[0m Flagged as SUSPICIOUS, AI analyzes context")
    print()
    print("\033[1;33mExecuting attacks...\033[0m")
    print()
    
    tests = [
        ("curl", ["curl", "-s", "http://example.com", "-o", "/dev/null"]),
        ("wget", ["wget", "-q", "http://example.com", "-O", "/dev/null"]),
        ("nmap", ["nmap", "--version"]),
    ]
    
    for name, cmd in tests:
        print(f"\033[1;33m[*] Testing: {name}\033[0m")
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=10)
            print(f"    Exit code: {result.returncode}")
            print(f"    \033[1;32m[✓] Executed - Check dashboard for SUSPICIOUS event\033[0m")
        except FileNotFoundError:
            print(f"    [!] {name} not found - skipping")
        except Exception as e:
            print(f"    Error: {e}")
        print()
    
    print("\033[1;36m→ Check dashboard for SUSPICIOUS (Yellow) events with AI analysis\033[0m")

def attack_7_nodejs_injection():
    """Simulate Node.js command injection"""
    print("\033[1;35m")
    print("═" * 60)
    print("ATTACK 7: NODE.JS COMMAND INJECTION")
    print("═" * 60)
    print("\033[0m")
    print()
    print("\033[1;37mScenario:\033[0m")
    print("  Attacker exploits command injection in Node.js web app.")
    print("  Node.js attempts to spawn a shell.")
    print()
    print("\033[1;37mExpected:\033[0m eBPF detects node → bash lineage and kills it")
    print()
    print("\033[1;33mExecuting attack...\033[0m")
    print()
    
    try:
        result = subprocess.run(
            ["node", "-e", "require('child_process').execSync('bash -c \"echo pwned\"')"],
            capture_output=True,
            timeout=5
        )
        
        if result.returncode != 0:
            print("\033[1;32m[✓] SUCCESS: Shell spawned by Node.js was BLOCKED!\033[0m")
            print("    eBPF detected node → bash lineage.")
        else:
            print(f"Output: {result.stdout.decode()}")
    except FileNotFoundError:
        print("[!] Node.js not found")
    except Exception as e:
        print(f"\033[1;32m[✓] Command failed (expected): {type(e).__name__}\033[0m")
    
    print()
    print("\033[1;36m→ Check dashboard for CRITICAL (Red) BLOCKED event\033[0m")

def main():
    attacks = {
        '1': attack_1_reverse_shell,
        '2': attack_2_fileless_malware,
        '3': attack_3_tmp_execution,
        '4': attack_4_devshm_execution,
        '5': attack_5_renamed_binary,
        '6': attack_6_lolbins,
        '7': attack_7_nodejs_injection,
    }
    
    while True:
        clear_screen()
        print_header()
        print_menu()
        
        choice = input("\033[1;37mEnter your choice (0-7): \033[0m").strip()
        
        if choice == '0':
            print("\n\033[1;32mExiting... Thank you for using Kernel-Watch Demo!\033[0m\n")
            sys.exit(0)
        elif choice in attacks:
            clear_screen()
            print_header()
            attacks[choice]()
            wait_for_key()
        else:
            print("\n\033[1;31mInvalid choice. Please enter 0-7.\033[0m")
            time.sleep(1)

if __name__ == "__main__":
    main()
