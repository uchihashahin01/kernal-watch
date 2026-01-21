#!/usr/bin/env python3
"""
Test 1: Fileless Malware Detection (memfd_create)

This script creates an anonymous in-memory file using memfd_create
and attempts to execute code from it - simulating fileless malware.

Expected behavior: The eBPF agent should detect the memfd_create syscall
and log it as SUSPICIOUS (or KILL if parent is a network service).
"""
import os
import sys
import ctypes

# Load libc
libc = ctypes.CDLL("libc.so.6", use_errno=True)

# Define memfd_create
# int memfd_create(const char *name, unsigned int flags);
libc.memfd_create.argtypes = [ctypes.c_char_p, ctypes.c_uint]
libc.memfd_create.restype = ctypes.c_int

MFD_CLOEXEC = 0x0001

def test_memfd_create():
    print("=" * 50)
    print("TEST: Fileless Malware Detection (memfd_create)")
    print("=" * 50)
    print()
    print("Creating anonymous memory file with memfd_create...")
    print("This simulates fileless malware that never touches disk.")
    print()
    
    # Create an anonymous memory file
    name = b"malicious_payload"
    fd = libc.memfd_create(name, MFD_CLOEXEC)
    
    if fd == -1:
        errno = ctypes.get_errno()
        print(f"[ERROR] memfd_create failed with errno: {errno}")
        return False
    
    print(f"[+] memfd_create succeeded! fd = {fd}")
    print(f"[+] Memory file name: {name.decode()}")
    print()
    print(">>> The eBPF agent should have detected this syscall! <<<")
    print(">>> Check the terminal running start_all.sh for MEMFD event <<<")
    print()
    
    # Clean up
    os.close(fd)
    print("[+] Test complete. Memory file closed.")
    return True

if __name__ == "__main__":
    test_memfd_create()
