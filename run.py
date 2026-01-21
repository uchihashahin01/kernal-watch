#!/usr/bin/env python3
import os
import sys
import subprocess

def main():
    # Check for root privileges
    if os.geteuid() != 0:
        print("Kernel-Watch requires root privileges to attach eBPF probes.")
        print("Attempting to elevate privileges via sudo...")
        
        # Re-run the script with sudo
        args = ['sudo', sys.executable] + sys.argv
        try:
            # Replace current process with sudo process
            os.execvp('sudo', args)
        except Exception as e:
            print(f"Error: Failed to elevate privileges: {e}")
            sys.exit(1)

    # If we are here, we are root
    print("-" * 50)
    print("   KERNEL-WATCH // SECURITY ENGINE STARTING")
    print("-" * 50)
    
    # Import dashboard here to avoid importing it before sudo check
    try:
        import dashboard
        
        # Start the thread
        import threading
        t = threading.Thread(target=dashboard.start_watcher_thread, daemon=True)
        t.start()
        
        print("Starting Web Interface...")
        dashboard.socketio.run(dashboard.app, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
        
    except ImportError as e:
        print(f"Error importing modules: {e}")
        print("Did you run setup_env.sh and install requirements?")
    except KeyboardInterrupt:
        print("\nStopping...")

if __name__ == "__main__":
    main()
