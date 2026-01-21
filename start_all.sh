#!/bin/bash

# ============================================
#  KERNEL-WATCH // MASTER STARTUP SCRIPT
# ============================================

echo "============================================"
echo "   KERNEL-WATCH // SECURITY SUITE"
echo "============================================"
echo ""

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Cleanup function
cleanup() {
    echo ""
    echo -e "${RED}[!] Shutting down all components...${NC}"
    kill $BACKEND_PID 2>/dev/null
    kill $FRONTEND_PID 2>/dev/null
    echo -e "${GREEN}[✓] Cleanup complete.${NC}"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Check if node_modules exist
if [ ! -d "backend/node_modules" ]; then
    echo -e "${RED}[!] Backend dependencies not installed.${NC}"
    echo "    Run: cd backend && npm install"
    exit 1
fi

if [ ! -d "frontend/node_modules" ]; then
    echo -e "${RED}[!] Frontend dependencies not installed.${NC}"
    echo "    Run: cd frontend && npm install"
    exit 1
fi

# 1. Start Backend
echo -e "${CYAN}[1/3] Starting Node.js Backend...${NC}"
cd backend
node server.js &
BACKEND_PID=$!
cd ..
sleep 2

if kill -0 $BACKEND_PID 2>/dev/null; then
    echo -e "${GREEN}[✓] Backend running (PID: $BACKEND_PID)${NC}"
else
    echo -e "${RED}[✗] Backend failed to start${NC}"
    exit 1
fi

# 2. Start Frontend
echo -e "${CYAN}[2/3] Starting React Frontend...${NC}"
cd frontend
npm run dev -- --host &
FRONTEND_PID=$!
cd ..
sleep 3

if kill -0 $FRONTEND_PID 2>/dev/null; then
    echo -e "${GREEN}[✓] Frontend running (PID: $FRONTEND_PID)${NC}"
else
    echo -e "${RED}[✗] Frontend failed to start${NC}"
    cleanup
fi

echo ""
echo "============================================"
echo -e "${GREEN}  SERVICES RUNNING:${NC}"
echo "  • Backend:  http://localhost:3000"
echo "  • Frontend: http://localhost:5173"
echo "============================================"
echo ""

# 3. Start eBPF Watcher (requires sudo)
echo -e "${CYAN}[3/3] Starting eBPF Watcher (requires sudo)...${NC}"
echo ""
sudo python3 watcher.py

# When watcher exits, cleanup
cleanup
