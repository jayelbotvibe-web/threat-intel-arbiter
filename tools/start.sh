#!/bin/bash
# Threat Intel Arbiter — Startup Script
# Starts the MISP VM (VMware) and the arbiter binary.
# Safe to run multiple times — idempotent.

set -e

ARBITER_DIR="/home/niel/projects/threat-intel-arbiter"
VM_PATH="/home/niel/vmware/misp-vm/misp.vmx"

echo "══════════════════════════════════════════"
echo "  Threat Intel Arbiter — System Startup"
echo "══════════════════════════════════════════"
echo ""

# ─── MISP VM ───────────────────────────────────────
echo "── MISP VM ──"
if vmrun list 2>/dev/null | grep -q "$VM_PATH"; then
    echo "  VM already running"
else
    echo "  Starting VM..."
    vmrun -T ws start "$VM_PATH" nogui 2>/dev/null
    echo "  VM started (booting...)"
fi

echo "  Waiting for SSH..."
for i in $(seq 1 30); do
    if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 misp@172.16.146.129 "hostname" 2>/dev/null | grep -q misp; then
        echo "  SSH ready (172.16.146.129)"
        break
    fi
    [ $i -eq 30 ] && echo "  ⚠ SSH not ready after 60s — continuing"
    sleep 2
done

# ─── Arbiter ───────────────────────────────────────
echo ""
echo "── Arbiter ──"

cd "$ARBITER_DIR"

# Kill any existing arbiter
pkill -f "./arbiter" 2>/dev/null && echo "  Stopped old arbiter" || true

# Clean old DB if needed (comment out to preserve state)
# rm -f data/arbiter.db

# Build if binary missing
[ -x arbiter ] || go build -o arbiter ./cmd/arbiter/

# Start
export MISP_API_KEY="${MISP_API_KEY:-your-misp-key}"
export ARBITER_ADMIN_KEY="${ARBITER_ADMIN_KEY:-demo}"

nohup ./arbiter -key="$ARBITER_ADMIN_KEY" > /tmp/arbiter.log 2>&1 &
sleep 2

if pgrep -f "./arbiter" > /dev/null; then
    echo "  Arbiter started (PID: $(pgrep -f "./arbiter"))"
else
    echo "  ⚠ Arbiter failed to start — check /tmp/arbiter.log"
    exit 1
fi

# ─── Status ────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════"
echo "  System running"
echo "══════════════════════════════════════════"
echo ""
echo "  Dashboard:  http://localhost:8080"
echo "  MISP VM:    172.16.146.129"
echo "  Arbiter log: /tmp/arbiter.log"
echo ""
echo "  Stop with:  pkill -f './arbiter'"
echo ""
