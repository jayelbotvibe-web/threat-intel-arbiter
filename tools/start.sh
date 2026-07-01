#!/bin/bash
# Threat Intel Arbiter — Startup Script
# Starts the MISP VM (VMware) and the arbiter binary.
# Safe to run multiple times — idempotent.

set -e

ARBITER_DIR="/home/niel/projects/threat-intel-arbiter"
VM_PATH="/home/niel/vmware/misp-vm/misp.vmx"
MISP_IP="172.16.146.129"
MISP_KEY="CGRy4XpFiJj66UCjb0rIFGAuROJ06BIieBlSnHko"

echo "══════════════════════════════════════════"
echo "  Threat Intel Arbiter — System Startup"
echo "══════════════════════════════════════════"
echo ""

# ─── MISP VM ───────────────────────────────────────
echo "── MISP VM ──"
if vmrun list 2>/dev/null | grep -q "$VM_PATH"; then
    echo "  VM already running"
else
    # Remove stale locks
    rm -rf "$(dirname "$VM_PATH")"/*.lck 2>/dev/null || true
    echo "  Starting VM..."
    vmrun -T ws start "$VM_PATH" nogui 2>/dev/null
    echo "  VM started (booting...)"
fi

echo "  Waiting for SSH..."
for i in $(seq 1 30); do
    if sshpass -p misp ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 misp@$MISP_IP "hostname" 2>/dev/null | grep -q misp; then
        echo "  SSH ready ($MISP_IP)"
        break
    fi
    [ $i -eq 30 ] && echo "  ⚠ SSH not ready after 60s — continuing"
    sleep 2
done

# Fix DNS + cache on MISP VM (idempotent)
echo "  Fixing MISP DNS + cache..."
sshpass -p misp ssh -o StrictHostKeyChecking=no misp@$MISP_IP "
    echo 'nameserver 8.8.8.8' | sudo tee /etc/resolv.conf > /dev/null
    sudo mkdir -p /var/www/MISP/app/tmp/cache/{persistent,models,views}
    sudo chown -R www-data:www-data /var/www/MISP/app/tmp
    sudo find /var/www/MISP/app/tmp -type d -exec chmod 2775 {} \\;
    sudo systemctl reload apache2 2>/dev/null || true
" 2>/dev/null
echo "  MISP ready"

# ─── Arbiter ───────────────────────────────────────
echo ""
echo "── Arbiter ──"

cd "$ARBITER_DIR"

# Kill any existing arbiter
pkill -f "./arbiter" 2>/dev/null && echo "  Stopped old arbiter" && sleep 1 || true

# Build if binary missing
[ -x arbiter ] || go build -o arbiter ./cmd/arbiter/

# Start
export MISP_API_KEY="${MISP_API_KEY:-$MISP_KEY}"
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
echo "  MISP:       https://$MISP_IP (admin@admin.test / password)"
echo "  Arbiter log: /tmp/arbiter.log"
echo ""
echo "  Stop with:  pkill -f './arbiter'"
echo "  Restore VM: vmrun revertToSnapshot $VM_PATH 'MISP-2.4-Clean-Install'"
echo ""
