#!/bin/bash
# Wait for MISP install, configure arbiter, shutdown
# Prerequisites: SSH access to MISP VM
# Set MISP_IP env var or edit below
set -e

VM_IP="${MISP_IP:-192.168.1.100}"
ARBITER_DIR="${ARBITER_DIR:-$HOME/threat-intel-arbiter}"
ARBITER_HOME="${ARBITER_HOME:-$HOME/.arbiter}"

# Secure log: private directory, umask 077
umask 077
mkdir -p "$ARBITER_HOME"
LOG="$ARBITER_HOME/misp-finish.log"
exec > "$LOG" 2>&1
echo "=== MISP finish script started at $(date) ==="

# Wait for MISP install to finish (max 40 min)
echo "Waiting for MISP install..."
for i in $(seq 1 80); do
    if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 misp@$VM_IP "sudo test -f /var/www/MISP/app/Config/config.php" 2>/dev/null; then
        echo "MISP config found — install complete!"
        break
    fi
    if [ $i -eq 80 ]; then
        echo "Timeout waiting for MISP — trying alternate key fetch"
        # Try to get key even if config.php not found
        API_KEY_FALLBACK=$(ssh misp@$VM_IP "sudo /var/www/MISP/app/Console/cake user authkey admin@admin.test 2>/dev/null | tail -1" || echo "")
        if [ -n "$API_KEY_FALLBACK" ] && [ ${#API_KEY_FALLBACK} -gt 10 ]; then
            echo "Got API key via fallback"
            API_KEY="$API_KEY_FALLBACK"
        else
            echo "No API key found — install may have failed"
            exit 1
        fi
    fi
    sleep 30
done

# Get API key from config.php
if [ -z "$API_KEY" ]; then
    echo "Getting MISP API key..."
    API_KEY=$(ssh misp@$VM_IP "sudo grep -oP \"'AuthKey' => '(.*?)'\" /var/www/MISP/app/Config/config.php | cut -d\"'\" -f4" 2>/dev/null)
    if [ -z "$API_KEY" ]; then
        API_KEY=$(ssh misp@$VM_IP "sudo /var/www/MISP/app/Console/cake user authkey admin@admin.test 2>/dev/null | tail -1" || echo "")
    fi
fi
# Never echo the key — print length confirmation only
echo "API key captured (length: ${#API_KEY})"

# Update arbiter config
echo "Updating arbiter sources.json..."
cd "$ARBITER_DIR"
python3 -c "
import json
cfg = json.load(open('config/sources.json'))
for s in cfg.get('sources', []):
    if s['type'] == 'misp':
        s['url'] = '$VM_IP'  # keep existing scheme (prefer https://)
json.dump(cfg, open('config/sources.json', 'w'), indent=2)
print('Config updated')
"

# Save API key outside repo tree (private, chmod 600)
ENV_FILE="$ARBITER_HOME/misp.env"
echo "export MISP_API_KEY=$API_KEY" > "$ENV_FILE"
chmod 600 "$ENV_FILE"
echo "MISP API key saved to $ENV_FILE"

# Stop arbiter if running
pkill -f "./arbiter" 2>/dev/null || true

# Gracefully shutdown VM
echo "Shutting down MISP VM..."
ssh misp@$VM_IP "sudo shutdown -h now" 2>/dev/null || true
sleep 5

# Shutdown host
echo "=== Done at $(date) — shutting down host ==="
sudo shutdown -h now 2>/dev/null || true
