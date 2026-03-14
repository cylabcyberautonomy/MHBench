#!/usr/bin/env bash
#
# bake-image.sh — Boot a qcow2 cloud image with QEMU/KVM, run an Ansible
# playbook against it over SSH, then shut it down so the image is ready
# for upload to OpenStack Glance.
#
# Usage:
#   ./bake-image.sh <image.qcow2> <playbook.yml> [--inventory extras.ini]
#
# Prerequisites:
#   - qemu-system-x86_64, qemu-img, cloud-localds (cloud-image-utils)
#   - ansible, ansible-playbook
#   - ssh-keygen, ssh-keyscan
#   - KVM support (/dev/kvm accessible)
#
set -euo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────
WORK_DIR="$(mktemp -d /tmp/bake-image.XXXXXX)"
SSH_PORT=""           # Will be auto-assigned
VM_USER="ansible"
VM_PASS="bake-image-temp"   # Temporary password; removed at the end
SSH_KEY="${WORK_DIR}/bake_key"
SEED_ISO="${WORK_DIR}/seed.iso"
VM_RAM="2048"         # MB
VM_CPUS="2"
SSH_TIMEOUT=180       # seconds to wait for SSH
ANSIBLE_EXTRA_ARGS=()

# ─── Argument parsing ────────────────────────────────────────────────────────
usage() {
    cat <<EOF
Usage: $(basename "$0") <image.qcow2> <playbook.yml> [OPTIONS]

Options:
  --inventory, -i FILE   Additional Ansible inventory file
  --extra-vars, -e VARS  Extra variables for Ansible (key=value or @file)
  --ram MB               VM RAM in MB (default: 2048)
  --cpus N               VM CPUs (default: 2)
  --ssh-timeout SECS     Seconds to wait for SSH (default: 180)
  --keep-user            Don't remove the temporary VM user after baking
  --help, -h             Show this help
EOF
    exit 1
}

KEEP_USER=false

[[ $# -lt 2 ]] && usage

IMAGE="$(realpath "$1")"; shift
PLAYBOOK="$(realpath "$1")"; shift

while [[ $# -gt 0 ]]; do
    case "$1" in
        --inventory|-i)   ANSIBLE_EXTRA_ARGS+=("-i" "$2"); shift 2 ;;
        --extra-vars|-e)  ANSIBLE_EXTRA_ARGS+=("-e" "$2"); shift 2 ;;
        --ram)            VM_RAM="$2"; shift 2 ;;
        --cpus)           VM_CPUS="$2"; shift 2 ;;
        --ssh-timeout)    SSH_TIMEOUT="$2"; shift 2 ;;
        --keep-user)      KEEP_USER=true; shift ;;
        --help|-h)        usage ;;
        *)                echo "Unknown option: $1"; usage ;;
    esac
done

# ─── Validation ──────────────────────────────────────────────────────────────
for cmd in qemu-system-x86_64 qemu-img cloud-localds ansible-playbook ssh-keygen ssh-keyscan; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: Required command '$cmd' not found. Please install it."
        echo "  apt install qemu-system-x86 qemu-utils cloud-image-utils ansible openssh-client"
        exit 1
    fi
done

if [[ ! -f "$IMAGE" ]]; then
    echo "ERROR: Image file not found: $IMAGE"
    exit 1
fi

if [[ ! -f "$PLAYBOOK" ]]; then
    echo "ERROR: Playbook not found: $PLAYBOOK"
    exit 1
fi

if [[ ! -e /dev/kvm ]]; then
    echo "WARNING: /dev/kvm not found. VM will run without KVM (very slow)."
    KVM_FLAG=""
else
    KVM_FLAG="-enable-kvm"
fi

# ─── Find a free port ────────────────────────────────────────────────────────
find_free_port() {
    python3 -c "
import socket
s = socket.socket()
s.bind(('', 0))
print(s.getsockname()[1])
s.close()
"
}

SSH_PORT=$(find_free_port)
echo "==> Using SSH port: ${SSH_PORT}"

# ─── Generate ephemeral SSH key ─────────────────────────────────────────────
echo "==> Generating ephemeral SSH key..."
ssh-keygen -t ed25519 -f "$SSH_KEY" -N "" -q

# ─── Create cloud-init seed ISO ─────────────────────────────────────────────
echo "==> Creating cloud-init seed ISO..."

cat > "${WORK_DIR}/user-data" <<EOF
#cloud-config
users:
  - name: ${VM_USER}
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: false
    plain_text_passwd: "${VM_PASS}"
    ssh_authorized_keys:
      - $(cat "${SSH_KEY}.pub")

# Ensure SSH is running
ssh_pwauth: true
package_update: false

# Signal that cloud-init is done
runcmd:
  - touch /tmp/cloud-init-done
EOF

cat > "${WORK_DIR}/meta-data" <<EOF
instance-id: bake-$(date +%s)
local-hostname: bake-vm
EOF

cloud-localds "$SEED_ISO" "${WORK_DIR}/user-data" "${WORK_DIR}/meta-data"

# ─── Boot the VM ─────────────────────────────────────────────────────────────
echo "==> Booting VM from: $(basename "$IMAGE")"
echo "    RAM: ${VM_RAM}MB | CPUs: ${VM_CPUS} | SSH: localhost:${SSH_PORT}"

qemu-system-x86_64 \
    ${KVM_FLAG} \
    -m "${VM_RAM}" \
    -smp "${VM_CPUS}" \
    -drive file="${IMAGE}",format=qcow2,if=virtio \
    -drive file="${SEED_ISO}",format=raw,if=virtio \
    -netdev user,id=net0,hostfwd=tcp::${SSH_PORT}-:22 \
    -device virtio-net-pci,netdev=net0 \
    -display none \
    -serial file:"${WORK_DIR}/console.log" \
    -pidfile "${WORK_DIR}/qemu.pid" \
    -daemonize

QEMU_PID=$(cat "${WORK_DIR}/qemu.pid")
echo "==> QEMU started (PID: ${QEMU_PID})"

# ─── Cleanup trap ────────────────────────────────────────────────────────────
cleanup() {
    echo ""
    echo "==> Cleaning up..."
    if [[ -f "${WORK_DIR}/qemu.pid" ]] && kill -0 "$QEMU_PID" 2>/dev/null; then
        echo "    Sending ACPI shutdown to VM..."
        # Try graceful shutdown first
        ssh -q -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -p "$SSH_PORT" "${VM_USER}@localhost" \
            "sudo shutdown -h now" 2>/dev/null || true
        # Wait up to 30s for QEMU to exit
        for i in $(seq 1 30); do
            kill -0 "$QEMU_PID" 2>/dev/null || break
            sleep 1
        done
        # Force kill if still running
        if kill -0 "$QEMU_PID" 2>/dev/null; then
            echo "    Force-killing QEMU..."
            kill -9 "$QEMU_PID" 2>/dev/null || true
        fi
    fi
    rm -rf "$WORK_DIR"
    echo "==> Done."
}
trap cleanup EXIT

# ─── Wait for SSH ────────────────────────────────────────────────────────────
echo "==> Waiting for SSH to become available (timeout: ${SSH_TIMEOUT}s)..."
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=ERROR"

elapsed=0
while [[ $elapsed -lt $SSH_TIMEOUT ]]; do
    if ssh $SSH_OPTS -i "$SSH_KEY" -p "$SSH_PORT" "${VM_USER}@localhost" "true" 2>/dev/null; then
        echo "==> SSH is ready! (took ${elapsed}s)"
        break
    fi
    sleep 5
    elapsed=$((elapsed + 5))
    echo "    ... waiting (${elapsed}s)"
done

if [[ $elapsed -ge $SSH_TIMEOUT ]]; then
    echo "ERROR: SSH did not become available within ${SSH_TIMEOUT}s"
    echo "       The VM may still be booting. Check the image."
    exit 1
fi

# ─── Wait for cloud-init to finish ──────────────────────────────────────────
echo "==> Waiting for cloud-init to complete..."
ssh $SSH_OPTS -i "$SSH_KEY" -p "$SSH_PORT" "${VM_USER}@localhost" \
    "while [ ! -f /tmp/cloud-init-done ]; do sleep 2; done" 2>/dev/null
echo "==> Cloud-init finished."

# ─── Build Ansible inventory ────────────────────────────────────────────────
INVENTORY="${WORK_DIR}/inventory.ini"
cat > "$INVENTORY" <<EOF
[bake_target]
vm ansible_host=127.0.0.1 ansible_port=${SSH_PORT} ansible_user=${VM_USER} ansible_ssh_private_key_file=${SSH_KEY} ansible_ssh_common_args='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'

[bake_target:vars]
ansible_become=true
ansible_become_method=sudo
EOF

# ─── Run Ansible ─────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  Running Ansible playbook: $(basename "$PLAYBOOK")"
echo "============================================================"
echo ""

ansible-playbook \
    -i "$INVENTORY" \
    "${ANSIBLE_EXTRA_ARGS[@]}" \
    "$PLAYBOOK"

ANSIBLE_EXIT=$?

if [[ $ANSIBLE_EXIT -ne 0 ]]; then
    echo ""
    echo "ERROR: Ansible playbook failed with exit code ${ANSIBLE_EXIT}"
    echo "       The VM is still running on port ${SSH_PORT} for debugging."
    echo "       SSH in with: ssh -i ${SSH_KEY} -p ${SSH_PORT} ${VM_USER}@localhost"
    echo ""
    echo "Press Enter to shut down the VM, or Ctrl+C to keep it running."
    read -r
    exit $ANSIBLE_EXIT
fi

echo ""
echo "==> Ansible playbook completed successfully!"

# ─── Post-bake cleanup inside the VM ────────────────────────────────────────
echo "==> Cleaning up VM internals..."

ssh $SSH_OPTS -i "$SSH_KEY" -p "$SSH_PORT" "${VM_USER}@localhost" bash <<'REMOTE_CLEANUP'
set -e

# Clean cloud-init so it runs fresh on next real boot
sudo cloud-init clean --logs 2>/dev/null || true

# Remove temporary cloud-init marker
sudo rm -f /tmp/cloud-init-done

# Clean apt caches
sudo apt-get clean 2>/dev/null || true
sudo rm -rf /var/lib/apt/lists/* 2>/dev/null || true

# Clear logs that are bake-specific
sudo truncate -s 0 /var/log/cloud-init.log 2>/dev/null || true
sudo truncate -s 0 /var/log/cloud-init-output.log 2>/dev/null || true

# Remove SSH host keys so they regenerate on real first boot
sudo rm -f /etc/ssh/ssh_host_* 2>/dev/null || true

# Clear machine-id so it regenerates (important for DHCP uniqueness)
sudo truncate -s 0 /etc/machine-id 2>/dev/null || true
sudo rm -f /var/lib/dbus/machine-id 2>/dev/null || true

# Clear bash history
history -c 2>/dev/null || true
rm -f ~/.bash_history 2>/dev/null || true

# Remove the temp user's authorized_keys (the bake key)
rm -rf ~/.ssh/authorized_keys 2>/dev/null || true
REMOTE_CLEANUP

# Optionally remove the temporary user
if [[ "$KEEP_USER" == "false" ]]; then
    echo "==> Removing temporary user '${VM_USER}' from VM..."
    ssh $SSH_OPTS -o BatchMode=yes -i "$SSH_KEY" -p "$SSH_PORT" "${VM_USER}@localhost" \
        "sudo userdel -r ${VM_USER} 2>/dev/null || true" 2>/dev/null || true
fi

# ─── Graceful shutdown ──────────────────────────────────────────────────────
echo "==> Shutting down VM gracefully..."
ssh $SSH_OPTS -o BatchMode=yes -i "$SSH_KEY" -p "$SSH_PORT" "${VM_USER}@localhost" \
    "sudo shutdown -h now" 2>/dev/null || true

# Wait for QEMU to exit
echo "==> Waiting for QEMU to exit..."
for i in $(seq 1 60); do
    kill -0 "$QEMU_PID" 2>/dev/null || break
    sleep 1
done

if kill -0 "$QEMU_PID" 2>/dev/null; then
    echo "    Force-killing QEMU..."
    kill -9 "$QEMU_PID" 2>/dev/null || true
fi

# Prevent the trap from trying shutdown again
rm -f "${WORK_DIR}/qemu.pid"

echo ""
echo "============================================================"
echo "  Image baked successfully!"
echo "  Modified image: ${IMAGE}"
echo ""
echo "  Upload to OpenStack with:"
echo "    openstack image create \\"
echo "      --disk-format qcow2 \\"
echo "      --container-format bare \\"
echo "      --file ${IMAGE} \\"
echo "      \"$(basename "${IMAGE}" .qcow2)-baked\""
echo "============================================================"
