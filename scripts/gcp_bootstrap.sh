#!/usr/bin/env bash
#
# gcp_bootstrap.sh — one-time Google Cloud setup for MHBench's GCP backend.
#
# Idempotent: safe to re-run. It creates only what is missing (project,
# billing link, APIs, service account, IAM roles, key, staging bucket, SSH
# key), checks quota, verifies the service-account key actually authenticates,
# and prints the exact `gcp:` block to paste into config/config.yaml.
#
# Configure by exporting the variables below (or editing their defaults), then:
#   ./scripts/gcp_bootstrap.sh
#
# Nothing here provisions VMs or networks — that is what `mhbench deploy` does.
# This only prepares the project so the backend can run.

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration (override via environment)
# ---------------------------------------------------------------------------
PROJECT_ID="${PROJECT_ID:-}"                       # required; globally unique
REGION="${REGION:-us-central1}"
ZONE="${ZONE:-us-central1-a}"
SA_NAME="${SA_NAME:-mhbench}"
KEY_FILE="${KEY_FILE:-$HOME/gcp-sa.json}"
SSH_KEY_PATH="${SSH_KEY_PATH:-$HOME/.ssh/id_ed25519}"
BILLING_ACCOUNT="${BILLING_ACCOUNT:-}"             # optional; XXXXXX-XXXXXX-XXXXXX
BUCKET="${BUCKET:-gs://${PROJECT_ID}-mhbench-images}"
CREATE_PROJECT="${CREATE_PROJECT:-0}"              # 1 to create PROJECT_ID if absent
INSTALL_GCLOUD="${INSTALL_GCLOUD:-0}"             # 1 to snap-install the Cloud SDK if missing

# Roles the MHBench service account needs, and why:
#   compute.admin          — VPC, subnets, firewall, Cloud Router/NAT, instances
#   storage.admin          — stage the image tarball during `mhbench upload`
#   iam.serviceAccountUser — attach the default compute SA when creating instances
ROLES=(roles/compute.admin roles/storage.admin roles/iam.serviceAccountUser)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_red=$'\033[31m'; c_rst=$'\033[0m'
log()  { printf '%s==>%s %s\n' "$c_grn" "$c_rst" "$*"; }
warn() { printf '%s[warn]%s %s\n' "$c_yel" "$c_rst" "$*" >&2; }
die()  { printf '%s[error]%s %s\n' "$c_red" "$c_rst" "$*" >&2; exit 1; }

usage() {
  sed -n '3,14p' "$0" | sed 's/^# \{0,1\}//'
  cat <<EOF

Required:  PROJECT_ID
Common overrides: REGION ZONE SA_NAME KEY_FILE SSH_KEY_PATH BILLING_ACCOUNT
                  BUCKET CREATE_PROJECT=1 INSTALL_GCLOUD=1

Example:
  PROJECT_ID=my-mhbench-proj BILLING_ACCOUNT=0X0X0X-0X0X0X-0X0X0X \\
    CREATE_PROJECT=1 ./scripts/gcp_bootstrap.sh
EOF
}

[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && { usage; exit 0; }
[[ -z "$PROJECT_ID" ]] && { usage; echo; die "PROJECT_ID is required."; }

SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

# ---------------------------------------------------------------------------
# 0. gcloud present + authenticated
# ---------------------------------------------------------------------------
if ! command -v gcloud >/dev/null 2>&1; then
  if [[ "$INSTALL_GCLOUD" == "1" ]]; then
    log "Installing the Google Cloud SDK via snap..."
    sudo snap install google-cloud-cli --classic
  else
    die "gcloud not found. Install it with 'sudo snap install google-cloud-cli --classic' (or re-run with INSTALL_GCLOUD=1)."
  fi
fi

if ! gcloud auth list --filter=status:ACTIVE --format='value(account)' | grep -q .; then
  log "No active gcloud login — launching 'gcloud auth login'..."
  gcloud auth login
fi
log "Active gcloud account: $(gcloud auth list --filter=status:ACTIVE --format='value(account)' | head -1)"

# ---------------------------------------------------------------------------
# 1. Project
# ---------------------------------------------------------------------------
if gcloud projects describe "$PROJECT_ID" >/dev/null 2>&1; then
  log "Project '$PROJECT_ID' already exists."
else
  if [[ "$CREATE_PROJECT" == "1" ]]; then
    log "Creating project '$PROJECT_ID'..."
    gcloud projects create "$PROJECT_ID"
  else
    die "Project '$PROJECT_ID' not found. Create it in the console, or re-run with CREATE_PROJECT=1."
  fi
fi
gcloud config set project "$PROJECT_ID" >/dev/null

# ---------------------------------------------------------------------------
# 2. Billing
# ---------------------------------------------------------------------------
billing_enabled="$(gcloud billing projects describe "$PROJECT_ID" \
  --format='value(billingEnabled)' 2>/dev/null || echo '')"
if [[ "$billing_enabled" == "True" ]]; then
  log "Billing already enabled."
elif [[ -n "$BILLING_ACCOUNT" ]]; then
  log "Linking billing account $BILLING_ACCOUNT..."
  gcloud billing projects link "$PROJECT_ID" --billing-account="$BILLING_ACCOUNT"
else
  warn "Billing is not enabled and BILLING_ACCOUNT is unset."
  warn "Available accounts:"; gcloud billing accounts list 2>/dev/null || true
  warn "Re-run with BILLING_ACCOUNT=XXXXXX-XXXXXX-XXXXXX (Compute will fail without billing)."
fi

# ---------------------------------------------------------------------------
# 3. APIs
# ---------------------------------------------------------------------------
log "Enabling Compute + Storage APIs (no-op if already on)..."
gcloud services enable compute.googleapis.com storage.googleapis.com --project "$PROJECT_ID"

# ---------------------------------------------------------------------------
# 4. Service account + roles + key
# ---------------------------------------------------------------------------
if gcloud iam service-accounts describe "$SA_EMAIL" --project "$PROJECT_ID" >/dev/null 2>&1; then
  log "Service account '$SA_EMAIL' already exists."
else
  log "Creating service account '$SA_NAME'..."
  gcloud iam service-accounts create "$SA_NAME" \
    --display-name "MHBench provisioner" --project "$PROJECT_ID"
fi

for role in "${ROLES[@]}"; do
  log "Granting $role..."
  gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:${SA_EMAIL}" --role="$role" \
    --condition=None --quiet >/dev/null
done

if [[ -f "$KEY_FILE" ]]; then
  log "Key file '$KEY_FILE' already present — keeping it (delete it to rotate)."
else
  log "Creating service-account key at '$KEY_FILE'..."
  gcloud iam service-accounts keys create "$KEY_FILE" --iam-account="$SA_EMAIL"
  chmod 600 "$KEY_FILE"
fi

# ---------------------------------------------------------------------------
# 5. Image-staging bucket
# ---------------------------------------------------------------------------
if gcloud storage buckets describe "$BUCKET" >/dev/null 2>&1; then
  log "Bucket '$BUCKET' already exists."
else
  log "Creating bucket '$BUCKET' in $REGION..."
  gcloud storage buckets create "$BUCKET" --project "$PROJECT_ID" --location="$REGION"
fi

# ---------------------------------------------------------------------------
# 6. SSH key
# ---------------------------------------------------------------------------
if [[ -f "$SSH_KEY_PATH" ]]; then
  log "SSH key '$SSH_KEY_PATH' already present."
else
  log "Generating SSH key at '$SSH_KEY_PATH'..."
  ssh-keygen -t ed25519 -N "" -f "$SSH_KEY_PATH"
fi

# ---------------------------------------------------------------------------
# 7. Quota snapshot (informational)
# ---------------------------------------------------------------------------
log "Region quota snapshot for $REGION (CPUS / external IPs / networks):"
gcloud compute regions describe "$REGION" --project "$PROJECT_ID" \
  --format="table(quotas.metric, quotas.limit, quotas.usage)" 2>/dev/null \
  | grep -E "METRIC|CPUS|IN_USE_ADDRESSES|NETWORKS|SUBNETWORKS" || warn "Could not read quotas."

# ---------------------------------------------------------------------------
# 8. Verify the key authenticates (isolated; does not touch your gcloud login)
# ---------------------------------------------------------------------------
log "Verifying the service-account key can call Compute..."
tmpcfg="$(mktemp -d)"
trap 'rm -rf "$tmpcfg"' EXIT
if CLOUDSDK_CONFIG="$tmpcfg" gcloud auth activate-service-account \
      --key-file="$KEY_FILE" >/dev/null 2>&1 \
   && CLOUDSDK_CONFIG="$tmpcfg" gcloud compute networks list \
      --project "$PROJECT_ID" >/dev/null 2>&1; then
  log "Service-account key authenticates and can list Compute resources."
else
  warn "Verification call failed. Roles may still be propagating (can take a minute); re-run to recheck."
fi

# ---------------------------------------------------------------------------
# Done — print the config block to paste
# ---------------------------------------------------------------------------
bucket_name="${BUCKET#gs://}"
cat <<EOF

$(printf '%s' "$c_grn")Google Cloud is ready.$(printf '%s' "$c_rst") Set 'backend: gcp' in config/config.yaml and add:

gcp:
  project: ${PROJECT_ID}
  region: ${REGION}
  zone: ${ZONE}
  credentials_file: ${KEY_FILE}
  ssh_key_path: ${SSH_KEY_PATH}
  ssh_public_key_path: ${SSH_KEY_PATH}.pub
  ssh_user: root
  image_bucket: ${bucket_name}
  default_machine_type: e2-standard-2
  machine_type_map:
    m1.small: e2-small
    m2.large: e2-standard-8

Next:
  uv sync --extra gcp
  mhbench compile ubuntu_base && mhbench upload ubuntu_base
  mhbench deploy environments/non-generated/gcp_smoke.json --project-name gcpsmoke -v
EOF
