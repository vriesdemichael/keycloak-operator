#!/bin/bash
# install-cnpg.sh - Install CloudNativePG operator into the Kind test cluster
# This script is idempotent and safe to re-run.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"; }
warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
err()  { echo -e "${RED}[ERROR] $1${NC}"; }
ok()   { echo -e "${GREEN}[OK] $1${NC}"; }

NAMESPACE="cnpg-system"
CHANNEL="stable"
CSV_TIMEOUT=300
CNPG_HELM_RELEASE="cnpg"
CNPG_HELM_CHART="cloudnative-pg/cloudnative-pg"
# Primary desired version (chart 0.26.0 corresponds to AppVersion 1.27.0)
CNPG_CHART_VERSION_PRIMARY="0.26.0"
CNPG_CHART_VERSION_FALLBACK="0.25.2" # Example fallback (AppVersion 1.26.x)
CNPG_VALUES=$(cat <<'EOF'
metrics:
  enablePodMonitor: true
webhook:
  create: true
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 512Mi
watchNamespace: ""
EOF
)

if ! command -v kubectl >/dev/null 2>&1; then
  err "kubectl not found"
  exit 1
fi

REQUIRED_CRDS=(clusters.postgresql.cnpg.io backups.postgresql.cnpg.io poolers.postgresql.cnpg.io)

already_complete=true
for r in "${REQUIRED_CRDS[@]}"; do
  if ! kubectl get crd "$r" >/dev/null 2>&1; then already_complete=false; fi
done
if $already_complete && kubectl get deployment -n "$NAMESPACE" cnpg-controller-manager >/dev/null 2>&1; then
  ok "CloudNativePG already installed and CRDs present"
  exit 0
fi

kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

if ! command -v helm >/dev/null 2>&1; then
  err "Helm not available; please install Helm for CNPG installation"
  exit 1
fi

if ! helm repo list | grep -q cloudnative-pg; then
  helm repo add cloudnative-pg https://cloudnative-pg.github.io/charts >/dev/null 2>&1 || {
    err "Failed adding cloudnative-pg repo"; exit 1; }
fi
helm repo update >/dev/null 2>&1 || true

log "Installing CloudNativePG helm chart version ${CNPG_CHART_VERSION_PRIMARY}"
if ! printf "%s" "$CNPG_VALUES" | helm upgrade --install "$CNPG_HELM_RELEASE" "$CNPG_HELM_CHART" \
    --version "$CNPG_CHART_VERSION_PRIMARY" \
    --namespace "$NAMESPACE" \
    --create-namespace -f -; then
  warn "Primary version failed; attempting fallback ${CNPG_CHART_VERSION_FALLBACK}"
  if ! printf "%s" "$CNPG_VALUES" | helm upgrade --install "$CNPG_HELM_RELEASE" "$CNPG_HELM_CHART" \
      --version "$CNPG_CHART_VERSION_FALLBACK" \
      --namespace "$NAMESPACE" \
      --create-namespace -f -; then
    err "Helm installation failed for both primary and fallback versions"
    exit 1
  fi
fi

# Wait for CRDs (Helm should have created them)

log "Waiting for CNPG CRDs to become available..."
CRDS=(clusters.postgresql.cnpg.io backups.postgresql.cnpg.io poolers.postgresql.cnpg.io)
for crd in "${CRDS[@]}"; do
  if ! kubectl wait --for=condition=Established "crd/${crd}" --timeout=180s 2>/dev/null; then
    warn "CRD ${crd} not established yet (continuing)"
  else
    ok "CRD ${crd} established"
  fi
done

log "Waiting for CNPG operator deployment to be ready..."
# Deployment name differs between helm (cnpg) and manifest (cloudnative-pg); check both
if kubectl get deployment cnpg -n "$NAMESPACE" >/dev/null 2>&1; then
  target_dep=cnpg
elif kubectl get deployment cloudnative-pg -n "$NAMESPACE" >/dev/null 2>&1; then
  target_dep=cloudnative-pg
else
  warn "Could not find CNPG operator deployment yet; listing resources"
  kubectl get all -n "$NAMESPACE" || true
  target_dep=cloudnative-pg
fi

if ! kubectl rollout status "deployment/${target_dep}" -n "$NAMESPACE" --timeout=240s; then
  err "CNPG operator deployment ${target_dep} not ready"
  exit 1
fi

ok "CloudNativePG operator installed successfully"
