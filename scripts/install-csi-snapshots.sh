#!/bin/bash
# install-csi-snapshots.sh - Install CSI snapshot support for VolumeSnapshot testing
#
# Purpose: Installs VolumeSnapshot CRDs, snapshot controller, and CSI hostpath driver
# Prerequisites: kubectl, running Kubernetes cluster (Kind)
# Produces: VolumeSnapshot support with CSI hostpath driver and VolumeSnapshotClass
# Used by: Taskfile infra:csi-snapshots task
#
# Components installed:
#   1. VolumeSnapshot CRDs (from kubernetes-csi/external-snapshotter)
#   2. Snapshot controller (validates and processes VolumeSnapshot objects)
#   3. CSI hostpath driver (provides a CSI driver that supports snapshots in Kind)
#   4. VolumeSnapshotClass (csi-hostpath-snapclass)
#
# This script is idempotent and safe to re-run.

set -euo pipefail

# Source common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

# Configuration
SNAPSHOTTER_VERSION="${SNAPSHOTTER_VERSION:-v8.2.0}"
HOSTPATH_DRIVER_VERSION="${HOSTPATH_DRIVER_VERSION:-v1.15.0}"

SNAPSHOTTER_BASE="https://raw.githubusercontent.com/kubernetes-csi/external-snapshotter/${SNAPSHOTTER_VERSION}"

# CRD URLs
CRD_URLS=(
    "${SNAPSHOTTER_BASE}/client/config/crd/snapshot.storage.k8s.io_volumesnapshotclasses.yaml"
    "${SNAPSHOTTER_BASE}/client/config/crd/snapshot.storage.k8s.io_volumesnapshotcontents.yaml"
    "${SNAPSHOTTER_BASE}/client/config/crd/snapshot.storage.k8s.io_volumesnapshots.yaml"
)

# Snapshot controller URLs
CONTROLLER_URLS=(
    "${SNAPSHOTTER_BASE}/deploy/kubernetes/snapshot-controller/rbac-snapshot-controller.yaml"
    "${SNAPSHOTTER_BASE}/deploy/kubernetes/snapshot-controller/setup-snapshot-controller.yaml"
)

# Required CRD names for idempotency check
REQUIRED_CRDS=(
    "volumesnapshotclasses.snapshot.storage.k8s.io"
    "volumesnapshotcontents.snapshot.storage.k8s.io"
    "volumesnapshots.snapshot.storage.k8s.io"
)

check_prerequisites() {
    log "Checking prerequisites..."

    if ! command -v kubectl &> /dev/null; then
        error "kubectl is not installed. Please install it."
        exit 1
    fi

    if ! command -v git &> /dev/null; then
        error "git is not installed. Required for cloning CSI hostpath driver."
        exit 1
    fi

    if ! kubectl cluster-info &> /dev/null; then
        error "Cannot connect to Kubernetes cluster. Please check your kubeconfig."
        exit 1
    fi

    success "Prerequisites check passed"
}

check_already_installed() {
    local all_crds_present=true
    for crd in "${REQUIRED_CRDS[@]}"; do
        if ! kubectl get crd "$crd" &> /dev/null; then
            all_crds_present=false
            break
        fi
    done

    if $all_crds_present && \
       kubectl get deployment snapshot-controller -n kube-system &> /dev/null && \
       kubectl get csidriver hostpath.csi.k8s.io &> /dev/null && \
       kubectl get volumesnapshotclass csi-hostpath-snapclass &> /dev/null; then
        success "CSI snapshot support already installed (CRDs, controller, hostpath driver, snapshot class)"
        exit 0
    fi
}

install_crds() {
    log "Installing VolumeSnapshot CRDs (external-snapshotter ${SNAPSHOTTER_VERSION})..."

    for url in "${CRD_URLS[@]}"; do
        local crd_name
        crd_name=$(basename "$url")
        log "  Applying CRD: ${crd_name}"
        if ! kubectl apply -f "$url"; then
            error "Failed to apply CRD: ${url}"
            exit 1
        fi
    done

    # Wait for CRDs to be established
    log "Waiting for VolumeSnapshot CRDs to be established..."
    for crd in "${REQUIRED_CRDS[@]}"; do
        if ! kubectl wait --for=condition=Established "crd/${crd}" --timeout=60s; then
            error "CRD ${crd} not established within timeout"
            exit 1
        fi
        success "  CRD ${crd} established"
    done
}

install_snapshot_controller() {
    log "Installing snapshot controller..."

    for url in "${CONTROLLER_URLS[@]}"; do
        local manifest_name
        manifest_name=$(basename "$url")
        log "  Applying: ${manifest_name}"
        if ! kubectl apply -f "$url"; then
            error "Failed to apply: ${url}"
            exit 1
        fi
    done

    log "Waiting for snapshot controller deployment..."
    if ! kubectl wait --for=condition=available deployment/snapshot-controller \
        -n kube-system --timeout=120s; then
        error "Snapshot controller not ready within timeout"
        kubectl get pods -n kube-system -l app.kubernetes.io/name=snapshot-controller || true
        exit 1
    fi

    success "Snapshot controller is running"
}

install_hostpath_driver() {
    log "Installing CSI hostpath driver ${HOSTPATH_DRIVER_VERSION}..."

    # The CSI hostpath driver's deploy.sh script computes BASE_DIR from its
    # own location, then reads YAML manifests from ${BASE_DIR}/hostpath/.
    # We must shallow-clone the repo and run the deploy.sh from the
    # kubernetes-1.27 directory (which contains the hostpath/ subdirectory).

    if kubectl get csidriver hostpath.csi.k8s.io &> /dev/null; then
        success "CSI hostpath driver already registered, skipping install"
        return 0
    fi

    clone_dir=$(mktemp -d)
    # Clean up clone directory — safe to call multiple times
    cleanup_clone() { [ -n "${clone_dir:-}" ] && rm -rf "${clone_dir}"; clone_dir=""; }
    trap cleanup_clone EXIT

    log "  Cloning csi-driver-host-path ${HOSTPATH_DRIVER_VERSION} (shallow)..."
    if ! git clone --depth 1 --branch "${HOSTPATH_DRIVER_VERSION}" \
        https://github.com/kubernetes-csi/csi-driver-host-path.git \
        "${clone_dir}" 2>&1 | while IFS= read -r line; do log "    ${line}"; done; then
        error "Failed to clone csi-driver-host-path"
        exit 1
    fi

    # The deploy.sh in kubernetes-1.27/ sets BASE_DIR to its own directory,
    # which contains the hostpath/ subdirectory with all required manifests.
    local deploy_script="${clone_dir}/deploy/kubernetes-1.27/deploy.sh"
    if [ ! -f "$deploy_script" ]; then
        error "deploy.sh not found at ${deploy_script}"
        ls -la "${clone_dir}/deploy/" || true
        exit 1
    fi

    log "  Running hostpath driver deploy script..."
    if ! bash "${deploy_script}" 2>&1 | while IFS= read -r line; do log "    ${line}"; done; then
        warn "Hostpath driver deploy script returned non-zero, checking if driver is actually running..."
    fi

    # Verify the CSI driver is registered
    log "Waiting for CSI hostpath driver to register..."
    local retries=30
    local i=0
    while [ $i -lt $retries ]; do
        if kubectl get csidriver hostpath.csi.k8s.io &> /dev/null; then
            success "CSI hostpath driver registered"
            cleanup_clone
            trap - EXIT
            return 0
        fi
        i=$((i + 1))
        sleep 2
    done

    error "CSI hostpath driver not registered after ${retries} retries"
    kubectl get csidriver || true
    kubectl get pods --all-namespaces -l app.kubernetes.io/instance=hostpath.csi.k8s.io || true
    exit 1
}

create_snapshot_class() {
    log "Creating VolumeSnapshotClass..."

    if kubectl get volumesnapshotclass csi-hostpath-snapclass &> /dev/null; then
        success "VolumeSnapshotClass csi-hostpath-snapclass already exists"
        return 0
    fi

    local snapclass_file
    snapclass_file=$(mktemp)
    cat > "$snapclass_file" <<'YAML'
apiVersion: snapshot.storage.k8s.io/v1
kind: VolumeSnapshotClass
metadata:
  name: csi-hostpath-snapclass
driver: hostpath.csi.k8s.io
deletionPolicy: Delete
YAML

    if ! kubectl apply -f "$snapclass_file"; then
        error "Failed to create VolumeSnapshotClass"
        rm -f "$snapclass_file"
        exit 1
    fi
    rm -f "$snapclass_file"

    success "VolumeSnapshotClass csi-hostpath-snapclass created"
}

verify_installation() {
    log "Verifying CSI snapshot installation..."

    log "VolumeSnapshot CRDs:"
    kubectl get crd | grep snapshot.storage.k8s.io || true

    log "Snapshot controller:"
    kubectl get deployment snapshot-controller -n kube-system -o wide || true

    log "CSI drivers:"
    kubectl get csidriver || true

    log "VolumeSnapshotClasses:"
    kubectl get volumesnapshotclass || true

    log "StorageClasses:"
    kubectl get storageclass || true

    success "Installation verification completed"
}

main() {
    log "Installing CSI snapshot support for VolumeSnapshot testing..."

    check_prerequisites
    check_already_installed
    install_crds
    install_snapshot_controller
    install_hostpath_driver
    create_snapshot_class
    verify_installation

    success "CSI snapshot support installed successfully!"
    log "Snapshotter version: ${SNAPSHOTTER_VERSION}"
    log "Hostpath driver version: ${HOSTPATH_DRIVER_VERSION}"
    log ""
    log "Available resources:"
    log "  VolumeSnapshotClass: csi-hostpath-snapclass"
    log "  CSI Driver: hostpath.csi.k8s.io"
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [options]"
        echo ""
        echo "Installs CSI snapshot support for VolumeSnapshot testing in Kind."
        echo ""
        echo "Components:"
        echo "  - VolumeSnapshot CRDs (external-snapshotter)"
        echo "  - Snapshot controller"
        echo "  - CSI hostpath driver (provides snapshot-capable volumes)"
        echo "  - VolumeSnapshotClass (csi-hostpath-snapclass)"
        echo ""
        echo "Options:"
        echo "  --help, -h      Show this help message"
        echo ""
        echo "Environment Variables:"
        echo "  SNAPSHOTTER_VERSION       external-snapshotter version (default: v8.2.0)"
        echo "  HOSTPATH_DRIVER_VERSION   CSI hostpath driver version (default: v1.15.0)"
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac
