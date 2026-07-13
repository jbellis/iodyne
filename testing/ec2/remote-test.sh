#!/usr/bin/env bash
set -euo pipefail

DISTRO="${1:?distro is required}"
RUN_ID="${2:?run ID is required}"
ARCHIVE="${3:?source archive is required}"
ACTION="${4:-test}"
WORK_DIR="$HOME/iodyne-matrix-$RUN_ID"
RESULT_DIR="$WORK_DIR/results"
IMAGE="iodyne-matrix:$RUN_ID"

install_packages() {
    case "$DISTRO" in
        ubuntu-*|debian-*)
            sudo apt-get update
            sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y \
                build-essential ca-certificates curl docker.io pkg-config podman
            sudo systemctl enable --now docker
            ;;
        rhel-*)
            sudo dnf install -y \
                ca-certificates curl dnf-plugins-core gcc gcc-c++ make pkgconf-pkg-config podman tar
            sudo dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo
            sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin
            sudo systemctl enable --now docker
            ;;
        *)
            echo "unsupported distro: $DISTRO" >&2
            return 1
            ;;
    esac
}

install_rust() {
    if ! command -v cargo >/dev/null; then
        curl --proto '=https' --tlsv1.2 -fsS https://sh.rustup.rs \
            | sh -s -- -y --profile minimal --default-toolchain stable
    fi
    export PATH="$HOME/.cargo/bin:$PATH"
}

expected_kernel() {
    case "$DISTRO" in
        rhel-9) printf '5.14.\n' ;;
        ubuntu-22.04) printf '5.15.\n' ;;
        debian-12) printf '6.1.\n' ;;
        ubuntu-24.04) printf '6.8.\n' ;;
    esac
}

select_grub_kernel() {
    local kernel="$1"
    sudo sed -i 's/^GRUB_DEFAULT=.*/GRUB_DEFAULT=saved/' /etc/default/grub
    sudo update-grub
    sudo grub-set-default "Advanced options for Ubuntu>Ubuntu, with Linux $kernel"
}

prepare_kernel() {
    local expected current target
    expected="$(expected_kernel)"
    current="$(uname -r)"
    if [[ "$current" == "$expected"* ]]; then
        echo "$DISTRO already runs target kernel $current"
        return 0
    fi
    case "$DISTRO" in
        ubuntu-22.04)
            sudo apt-get update
            sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y linux-aws-5.15
            target="$(basename "$(find /boot -maxdepth 1 -name 'vmlinuz-5.15.*-aws' -print | sort -V | tail -n 1)")"
            target="${target#vmlinuz-}"
            select_grub_kernel "$target"
            ;;
        ubuntu-24.04)
            sudo apt-get update
            sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y linux-aws-6.8
            target="$(basename "$(find /boot -maxdepth 1 -name 'vmlinuz-6.8.*-aws' -print | sort -V | tail -n 1)")"
            target="${target#vmlinuz-}"
            select_grub_kernel "$target"
            ;;
        *)
            echo "$DISTRO booted $current; expected the $expected kernel family" >&2
            return 1
            ;;
    esac
    echo "$DISTRO installed $target; reboot required"
    return 10
}

container_base() {
    case "$DISTRO" in
        ubuntu-22.04) printf 'ubuntu:22.04\n' ;;
        ubuntu-24.04) printf 'ubuntu:24.04\n' ;;
        debian-12) printf 'debian:12-slim\n' ;;
        rhel-9) printf 'registry.access.redhat.com/ubi9/ubi-minimal\n' ;;
    esac
}

write_containerfile() {
    local base install
    base="$(container_base)"
    case "$DISTRO" in
        ubuntu-*|debian-*)
            install='RUN apt-get update && apt-get install -y --no-install-recommends libgcc-s1 && rm -rf /var/lib/apt/lists/*'
            ;;
        rhel-*)
            install='RUN microdnf install -y libgcc && microdnf clean all'
            ;;
    esac
    printf 'FROM %s\n%s\nCOPY target/release/iodyne /usr/local/bin/iodyne\nENTRYPOINT ["/usr/local/bin/iodyne", "--diag"]\n' \
        "$base" "$install" >"$WORK_DIR/Containerfile"
}

run_case() {
    local name="$1" expectation="$2"
    shift 2
    local log="$RESULT_DIR/$name.log"
    echo "=== $name ==="
    if "$@" >"$log" 2>&1; then
        :
    else
        cat "$log"
        echo "$name: command failed" >&2
        return 1
    fi
    cat "$log"
    case "$expectation" in
        ebpf)
            grep -Eq 'latency source=EbpfPerRequest  status=Active' "$log"
            grep -Eq 'VFS activity source=EbpfCompletedBytes  status=Active' "$log"
            grep -Eq 'VFS event paths status=Active' "$log"
            grep -Eq 'FUSE requester attribution status=Active' "$log"
            grep -Eq 'FUSE PID-0 writeback attribution status=Active' "$log"
            grep -Eq 'OverlayFS backing attribution status=Active' "$log"
            ;;
        unprivileged)
            grep -Eq 'latency source=AggregateAwait  status=Unavailable' "$log"
            grep -Eq 'VFS activity source=Unavailable  status=Unavailable' "$log"
            ;;
    esac
}

main() {
    local failures=0 kernel base
    install_packages
    install_rust
    rm -rf "$WORK_DIR"
    mkdir -p "$RESULT_DIR"
    tar -xzf "$ARCHIVE" -C "$WORK_DIR"
    cd "$WORK_DIR"
    cargo build --release --locked
    sudo modprobe fuse 2>/dev/null || true
    sudo modprobe overlay 2>/dev/null || true
    write_containerfile
    sudo docker build -t "$IMAGE" -f Containerfile .
    sudo podman build -t "$IMAGE" -f Containerfile .
    kernel="$(uname -r)"
    base="$(container_base)"
    {
        echo "distro=$DISTRO"
        echo "kernel=$kernel"
        echo "container_base=$base"
        echo "btf=$(test -r /sys/kernel/btf/vmlinux && echo present || echo missing)"
        echo "unprivileged_bpf_disabled=$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo unknown)"
        echo "lockdown=$(cat /sys/kernel/security/lockdown 2>/dev/null || echo unavailable)"
        sudo docker version --format 'docker={{.Server.Version}}'
        sudo podman version --format 'podman={{.Version}}'
        sed -n '1,8p' /etc/os-release
    } | tee "$RESULT_DIR/system.txt"

    run_case bare-unprivileged unprivileged target/release/iodyne --diag || failures=$((failures + 1))
    run_case bare-ebpf ebpf sudo target/release/iodyne --diag || failures=$((failures + 1))

    run_case docker-unprivileged unprivileged \
        sudo docker run --rm --user 65534:65534 --cap-drop=ALL \
            --security-opt no-new-privileges:true --security-opt label=disable \
            --pid=host --cgroupns=host --userns=host \
            -v /sys:/sys:ro -v /dev:/dev:ro "$IMAGE" || failures=$((failures + 1))
    run_case docker-ebpf ebpf \
        sudo docker run --rm --privileged --pid=host --cgroupns=host --userns=host \
            --ulimit memlock=-1:-1 --security-opt label=disable \
            -v /sys:/sys:ro -v /dev:/dev:ro "$IMAGE" || failures=$((failures + 1))

    run_case podman-unprivileged unprivileged \
        sudo podman run --rm --user 65534:65534 --cap-drop=ALL \
            --security-opt no-new-privileges --security-opt label=disable \
            --pid=host --cgroupns=host --userns=host \
            -v /sys:/sys:ro -v /dev:/dev:ro "$IMAGE" || failures=$((failures + 1))
    run_case podman-ebpf ebpf \
        sudo podman run --rm --privileged --pid=host --cgroupns=host --userns=host \
            --ulimit host --security-opt label=disable \
            -v /sys:/sys:ro -v /dev:/dev:ro "$IMAGE" || failures=$((failures + 1))

    printf 'failures=%d\n' "$failures" | tee "$RESULT_DIR/summary.txt"
    ((failures == 0))
}

case "$ACTION" in
    prepare-kernel) prepare_kernel ;;
    test) main ;;
    *) echo "unknown action: $ACTION" >&2; exit 2 ;;
esac
