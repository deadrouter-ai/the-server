#!/bin/bash
set -e

if ! docker info >/dev/null 2>&1; then
    if sudo docker info >/dev/null 2>&1; then
        DOCKER="sudo docker"
    else
        echo "Docker is not installed or running."
        exit 1
    fi
else
    DOCKER="docker"
fi

# Build the Docker image specifically for our reproducibility
echo "Building reproducible Docker image..."
$DOCKER build --network host -t sev-reproducible-builder -f Dockerfile.reproducible .

# Run the build process inside the container
echo "Running build inside isolated container..."
mkdir -p "$HOME/.cache/ccache" "$HOME/.cache/cargo-repro/registry" "$HOME/.cache/cargo-repro/git" "$HOME/.cache/cargo-repro/target"
$DOCKER run --rm --network host \
    -v "$(pwd):/workspace" \
    -v "$HOME/.cache/ccache:/root/.cache/ccache" \
    -v "$HOME/.cache/cargo-repro/registry:/root/.cargo/registry" \
    -v "$HOME/.cache/cargo-repro/git:/root/.cargo/git" \
    -v "$HOME/.cache/cargo-repro/target:/tmp/cargo-target" \
    -w /workspace \
    sev-reproducible-builder \
    /bin/bash -c '
        # 1. Build Rust Server
        export CARGO_TARGET_DIR=/tmp/cargo-target
        CC_x86_64_unknown_linux_musl=musl-gcc \
            RUSTFLAGS="--remap-path-prefix $(pwd)=/workspace" \
            cargo build --locked --release --target x86_64-unknown-linux-musl

        cp /tmp/cargo-target/x86_64-unknown-linux-musl/release/the-server ./the_server

        # 2. Generate SHA384 hash (similar to measurement)
        sha384sum the_server | cut -d" " -f1 > the_server_hash.txt
        echo "=== FINAL THE SERVER HASH ==="
        cat the_server_hash.txt
        echo
    '
