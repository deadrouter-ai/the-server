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
# IMPORTANT: We do NOT mount $HOME/.cargo into the container. The Docker image
# has Rust 1.95.0 installed at a fixed version. Mounting the host's .cargo would
# override this with whatever the host has, breaking reproducibility.
echo "Running build inside isolated container..."
mkdir -p "$HOME/.cache/ccache"
$DOCKER run --rm --network host \
    -v "$(pwd):/workspace" \
    -v "$HOME/.cache/ccache:/root/.cache/ccache" \
    -w /workspace \
    sev-reproducible-builder \
    /bin/bash -c '
        # 1. Build Rust Server
        export CARGO_TARGET_DIR=/tmp/cargo-target
        CC_x86_64_unknown_linux_musl=musl-gcc \
            RUSTFLAGS="--remap-path-prefix $(pwd)=/workspace" \
            cargo build --locked --release --target x86_64-unknown-linux-musl

        cp /tmp/cargo-target/x86_64-unknown-linux-musl/release/the_server .

        # 2. Generate SHA384 hash (similar to measurement)
        sha384sum the_server | awk '{print $1}' > the_server_hash.txt
        echo "=== FINAL THE SERVER HASH ==="
        cat the_server_hash.txt
        echo
    '
echo "Build complete. Artifacts generated perfectly reproducibly."
