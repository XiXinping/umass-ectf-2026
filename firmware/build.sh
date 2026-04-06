#!/bin/bash
set -e

echo "=== Generating secrets.rs ==="
SECRETS_OUTPUT_DIR=/hsm/src/ python3 /hsm/secrets_to_rust_file.py \
    /secrets/global.secrets \
    "$HSM_PIN" \
    "$PERMISSIONS"

echo "=== Building firmware ==="
cd /hsm
cargo build --release

echo "=== Converting to binary ==="
arm-none-eabi-objcopy -O binary \
    /hsm/target/thumbv6m-none-eabi/release/ectf-2026 \
    /out/hsm.bin

echo "=== Done ==="
