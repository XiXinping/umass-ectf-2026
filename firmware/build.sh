#!/bin/bash
set -e

# Output directory = /out
BUILDDIR=${1:-/tmp/build}
TARGET=${TARGET:-thumbv6m-none-eabi}
BIN_NAME=${BIN_NAME:-ectf-2026}
export SECRETS_FILE="/secrets/global.secrets"
mkdir -p "$BUILDDIR"

# Compile firmware
cargo build --release --target "$TARGET" --bin "$BIN_NAME"

# Copy the output to the build directory
ELF_PATH="target/$TARGET/release/$BIN_NAME"

if [ -f "$ELF_PATH" ]; then
    rust-objcopy "$ELF_PATH" -O binary "$BUILDDIR/hsm.bin"
    echo "Flashable binary generated at: $BUILDDIR/hsm.bin"
    echo "Copying firmware to $BUILDDIR/hsm.elf"
    cp "$ELF_PATH" "$BUILDDIR/hsm.elf"
    mkdir -p /out
    cp "$BUILDDIR/hsm.elf" "$BUILDDIR/hsm.bin" /out
    echo "Copied hsm.elf and hsm.bin to /out"

else
    echo "Error: Build output not found at $ELF_PATH"
    exit 1
fi
