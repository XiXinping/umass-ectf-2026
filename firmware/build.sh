#!/bin/bash
set -e

# Default output directory to /out (mapped volume) if not provided
BUILDDIR=${1:-/tmp/build}
TARGET=${TARGET:-thumbv6m-none-eabi}
BIN_NAME=${BIN_NAME:-ectf-2026}
export SECRETS_FILE="/secrets/global.secrets"
mkdir -p "$BUILDDIR"

# 1. Generate secrets (existing logic)
# python3 secrets_to_rust_file.py /secrets/global.secrets ${HSM_PIN} ${PERMISSIONS}

# 2. Compile the firmware
# Build one explicit binary to avoid building extra bin targets.
cargo build --release --target "$TARGET" --bin "$BIN_NAME"

# 3. Copy the output artifact
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
    echo "Error: Build artifact not found at $ELF_PATH"
    exit 1
fi
