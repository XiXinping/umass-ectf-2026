#!/usr/bin/env bash
set -euo pipefail

BUILDDIR=${1:-/tmp/build}
mkdir -p "${BUILDDIR}"

python3 ../firmware/secrets_to_c_header.py /secrets/global.secrets ${HSM_PIN} ${PERMISSIONS}
make BUILDDIR=${BUILDDIR}
cp ${BUILDDIR}/hsm.elf ${BUILDDIR}/hsm.bin /out
