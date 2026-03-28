# firmware-rust

Rust port of the eCTF 2026 MSPM0 firmware application layer.

## Scope of this port

- Rust: main loop, host messaging protocol, command handlers, and MSPM0 platform init/UART/LED via Embassy HAL.
- C (reused): MSPM0 startup, flash driver, filesystem persistence, and security stubs.
- ABI compatibility: keeps packet wire format and command behavior aligned with the original reference firmware.

## Layout

- `src/` Rust firmware logic (`lib.rs`, `commands.rs`, `host_messaging.rs`, etc.).
- `Makefile` builds Rust static library + MSPM0 C support objects and links `hsm.elf`.
- `build.sh` mirrors the original secrets/header generation flow.

## Build

From `firmware-rust/`:

- `make` (or `make BUILDDIR=/tmp/build`)
- outputs: `hsm.elf` and `hsm.bin`

This port is intended as a migration base. Remaining C modules can be moved into Rust incrementally (filesystem, security, and hardware drivers) once platform-specific HAL support is in place.
