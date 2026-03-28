# firmware-sodium

This folder is a copy of `firmware/` with the crypto backend switched from wolfSSL to libsodium.

## What changed

- `src/crypto.c` now uses libsodium AEAD APIs.
- `inc/crypto.h` now imports `sodium.h` and uses libsodium size constants.
- `Makefile` removes wolfSSL object builds/includes and links against libsodium (`-lsodium`).

## Crypto behavior

The function names are unchanged (`aes_gcm_encrypt` / `aes_gcm_decrypt`) for compatibility with existing call sites, but the implementation now uses:

- `crypto_aead_chacha20poly1305_ietf_encrypt_detached`
- `crypto_aead_chacha20poly1305_ietf_decrypt_detached`

This keeps the same key/nonce/tag sizes used by the original call pattern (32-byte key, 12-byte nonce, 16-byte tag).

## Build requirements

Set `SODIUM_PREFIX` to a libsodium install built for your target toolchain:

- headers at `${SODIUM_PREFIX}/include/sodium.h`
- library at `${SODIUM_PREFIX}/lib/libsodium.a` (or compatible `.so`)

Example:

```bash
make BUILDDIR=/tmp/build SODIUM_PREFIX=/opt/libsodium
```

Note: `libsodium-dev` in Docker installs host libraries. For cross-compiling firmware, you still need a target-compatible libsodium build at `SODIUM_PREFIX`.
