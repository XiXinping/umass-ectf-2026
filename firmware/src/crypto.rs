//! Cryptographic operations for eCTF secure HSM communication.
//!
//! AES-128-GCM is performed via the MSPM0L2228 AESADV hardware accelerator
//! (see `aes_hardware_accel`). Hybrid (asymmetric) encryption layers
//! X25519 ECDH + HKDF-SHA256 key derivation on top of the hardware GCM.

use crate::{GLOBAL_PUB_KEY, GLOBAL_RNG};
use crate::{GLOBAL_SECRET, aes_hardware_accel::GcmEngine};
use crate::random::SecureRng;
use heapless::Vec;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// GCM operates on 128-bit (16-byte) blocks regardless of key size.
const GCM_BLOCK_BYTES: usize = 16;
/// The size of an AES-GCM nonce.
pub const NONCE_SIZE: usize = 12;
/// The size of an AES-GCM authentication tag.
pub const AUTH_TAG_SIZE: usize = 16;
pub const PUBLIC_KEY_SIZE: usize = size_of::<PublicKey>();
pub const PRIVATE_KEY_SIZE: usize = 32;
/// The size of an Ed25519 signature.
pub const SIGNATURE_SIZE: usize = 64;

/// Spin-loop ceiling for AESADV ready-flag polling.
/// Generous enough for multi-block payloads at 32 MHz.
const POLL_LIMIT: u32 = 2_500_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum CryptoError {
    /// Input is too large
    InvalidInput,
    /// Failure in securely generating random numbers
    RngError,
    /// Failed to derive asymmetric key
    AsymmetricKeyError,
    /// Failed to validate authentication tag when decrypting with AES-GCM
    BadAuthTag,
    /// Invalid key when decrypting with AES-GCM
    BadAesKey,
    /// Failed to encrypt using AES-GCM
    AesGcmEncryptError,
    /// Failed to decrypt using AES-GCM
    AesGcmDecryptError,
    /// AESADV peripheral did not become ready within the polling limit
    HardwareTimeout,
}

/// Error types for authentication operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// Random number generation failed.
    RngFailed,
    /// Could not import a key from raw bytes.
    KeyImportFailed,
    /// ECDSA signing failed.
    SigningFailed,
    /// ECDSA verification failed (bad signature or wrong key).
    VerificationFailed,
    /// Signature bytes could not be parsed.
    BadSignatureFormat,
}

/// A struct containing the result of calling asymmetric_encrypt(). The result of a hybrid
/// encryption contains the ciphertext, the AES shared secret, and an AES-GCM authentication tag.
#[repr(C)]
pub struct AsymmetricEncrypted<const N: usize> {
    pub ciphertext: [u8; N],
    pub nonce: [u8; 12],
    pub cipher_public_key: PublicKey,
    pub auth_tag: [u8; AUTH_TAG_SIZE],
}

pub struct AsymmetricEncryptedMetadata {
    pub nonce: [u8; 12],
    pub cipher_public_key: PublicKey,
    pub auth_tag: [u8; AUTH_TAG_SIZE],
}

// ─── Byte ↔ word conversion for AESADV registers ──────────────────

/// Pack up to 4 bytes into a little-endian u32, zero-filling any
/// missing trailing bytes.
#[inline(always)]
fn le_word_from_slice(src: &[u8]) -> u32 {
    let mut tmp = [0u8; 4];
    let n = core::cmp::min(src.len(), 4);
    tmp[..n].copy_from_slice(&src[..n]);
    u32::from_le_bytes(tmp)
}

/// Pack a byte slice (≤16 bytes) into four little-endian u32 words,
/// zero-padding any trailing space.
#[inline(always)]
fn pack_block(src: &[u8]) -> [u32; 4] {
    let mut words = [0u32; 4];
    for i in 0..4 {
        let start = i * 4;
        if start < src.len() {
            let end = core::cmp::min(start + 4, src.len());
            words[i] = le_word_from_slice(&src[start..end]);
        }
    }
    words
}

/// Unpack four little-endian u32 words into a byte slice of up to 16
/// bytes, writing only as many bytes as `dst` can hold.
#[inline(always)]
fn unpack_block(words: &[u32; 4], dst: &mut [u8]) {
    for (i, &w) in words.iter().enumerate() {
        let start = i * 4;
        if start >= dst.len() {
            break;
        }
        let wb = w.to_le_bytes();
        let end = core::cmp::min(start + 4, dst.len());
        dst[start..end].copy_from_slice(&wb[..end - start]);
    }
}

// ─── AESADV session helpers ────────────────────────────────────────

/// Prepare the GCM engine for a new encrypt or decrypt session.
///
/// Clears leftover tag state, loads the 96-bit nonce with the
/// standard GCM initial counter value (J₀ = nonce ‖ 0x00000001 in
/// big-endian), configures the control register for autonomous GCM
/// mode, and programs the payload / AAD lengths.
fn begin_gcm_session(
    eng: &GcmEngine,
    nonce: &[u8; 12],
    encrypt: bool,
    payload_bytes: u32,
    aad_bytes: u32,
) -> bool {
    eng.zero_gcm_tag_state();

    // GCM initial counter block: 96-bit nonce + big-endian 1.
    // The AESADV stores the counter in the top IV word with reversed
    // byte order, so the literal 0x0100_0000 represents the value 1.
    let iv = [
        le_word_from_slice(&nonce[0..4]),
        le_word_from_slice(&nonce[4..8]),
        le_word_from_slice(&nonce[8..12]),
        0x0100_0000,
    ];
    eng.load_iv(&iv);

    eng.configure_gcm_mode(encrypt);
    eng.set_lengths(payload_bytes, 0, aad_bytes);

    true
}

/// Submit all AAD blocks to the engine.
///
/// AAD is authenticated but not encrypted, so the engine consumes
/// input without producing output. A partial final block must be
/// followed by `signal_partial_block()`.
fn submit_aad(eng: &GcmEngine, aad: &[u8]) -> bool {
    if aad.is_empty() {
        return true;
    }

    let full = aad.len() / GCM_BLOCK_BYTES;
    let tail = aad.len() % GCM_BLOCK_BYTES;

    for i in 0..full {
        if !eng.poll_input_rdy(POLL_LIMIT) {
            return false;
        }
        let start = i * GCM_BLOCK_BYTES;
        eng.submit_data_block(&pack_block(&aad[start..start + GCM_BLOCK_BYTES]));
    }

    if tail > 0 {
        if !eng.poll_input_rdy(POLL_LIMIT) {
            return false;
        }
        let start = full * GCM_BLOCK_BYTES;
        eng.submit_data_block(&pack_block(&aad[start..]));
        eng.signal_partial_block();
    }

    true
}

/// Run encrypt-or-decrypt payload through the AESADV two-stage pipeline.
///
/// The hardware has a depth-2 pipeline: two input blocks must be
/// submitted before the first output block appears.  After priming,
/// each output read is paired with the next input write.  Finally the
/// remaining outputs are drained.
///
/// `src` and `dst` may alias (point to the same buffer) for in-place
/// operation — the pipeline depth ensures reads happen before the
/// corresponding writes overwrite the same offset.
fn run_pipeline(eng: &GcmEngine, src: &[u8], dst: &mut [u8], len: usize) -> bool {
    if len == 0 {
        return true;
    }

    let full = len / GCM_BLOCK_BYTES;
    let tail = len % GCM_BLOCK_BYTES;
    let n_blocks = full + usize::from(tail > 0);

    let mut enqueued = 0usize;
    let mut dequeued = 0usize;

    // ── Phase 1: prime the pipeline (up to 2 blocks, no reads) ─────
    while enqueued < n_blocks && enqueued < 2 {
        if !eng.poll_input_rdy(POLL_LIMIT) {
            return false;
        }
        let off = enqueued * GCM_BLOCK_BYTES;
        let partial = enqueued >= full && tail > 0;
        let blk = if partial {
            pack_block(&src[off..])
        } else {
            pack_block(&src[off..off + GCM_BLOCK_BYTES])
        };
        eng.submit_data_block(&blk);
        if partial {
            eng.signal_partial_block();
        }
        enqueued += 1;
    }

    // ── Phase 2: steady state — alternate read / write ─────────────
    while enqueued < n_blocks {
        if !eng.poll_output_rdy(POLL_LIMIT) {
            return false;
        }
        let result = eng.collect_data_block();
        let roff = dequeued * GCM_BLOCK_BYTES;
        let rlen = if dequeued < full { GCM_BLOCK_BYTES } else { tail };
        unpack_block(&result, &mut dst[roff..roff + rlen]);
        dequeued += 1;

        if !eng.poll_input_rdy(POLL_LIMIT) {
            return false;
        }
        let woff = enqueued * GCM_BLOCK_BYTES;
        let partial = enqueued >= full && tail > 0;
        let blk = if partial {
            pack_block(&src[woff..])
        } else {
            pack_block(&src[woff..woff + GCM_BLOCK_BYTES])
        };
        eng.submit_data_block(&blk);
        if partial {
            eng.signal_partial_block();
        }
        enqueued += 1;
    }

    // ── Phase 3: drain remaining outputs ───────────────────────────
    while dequeued < n_blocks {
        if !eng.poll_output_rdy(POLL_LIMIT) {
            return false;
        }
        let result = eng.collect_data_block();
        let roff = dequeued * GCM_BLOCK_BYTES;
        let rlen = if dequeued < full { GCM_BLOCK_BYTES } else { tail };
        unpack_block(&result, &mut dst[roff..roff + rlen]);
        dequeued += 1;
    }

    true
}

/// Read the computed tag from the engine and compare it against the
/// expected tag in constant time to avoid timing side-channels.
fn verify_computed_tag(eng: &GcmEngine, expected: &[u8; AUTH_TAG_SIZE]) -> Result<(), CryptoError> {
    if !eng.poll_saved_cntxt_rdy(POLL_LIMIT) {
        return Err(CryptoError::HardwareTimeout);
    }
    let tag_words = eng.collect_tag();
    let mut computed = [0u8; AUTH_TAG_SIZE];
    unpack_block(&tag_words, &mut computed);

    let mut diff: u8 = 0;
    for i in 0..AUTH_TAG_SIZE {
        diff |= computed[i] ^ expected[i];
    }
    if diff != 0 {
        Err(CryptoError::BadAuthTag)
    } else {
        Ok(())
    }
}

/// Read the computed tag from the engine into a caller-provided buffer.
fn read_tag_into(eng: &GcmEngine, out: &mut [u8; AUTH_TAG_SIZE]) -> Result<(), CryptoError> {
    if !eng.poll_saved_cntxt_rdy(POLL_LIMIT) {
        return Err(CryptoError::HardwareTimeout);
    }
    let tag_words = eng.collect_tag();
    unpack_block(&tag_words, out);
    Ok(())
}

// ─── Public AES-GCM API (hardware-backed) ─────────────────────────

pub fn aes_gcm_encrypt<const N: usize>(
    plaintext: &[u8],
    key: &[u8; 16],
    iv: &[u8; 12],
    associated_data: &[u8],
) -> Result<(Vec<u8, N>, [u8; AUTH_TAG_SIZE]), CryptoError> {
    let eng = GcmEngine::new();

    eng.load_key_128(key);

    if !begin_gcm_session(&eng, iv, true, plaintext.len() as u32, associated_data.len() as u32) {
        return Err(CryptoError::HardwareTimeout);
    }

    if !submit_aad(&eng, associated_data) {
        return Err(CryptoError::HardwareTimeout);
    }

    let mut buffer: Vec<u8, N> = Vec::new();
    buffer
        .resize(plaintext.len(), 0)
        .map_err(|_| CryptoError::InvalidInput)?;

    if !run_pipeline(&eng, plaintext, &mut buffer, plaintext.len()) {
        return Err(CryptoError::AesGcmEncryptError);
    }

    let mut auth_tag = [0u8; AUTH_TAG_SIZE];
    read_tag_into(&eng, &mut auth_tag)?;

    Ok((buffer, auth_tag))
}

pub fn aes_gcm_encrypt_in_place(
    plaintext: &mut [u8],
    key: &[u8; 16],
    iv: &[u8; 12],
    associated_data: &[u8],
) -> Result<[u8; AUTH_TAG_SIZE], CryptoError> {
    let eng = GcmEngine::new();

    eng.load_key_128(key);

    if !begin_gcm_session(&eng, iv, true, plaintext.len() as u32, associated_data.len() as u32) {
        return Err(CryptoError::HardwareTimeout);
    }

    if !submit_aad(&eng, associated_data) {
        return Err(CryptoError::HardwareTimeout);
    }

    // In-place is safe: the pipeline depth-2 guarantee means we always
    // read a block from the engine before overwriting that same offset
    // in the source buffer.
    let len = plaintext.len();
    let src_ptr = plaintext.as_ptr();
    // SAFETY: we need to alias plaintext as both src and dst. The
    // pipeline ensures block N is read from `src` before block N-2 is
    // written to `dst`, so with depth=2 there is no true data race.
    let src_alias = unsafe { core::slice::from_raw_parts(src_ptr, len) };

    if !run_pipeline(&eng, src_alias, plaintext, len) {
        return Err(CryptoError::AesGcmEncryptError);
    }

    let mut auth_tag = [0u8; AUTH_TAG_SIZE];
    read_tag_into(&eng, &mut auth_tag)?;

    Ok(auth_tag)
}

pub fn aes_gcm_decrypt<const N: usize>(
    ciphertext: &[u8],
    key: &[u8; 16],
    iv: &[u8; 12],
    auth_tag: &[u8; AUTH_TAG_SIZE],
    associated_data: &[u8],
) -> Result<Vec<u8, N>, CryptoError> {
    let eng = GcmEngine::new();

    eng.load_key_128(key);

    if !begin_gcm_session(&eng, iv, false, ciphertext.len() as u32, associated_data.len() as u32) {
        return Err(CryptoError::HardwareTimeout);
    }

    if !submit_aad(&eng, associated_data) {
        return Err(CryptoError::HardwareTimeout);
    }

    let mut buffer: Vec<u8, N> = Vec::new();
    buffer
        .resize(ciphertext.len(), 0)
        .map_err(|_| CryptoError::InvalidInput)?;

    if !run_pipeline(&eng, ciphertext, &mut buffer, ciphertext.len()) {
        return Err(CryptoError::AesGcmDecryptError);
    }

    verify_computed_tag(&eng, auth_tag)?;

    Ok(buffer)
}

pub fn aes_gcm_decrypt_in_place(
    ciphertext: &mut [u8],
    key: &[u8; 16],
    iv: &[u8; 12],
    auth_tag: &[u8; AUTH_TAG_SIZE],
    associated_data: &[u8],
) -> Result<(), CryptoError> {
    let eng = GcmEngine::new();

    eng.load_key_128(key);

    if !begin_gcm_session(&eng, iv, false, ciphertext.len() as u32, associated_data.len() as u32) {
        return Err(CryptoError::HardwareTimeout);
    }

    if !submit_aad(&eng, associated_data) {
        return Err(CryptoError::HardwareTimeout);
    }

    let len = ciphertext.len();
    let src_ptr = ciphertext.as_ptr();
    let src_alias = unsafe { core::slice::from_raw_parts(src_ptr, len) };

    if !run_pipeline(&eng, src_alias, ciphertext, len) {
        return Err(CryptoError::AesGcmDecryptError);
    }

    verify_computed_tag(&eng, auth_tag)?;

    Ok(())
}

// ─── Hybrid (asymmetric) encryption ───────────────────────────────
//
// X25519 ECDH key agreement → HKDF-SHA256 key derivation → AES-128-GCM.
// An ephemeral keypair is generated per encryption so that only the
// holder of the static private key can recover the shared secret.

pub fn asymmetric_encrypt_in_place<const N: usize>(
    plaintext: &mut [u8],
    public_key: &PublicKey,
) -> Result<([u8; NONCE_SIZE], [u8; AUTH_TAG_SIZE], PublicKey), CryptoError> {
    // Can just generate 32 bytes using random_bytes() and use that as the ephemeral secret
    // let mut rng = SecureRng::new().map_err(|_| CryptoError::RngError)?;

    // let ephemeral_secret = EphemeralSecret::random_from_rng(&mut rng);

    // Creates a public key specifically for this batch of ciphertext. This public key gets sent
    // along with the ciphertext and can be used to derive the secret key to decrypt it.

    // let cipher_public_key = PublicKey::from(&ephemeral_secret);

    let secret = critical_section::with(|cs| {
        GLOBAL_SECRET
            .borrow(cs)
            .borrow_mut()
            .take()                          // moves it out, leaves None behind
            .expect("crypto not initialised")
    });


    let shared_secret = secret.diffie_hellman(public_key);
    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut aes_key: [u8; 16] = [0; 16];
    hk.expand(b"aes-gcm key", &mut aes_key)
        .map_err(|_| CryptoError::AsymmetricKeyError)?;

    let nonce: [u8; 12] = critical_section::with(|cs| {
        GLOBAL_RNG
            .borrow(cs)
            .borrow_mut()
            .as_mut()
            .expect("rng not initialised")
            .random_array()
    })
    .map_err(|_| CryptoError::RngError)?;

    let auth_tag = aes_gcm_encrypt_in_place(plaintext, &aes_key, &nonce, &[])
        .map_err(|_| CryptoError::AesGcmEncryptError)?;
    let pub_key = critical_section::with(|cs| {
        *GLOBAL_PUB_KEY
            .borrow(cs)
            .borrow()
            .as_ref()
            .expect("pub key not initialised")
    });


    Ok((nonce, auth_tag, pub_key))
}

/// Decrypts ciphertext produced by hybrid encryption. Recovers the
/// shared AES key via ECDH with the static private key and the
/// per-message ephemeral public key, then verifies + decrypts via
/// hardware AES-128-GCM.
pub fn asymmetric_decrypt<const N: usize>(
    ciphertext: &Vec<u8, N>,
    nonce: &[u8; 12],
    cipher_public_key: &PublicKey,
    auth_tag: &[u8; AUTH_TAG_SIZE],
    private_key: &StaticSecret,
) -> Result<Vec<u8, N>, CryptoError> {
    let shared_secret = private_key.diffie_hellman(cipher_public_key);

    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut aes_key: [u8; 16] = [0; 16];
    hk.expand(b"aes-gcm key", &mut aes_key)
        .map_err(|_| CryptoError::AsymmetricKeyError)?;

    let plaintext = aes_gcm_decrypt(ciphertext.as_slice(), &aes_key, nonce, auth_tag, &[])
        .map_err(|_| CryptoError::AesGcmDecryptError)?;

    Ok(plaintext)
}

pub fn asymmetric_decrypt_in_place(
    ciphertext: &mut [u8],
    nonce: &[u8; 12],
    cipher_public_key: &PublicKey,
    auth_tag: &[u8; AUTH_TAG_SIZE],
    private_key: &StaticSecret,
) -> Result<(), CryptoError> {
    let shared_secret = private_key.diffie_hellman(cipher_public_key);

    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut aes_key: [u8; 16] = [0; 16];
    hk.expand(b"aes-gcm key", &mut aes_key)
        .map_err(|_| CryptoError::AsymmetricKeyError)?;

    aes_gcm_decrypt_in_place(ciphertext, &aes_key, nonce, auth_tag, &[])
        .map_err(|_| CryptoError::AesGcmDecryptError)?;

    Ok(())
}

// ─── Ed25519 signing / verification ───────────────────────────────

/// Sign a file digest using Ed25519.
pub fn ecc_sign_file_digest(
    digest: &[u8],
    private_key_bytes: &[u8; PRIVATE_KEY_SIZE],
) -> Result<Signature, AuthError> {
    let signing_key = SigningKey::from_bytes(private_key_bytes);
    let signature: Signature = signing_key.sign(digest);
    Ok(signature)
}

/// Verify an Ed25519 signature over a file digest.
pub fn ecc_verify_file_digest(
    signature: &Signature,
    digest: &[u8],
    public_key_bytes: &[u8; PUBLIC_KEY_SIZE],
) -> Result<(), AuthError> {
    let verifying_key =
        VerifyingKey::from_bytes(public_key_bytes).map_err(|_| AuthError::KeyImportFailed)?;

    verifying_key
        .verify(digest, signature)
        .map_err(|_| AuthError::VerificationFailed)
}