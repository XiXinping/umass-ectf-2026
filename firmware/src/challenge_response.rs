// Challenge-response authentication implementation
// This module implements the challenge-response authentication mechanism using ECDSA with the P-256 curve
// Using x9.63 format keys
use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};

use crate::random::SecureRng;

// Nonce size
pub const NONCE_SIZE: usize = 32;
// P-256 private key size
pub const PRIVATE_KEY_SIZE: usize = 32;
// P-256 public key sizes
pub const PUBLIC_KEY_UNCOMPRESSED_SIZE: usize = 65;
pub const PUBLIC_KEY_COMPRESSED_SIZE: usize = 33;
// Signature size
pub const SIGNATURE_SIZE: usize = 64;

// Error types for authentication operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    // Random number generation failed.
    RngFailed,
    // Could not import a key from raw bytes.
    KeyImportFailed,
    // ECDSA signing failed.
    SigningFailed,
    // ECDSA verification failed (bad signature or wrong key).
    VerificationFailed,
    // Signature bytes could not be parsed.
    BadSignatureFormat,
}

// send challenge nonce
pub fn gen_challenge_nonce() -> Result<[u8; NONCE_SIZE], AuthError> {
    let mut rng = SecureRng::new().map_err(|_| AuthError::RngFailed)?;
    rng.random_array().map_err(|_| AuthError::RngFailed)
}

// sign nonce
pub fn sign_nonce(
    nonce: &[u8],
    private_key_bytes: &[u8; PRIVATE_KEY_SIZE],
) -> Result<Signature, AuthError> {
    let signing_key =
        SigningKey::from_slice(private_key_bytes).map_err(|_| AuthError::KeyImportFailed)?;

    // RFC 6979 deterministic — no RNG needed
    let signature: Signature = signing_key.sign(nonce);
    Ok(signature)
}

// verify signature (ECDSA P-256 signature over a nonce / digest)
//
// `public_key_bytes` must be SEC1-encoded (either uncompressed 65 B
// starting with 0x04, or compressed 33 B starting with 0x02 / 0x03).
// Sec1 uses the same encoding as x9.63
pub fn verify_nonce_sig(
    signature: &Signature,
    nonce: &[u8],
    public_key_bytes: &[u8],
) -> Result<(), AuthError> {
    let verifying_key =
        VerifyingKey::from_sec1_bytes(public_key_bytes).map_err(|_| AuthError::KeyImportFailed)?;

    verifying_key
        .verify(nonce, signature)
        .map_err(|_| AuthError::VerificationFailed)
}

// helpers:

// Export the public key from a private key in SEC1 uncompressed format
// (same as `wc_ecc_export_x963` from our C code)
pub fn public_key_from_private(
    private_key_bytes: &[u8; PRIVATE_KEY_SIZE],
) -> Result<[u8; PUBLIC_KEY_UNCOMPRESSED_SIZE], AuthError> {
    let signing_key =
        SigningKey::from_slice(private_key_bytes).map_err(|_| AuthError::KeyImportFailed)?;

    let verifying_key = signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false); // false = uncompressed
    let bytes = point.as_bytes();

    let mut out = [0u8; PUBLIC_KEY_UNCOMPRESSED_SIZE];
    out.copy_from_slice(bytes);
    Ok(out)
}
