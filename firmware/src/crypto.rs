use crate::{filesystem::MAX_CONTENTS_SIZE, random::SecureRng};
use aes_gcm::{
    Aes256Gcm, Key, Nonce, Tag as GcmTag,
    aead::{AeadInPlace, KeyInit, heapless::Vec as AesVec},
};
use heapless::Vec;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

use crate::challenge_response_auth;
use p256::ecdsa::SigningKey;

use p256::ecdsa::{
    Signature, VerifyingKey,
    signature::{Signer, Verifier},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum CryptoError {
    /// Input is too large
    InvalidInput,
    /// Failure in securely generating random numbers
    RngFailure,
    /// Failed to derive assymetric key
    AsymmetricKey,
}

/// A struct containing the result of calling assymetric_encrypt(). The result of a hybrid
/// encryption contains the ciphertext, the AES shared secret, and an AES-GCM authentication tag.
struct HybridEncrypted {
    ciphertext: Vec<u8, MAX_CONTENTS_SIZE>,
    shared_secret: SharedSecret,
    auth_tag: GcmTag,
}

pub fn aes_gcm_encrypt(
    plaintext: &[u8],
    key: &[u8; 32],
    iv: &[u8; 12],
    associated_data: &[u8],
) -> Result<(Vec<u8, MAX_CONTENTS_SIZE>, GcmTag), aes_gcm::Error> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let nonce = Nonce::from_slice(iv);
    let cipher = Aes256Gcm::new(key);

    let mut buffer: AesVec<u8, MAX_CONTENTS_SIZE> = AesVec::new();

    buffer
        .extend_from_slice(plaintext)
        .map_err(|_| aes_gcm::Error)?;

    let auth_tag = cipher.encrypt_in_place_detached(nonce, associated_data, &mut buffer)?;

    Ok((
        Vec::from_array(buffer.into_array::<MAX_CONTENTS_SIZE>().unwrap()),
        auth_tag,
    ))
}

pub fn aes_gcm_decrypt(
    ciphertext: &[u8],
    key: &[u8; 32],
    iv: &[u8; 12],
    auth_tag: &GcmTag,
    associated_data: &[u8],
) -> Result<Vec<u8, MAX_CONTENTS_SIZE>, aes_gcm::Error> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let nonce = Nonce::from_slice(iv);
    let cipher = Aes256Gcm::new(key);

    let mut buffer: Vec<u8, MAX_CONTENTS_SIZE> = Vec::new();

    buffer
        .extend_from_slice(ciphertext)
        .map_err(|_| aes_gcm::Error)?;

    cipher.decrypt_in_place_detached(nonce, associated_data, &mut buffer, auth_tag)?;

    Ok(buffer)
}

// Encrypts the contents of a file using assymetric cryptography. The output contains the
// ciphertext, the shared secret, and an auth tag
// Currently initializes a new TRNG instance every call. This may be changed.
pub fn assymetric_encrypt(
    plaintext: Vec<u8, MAX_CONTENTS_SIZE>,
    public_key: &PublicKey,
    // ) -> Result<HybridEncrypted, CryptoError> {
) -> Result<(), CryptoError> {
    // Can just generate 32 bytes using random_bytes() and use that as the ephemeral secret
    let rng = SecureRng::new().map_err(|_| CryptoError::RngFailure)?;
    let ephemeral_secret = EphemeralSecret::random_from_rng(rng);

    let shared_secret = ephemeral_secret.diffie_hellman(public_key);
    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut aes_key: [u8; 32] = [0; 32];
    hk.expand(b"aes-gcm key", &mut aes_key)
        .map_err(|_| CryptoError::AsymmetricKey)?;

    Ok(())
}

pub fn ecc_sign_file_digest(digest: &[u8], private_key_bytes: &[u8; challenge_response_auth::PRIVATE_KEY_SIZE]) -> Result<Signature, challenge_response_auth::AuthError>{
    let signing_key = SigningKey::from_slice(private_key_bytes)
        .map_err(|_| challenge_response_auth::AuthError::KeyImportFailed)?;

    let signature: Signature = signing_key.sign(digest);

    Ok(signature)

}

pub fn ecc_verify_file_digest(
    signature: &Signature,
    digest: &[u8],
    public_key_bytes: &[u8],
) -> Result<(), challenge_response_auth::AuthError> {
    let verifying_key = VerifyingKey::from_sec1_bytes(public_key_bytes)
        .map_err(|_| challenge_response_auth::AuthError::KeyImportFailed)?;

    verifying_key
        .verify(digest, signature)
        .map_err(|_| challenge_response_auth::AuthError::VerificationFailed)
}
