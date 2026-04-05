use crate::random::SecureRng;
use crate::serialization::serde_x25519_pubkey;
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{AeadInPlace, KeyInit},
};
use heapless::Vec;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use p256::ecdsa::SigningKey;

use p256::ecdsa::{
    Signature, VerifyingKey,
    signature::{Signer, Verifier},
};

/// The AES-256 block size.
pub const AES_BLOCK_SIZE: usize = 32;
/// The size of an AES-GCM nonce.
pub const NONCE_SIZE: usize = 12;
/// The size of an AES-GCM authentication tag.
pub const AUTH_TAG_SIZE: usize = 16;
pub const PUBLIC_KEY_SIZE: usize = size_of::<PublicKey>();
pub const PRIVATE_KEY_SIZE: usize = 32;
/// The size of an ED25519 signature
pub const SIGNATURE_SIZE: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum CryptoError {
    /// Input is too large
    InvalidInput,
    /// Failure in securely generating random numbers
    RngError,
    /// Failed to derive assymetric key
    AsymmetricKeyError,
    /// Failed to validate authentication tag when decrypting with AES-GCM
    BadAuthTag,
    /// Invalid key when decrypting with AES-GCM
    BadAesKey,
    /// Failed to encrypt using AES-GCM
    AesGcmEncryptError,
    /// Failed to decrypt using AES-GCM
    AesGcmDecryptError,
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

/// A struct containing the result of calling assymetric_encrypt(). The result of a hybrid
/// encryption contains the ciphertext, the AES shared secret, and an AES-GCM authentication tag.
#[repr(C)]
pub struct AsymmetricEncrypted<const N: usize> {
    pub ciphertext: [u8; N],
    pub nonce: [u8; 12],
    // #[serde(with = "serde_x25519_pubkey")]
    pub cipher_public_key: PublicKey,
    pub auth_tag: [u8; AUTH_TAG_SIZE],
}

#[derive(Serialize, Deserialize)]
pub struct AsymmetricEncryptedMetadata {
    pub nonce: [u8; 12],
    #[serde(with = "serde_x25519_pubkey")]
    pub cipher_public_key: PublicKey,
    pub auth_tag: [u8; AUTH_TAG_SIZE],
}

pub fn aes_gcm_encrypt<const N: usize>(
    plaintext: &[u8],
    key: &[u8; 32],
    iv: &[u8; 12],
    associated_data: &[u8],
) -> Result<(Vec<u8, N>, [u8; AUTH_TAG_SIZE]), aes_gcm::Error> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let nonce = Nonce::from_slice(iv);
    let cipher = Aes256Gcm::new(key);

    let mut buffer: Vec<u8, N> = Vec::new();

    buffer
        .extend_from_slice(plaintext)
        .map_err(|_| aes_gcm::Error)?;

    let auth_tag = cipher.encrypt_in_place_detached(nonce, associated_data, &mut buffer)?;

    Ok((buffer, auth_tag.into()))
}

pub fn aes_gcm_encrypt_in_place(
    plaintext: &mut [u8],
    key: &[u8; 32],
    iv: &[u8; 12],
    associated_data: &[u8],
) -> Result<[u8; AUTH_TAG_SIZE], aes_gcm::Error> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let nonce = Nonce::from_slice(iv);
    let cipher = Aes256Gcm::new(key);

    let auth_tag = cipher.encrypt_in_place_detached(nonce, associated_data, plaintext)?;

    Ok(auth_tag.into())
}

pub fn aes_gcm_decrypt<const N: usize>(
    ciphertext: &[u8],
    key: &[u8; 32],
    iv: &[u8; 12],
    auth_tag: &[u8; AUTH_TAG_SIZE],
    associated_data: &[u8],
) -> Result<Vec<u8, N>, aes_gcm::Error> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let nonce = Nonce::from_slice(iv);
    let cipher = Aes256Gcm::new(key);

    let mut buffer: Vec<u8, N> = Vec::new();

    buffer
        .extend_from_slice(ciphertext)
        .map_err(|_| aes_gcm::Error)?;

    cipher.decrypt_in_place_detached(nonce, associated_data, &mut buffer, auth_tag.into())?;

    Ok(buffer)
}

pub fn aes_gcm_decrypt_in_place(
    ciphertext: &mut [u8],
    key: &[u8; 32],
    iv: &[u8; 12],
    auth_tag: &[u8; AUTH_TAG_SIZE],
    associated_data: &[u8],
) -> Result<(), aes_gcm::Error> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let nonce = Nonce::from_slice(iv);
    let cipher = Aes256Gcm::new(key);

    cipher.decrypt_in_place_detached(nonce, associated_data, ciphertext, auth_tag.into())?;

    Ok(())
}

// Encrypts the contents of a file using assymetric cryptography. The output contains the
// ciphertext, the shared secret, and an auth tag
// Currently initializes a new TRNG instance every call. This may be changed.
// pub fn asymmetric_encrypt<const N: usize>(
//     plaintext: &Vec<u8, N>,
//     public_key: &PublicKey,
// ) -> Result<AsymmetricEncrypted<N>, CryptoError> {
//     // Can just generate 32 bytes using random_bytes() and use that as the ephemeral secret
//     let mut rng = SecureRng::new().map_err(|_| CryptoError::RngError)?;
//     let ephemeral_secret = EphemeralSecret::random_from_rng(&mut rng);
//     // Creates a public key specifically for this batch of ciphertext. This public key gets sent
//     // along with the ciphertext and can be used to derive the secret key to decrypt it.
//     let cipher_public_key = PublicKey::from(&ephemeral_secret);
//
//     let shared_secret = ephemeral_secret.diffie_hellman(public_key);
//     let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
//     let mut aes_key: [u8; 32] = [0; 32];
//     hk.expand(b"aes-gcm key", &mut aes_key)
//         .map_err(|_| CryptoError::AsymmetricKeyError)?;
//
//     let nonce: [u8; 12] = rng.random_array().map_err(|_| CryptoError::RngError)?;
//
//     let (ciphertext, auth_tag) = aes_gcm_encrypt(plaintext.as_slice(), &aes_key, &nonce, &[])
//         .map_err(|_| CryptoError::AesGcmEncryptError)?;
//     Ok(AsymmetricEncrypted {
//         ciphertext,
//         nonce,
//         cipher_public_key,
//         auth_tag,
//     })
// }

pub fn asymmetric_encrypt_in_place<const N: usize>(
    plaintext: &mut [u8],
    public_key: &PublicKey,
) -> Result<([u8; NONCE_SIZE], [u8; AUTH_TAG_SIZE], PublicKey), CryptoError> {
    // Can just generate 32 bytes using random_bytes() and use that as the ephemeral secret
    let mut rng = SecureRng::new().map_err(|_| CryptoError::RngError)?;
    let ephemeral_secret = EphemeralSecret::random_from_rng(&mut rng);
    // Creates a public key specifically for this batch of ciphertext. This public key gets sent
    // along with the ciphertext and can be used to derive the secret key to decrypt it.
    let cipher_public_key = PublicKey::from(&ephemeral_secret);

    let shared_secret = ephemeral_secret.diffie_hellman(public_key);
    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut aes_key: [u8; 32] = [0; 32];
    hk.expand(b"aes-gcm key", &mut aes_key)
        .map_err(|_| CryptoError::AsymmetricKeyError)?;

    let nonce: [u8; 12] = rng.random_array().map_err(|_| CryptoError::RngError)?;

    let auth_tag = aes_gcm_encrypt_in_place(plaintext, &aes_key, &nonce, &[])
        .map_err(|_| CryptoError::AesGcmEncryptError)?;
    Ok((nonce, auth_tag, cipher_public_key))
}

/// Decrypts the contents of a file encrypted with assymetric cryptography. Uses the ciphertext
/// public key generated from assymetric_encrypt() to derive a symmetric key to decrypt the
/// ciphertext.
pub fn asymmetric_decrypt<const N: usize>(
    ciphertext: &Vec<u8, N>,
    nonce: &[u8; 12],
    cipher_public_key: &PublicKey,
    auth_tag: &[u8; AUTH_TAG_SIZE],
    private_key: &StaticSecret,
) -> Result<Vec<u8, N>, CryptoError> {
    let shared_secret = private_key.diffie_hellman(cipher_public_key);

    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut aes_key: [u8; 32] = [0; 32];
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
    let mut aes_key: [u8; 32] = [0; 32];
    hk.expand(b"aes-gcm key", &mut aes_key)
        .map_err(|_| CryptoError::AsymmetricKeyError)?;

    aes_gcm_decrypt_in_place(ciphertext, &aes_key, nonce, auth_tag, &[])
        .map_err(|_| CryptoError::AesGcmDecryptError)?;

    Ok(())
}

/// Sign a file digest using ECDSA.
pub fn ecc_sign_file_digest(
    digest: &[u8],
    private_key_bytes: &[u8; PRIVATE_KEY_SIZE],
) -> Result<Signature, AuthError> {
    let signing_key =
        SigningKey::from_slice(private_key_bytes).map_err(|_| AuthError::KeyImportFailed)?;

    let signature: Signature = signing_key.sign(digest);

    Ok(signature)
}

/// Use a public key to verify that a file was signed using ECDSA with the corresponding private key.
pub fn ecc_verify_file_digest(
    signature: &Signature,
    digest: &[u8],
    public_key_bytes: &[u8],
) -> Result<(), AuthError> {
    let verifying_key =
        VerifyingKey::from_sec1_bytes(public_key_bytes).map_err(|_| AuthError::KeyImportFailed)?;

    verifying_key
        .verify(digest, signature)
        .map_err(|_| AuthError::VerificationFailed)
}
