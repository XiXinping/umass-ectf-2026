use crate::{
    challenge_response::{AuthError, PRIVATE_KEY_SIZE},
    filesystem::MAX_CONTENTS_SIZE,
    random::SecureRng,
};
use aes_gcm::{
    Aes256Gcm, Key, Nonce, Tag as GcmTag,
    aead::{AeadInPlace, KeyInit, heapless::Vec as AesVec},
};
use heapless::Vec;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

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

/// A struct containing the result of calling assymetric_encrypt(). The result of a hybrid
/// encryption contains the ciphertext, the AES shared secret, and an AES-GCM authentication tag.
pub struct AsymmetricEncrypted {
    pub ciphertext: Vec<u8, MAX_CONTENTS_SIZE>,
    pub nonce: [u8; 12],
    pub cipher_public_key: PublicKey,
    pub auth_tag: GcmTag,
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

    Ok((Vec::from_slice(buffer.as_slice()).unwrap(), auth_tag))
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

/// Encrypts the contents of a file using assymetric cryptography. The output contains the
/// ciphertext, the shared secret, and an auth tag
/// Currently initializes a new TRNG instance every call. This may be changed.
pub fn asymmetric_encrypt(
    plaintext: &Vec<u8, MAX_CONTENTS_SIZE>,
    public_key: &PublicKey,
) -> Result<AsymmetricEncrypted, CryptoError> {
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

    let (ciphertext, auth_tag) = aes_gcm_encrypt(plaintext.as_slice(), &aes_key, &nonce, &[])
        .map_err(|_| CryptoError::AesGcmEncryptError)?;
    Ok(AsymmetricEncrypted {
        ciphertext,
        nonce,
        cipher_public_key,
        auth_tag,
    })
}

/// Decrypts the contents of a file encrypted with assymetric cryptography. Uses the ciphertext
/// public key generated from assymetric_encrypt() to derive a symmetric key to decrypt the
/// ciphertext.
pub fn asymmetric_decrypt(
    ciphertext: &Vec<u8, MAX_CONTENTS_SIZE>,
    nonce: &[u8; 12],
    cipher_public_key: &PublicKey,
    auth_tag: &GcmTag,
    private_key: &StaticSecret,
) -> Result<Vec<u8, MAX_CONTENTS_SIZE>, CryptoError> {
    let shared_secret = private_key.diffie_hellman(cipher_public_key);

    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut aes_key: [u8; 32] = [0; 32];
    hk.expand(b"aes-gcm key", &mut aes_key)
        .map_err(|_| CryptoError::AsymmetricKeyError)?;

    let plaintext = aes_gcm_decrypt(ciphertext.as_slice(), &aes_key, nonce, auth_tag, &[])
        .map_err(|_| CryptoError::AesGcmDecryptError)?;

    Ok(plaintext)
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
