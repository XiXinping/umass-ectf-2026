//! Group permissions and key lookup.
//!
//! Each file group has an associated set of cryptographic keys and permission
//! flags that control read, write, and receive access. The backing data lives
//! in the build-time `secrets` module; this module provides typed accessors.

use crate::secrets;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{VerifyingKey, hazmat::ExpandedSecretKey};

/// Pre-computed AES key created by performing Diffie-Hellman key exchange using the public key
/// of the group and the HSM's local secret. Used for asymmetric decryption.
pub type EncryptKey = [u8; 16];

// Diffie-Hellman private key used to derive shared secret. Used for asymmetric decryption.
pub type DecryptKey = [u8; 32];

/// Public-private keypair for Elliptic-Curve Diffie Hellman key exchange. Used for asymmetric
/// encryption.
#[derive(Clone, Copy)]
pub struct EcdhKeyPair {
    pub public_key: [u8; 32],
    pub private_key: Option<[u8; 32]>,
}

/// Public-private keypair for Elliptic-Curve Digital Signature Algorithm. Used for signing and
/// verification.
#[derive(Clone, Copy)]
pub struct EcdsaKeyPair {
    pub public_key: [u8; 32],
    pub private_key: Option<[u8; 32]>,
}

/// Public-private keypair for Elliptic-Curve Digital Signature Algorithm. Used for signing and
/// verification.
#[derive(Clone)]
pub struct SignatureKeyPair {
    pub signing_key: Option<SigningKey>,
    pub verifying_key: VerifyingKey,
}

/// Symmetric encrypt/decrypt key pair for a single permission type (read or receive).
#[derive(Clone)]
pub struct EncryptionKeyPair {
    pub encrypt_key: EncryptKey,
    pub decrypt_key: DecryptKey,
}

/// Complete set of cryptographic keys for one file group.
#[derive(Clone)]
pub struct KeyPairSet {
    pub read_keys: EncryptionKeyPair,
    pub write_keys: SignatureKeyPair,
    pub receive_keys: EncryptionKeyPair,
}

/// The three kinds of access that can be granted for a file group.
#[derive(Clone, Copy)]
pub enum PermissionType {
    Read,
    Write,
    Receive,
}

/// Per-group permission flags indicating which operations this HSM may perform.
#[derive(Clone)]
pub struct GroupPermission {
    pub group_id: u16,
    pub read_perm: bool,
    pub write_perm: bool,
    pub receive_perm: bool,
}

/// Group-scoped encryption key pair for read operations.
#[derive(Clone)]
pub struct ReadKeyPair {
    pub group_id: u16,
    pub key_pair: EncryptionKeyPair,
}

/// Group-scoped encryption key pair for receive operations.
#[derive(Clone)]
pub struct ReceiveKeyPair {
    pub group_id: u16,
    pub key_pair: EncryptionKeyPair,
}

/// Group-scoped signature key pair for write operations.
#[derive(Clone)]
pub struct WriteKeyPair {
    pub group_id: u16,
    pub key_pair: SignatureKeyPair,
}

// ─── Key lookup functions ──────────────────────────────────────────

/// Retrieve the expanded Ed25519 secret key for signing files in `group_id`.
pub fn get_expanded_secret_key(group_id: u16) -> Option<ExpandedSecretKey> {
    let raw = secrets::RAW_WRITE_KEYS
        .iter()
        .find(|k| k.group_id == group_id)?;

    let scalar_bytes = raw.expanded_scalar?;
    let prefix = raw.expanded_prefix?;

    Some(ExpandedSecretKey {
        scalar: Scalar::from_bytes_mod_order(scalar_bytes),
        hash_prefix: prefix,
    })
}

/// Retrieve the Ed25519 verifying key for `group_id`.
pub fn get_verifying_key(group_id: u16) -> Option<VerifyingKey> {
    let raw = secrets::RAW_WRITE_KEYS
        .iter()
        .find(|k| k.group_id == group_id)?;
    Some(VerifyingKey::from_bytes(&raw.verifying_key_bytes).ok()?)
}

/// Retrieve the symmetric encryption key for reading files in `group_id`.
pub fn get_read_encrypt_key(group_id: u16) -> Option<EncryptKey> {
    secrets::READ_KEYS
        .iter()
        .find(|g| g.group_id == group_id)
        .map(|g| g.key_pair.encrypt_key)
}

/// Retrieve the ECDH private key for decrypting files in `group_id`.
pub fn get_read_decrypt_key(group_id: u16) -> Option<DecryptKey> {
    secrets::READ_KEYS
        .iter()
        .find(|g| g.group_id == group_id)
        .map(|g| g.key_pair.decrypt_key)
}

/// Retrieve the symmetric encryption key for receiving files in `group_id`.
pub fn get_receive_encrypt_key(group_id: u16) -> Option<EncryptKey> {
    secrets::RECEIVE_KEYS
        .iter()
        .find(|g| g.group_id == group_id)
        .map(|g| g.key_pair.encrypt_key)
}

/// Retrieve the ECDH private key for decrypting received files in `group_id`.
pub fn get_receive_decrypt_key(group_id: u16) -> Option<DecryptKey> {
    secrets::RECEIVE_KEYS
        .iter()
        .find(|g| g.group_id == group_id)
        .map(|g| g.key_pair.decrypt_key)
}

/// Check whether this HSM holds a specific permission for `group_id`.
pub fn has_permission(group_id: u16, permission_type: PermissionType) -> bool {
    secrets::PERMISSIONS
        .iter()
        .find(|g| g.group_id == group_id)
        .map(|g| match permission_type {
            PermissionType::Read => g.read_perm,
            PermissionType::Write => g.write_perm,
            PermissionType::Receive => g.receive_perm,
        })
        .unwrap_or(false)
}