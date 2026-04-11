use crate::secrets;
use ed25519_dalek::{SigningKey, VerifyingKey};

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

#[derive(Clone)]
pub struct EncryptionKeyPair {
    pub encrypt_key: EncryptKey,
    pub decrypt_key: DecryptKey,
}

#[derive(Clone)]
pub struct KeyPairSet {
    pub read_keys: EncryptionKeyPair,
    pub write_keys: SignatureKeyPair,
    pub receive_keys: EncryptionKeyPair,
}

#[derive(Clone, Copy)]
pub enum PermissionType {
    Read,
    Write,
    Receive,
}

#[derive(Clone)]
pub struct GroupPermission {
    pub group_id: u16,
    pub read_perm: bool,
    pub write_perm: bool,
    pub receive_perm: bool,
    pub keys: KeyPairSet,
}

pub fn get_signing_key(group_id: u16) -> Option<SigningKey> {
    secrets::permissions()
        .iter()
        .find(|g| g.group_id == group_id)
        .and_then(|g| g.keys.write_keys.signing_key.clone())
}

pub fn get_verifying_key(group_id: u16) -> Option<VerifyingKey> {
    secrets::permissions()
        .iter()
        .find(|g| g.group_id == group_id)
        .and_then(|g| Some(g.keys.write_keys.verifying_key))
}

pub fn get_read_encrypt_key(group_id: u16) -> Option<EncryptKey> {
    secrets::permissions()
        .iter()
        .find(|g| g.group_id == group_id)
        .map(|g| g.keys.read_keys.encrypt_key)
}

pub fn get_read_decrypt_key(group_id: u16) -> Option<DecryptKey> {
    secrets::permissions()
        .iter()
        .find(|g| g.group_id == group_id)
        .map(|g| g.keys.read_keys.decrypt_key)
}

pub fn get_receive_encrypt_key(group_id: u16) -> Option<EncryptKey> {
    secrets::permissions()
        .iter()
        .find(|g| g.group_id == group_id)
        .map(|g| g.keys.receive_keys.encrypt_key)
}

pub fn get_receive_decrypt_key(group_id: u16) -> Option<DecryptKey> {
    secrets::permissions()
        .iter()
        .find(|g| g.group_id == group_id)
        .map(|g| g.keys.receive_keys.decrypt_key)
}

pub fn has_permission(group_id: u16, permission_type: PermissionType) -> bool {
    secrets::permissions()
        .iter()
        .find(|g| g.group_id == group_id)
        .map(|g| match permission_type {
            PermissionType::Read => g.read_perm,
            PermissionType::Write => g.write_perm,
            PermissionType::Receive => g.receive_perm,
        })
        .unwrap_or(false)
}
