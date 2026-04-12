use crate::secrets;
use defmt::println;
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
}

#[derive(Clone)]
pub struct ReadKeyPair {
    pub group_id: u16,
    pub key_pair: EncryptionKeyPair,
}

#[derive(Clone)]
pub struct ReceiveKeyPair {
    pub group_id: u16,
    pub key_pair: EncryptionKeyPair,
}

#[derive(Clone)]
pub struct WriteKeyPair {
    pub group_id: u16,
    pub key_pair: SignatureKeyPair,
}

pub fn get_signing_key(group_id: u16) -> Option<SigningKey> {
    // for perm in secrets::write_permissions() {
    //     let signing_key_print = match perm.key_pair.signing_key.clone() {
    //         Some(signing_key) => signing_key.to_bytes(),
    //         None => [0; 32],
    //     };
    //     println!(
    //         "{}: {:?} and {:?}",
    //         perm.group_id,
    //         signing_key_print,
    //         perm.key_pair.verifying_key.to_bytes()
    //     );
    // }
    secrets::write_permissions()
        .iter()
        .find(|g| g.group_id == group_id)
        .and_then(|g| g.key_pair.signing_key.clone())
}

pub fn get_verifying_key(group_id: u16) -> Option<VerifyingKey> {
    secrets::write_permissions()
        .iter()
        .find(|g| g.group_id == group_id)
        .and_then(|g| Some(g.key_pair.verifying_key))
}

pub fn get_read_encrypt_key(group_id: u16) -> Option<EncryptKey> {
    secrets::READ_KEYS
        .iter()
        .find(|g| g.group_id == group_id)
        .map(|g| g.key_pair.encrypt_key)
}

pub fn get_read_decrypt_key(group_id: u16) -> Option<DecryptKey> {
    secrets::READ_KEYS
        .iter()
        .find(|g| g.group_id == group_id)
        .map(|g| g.key_pair.decrypt_key)
}

pub fn get_receive_encrypt_key(group_id: u16) -> Option<EncryptKey> {
    secrets::RECEIVE_KEYS
        .iter()
        .find(|g| g.group_id == group_id)
        .map(|g| g.key_pair.encrypt_key)
}

pub fn get_receive_decrypt_key(group_id: u16) -> Option<DecryptKey> {
    secrets::RECEIVE_KEYS
        .iter()
        .find(|g| g.group_id == group_id)
        .map(|g| g.key_pair.decrypt_key)
}

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
