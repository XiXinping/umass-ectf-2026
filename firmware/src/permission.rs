use defmt::println;
use heapless::Vec;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::{NUM_SHARED_SECRETS, SharedSecrets};
use crate::secrets::{NUM_PERMS, PERMISSIONS};
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

#[derive(Clone, Copy)]
pub struct KeyPairSet {
    pub read_keys: EcdhKeyPair,
    pub write_keys: EcdsaKeyPair,
    pub receive_keys: EcdhKeyPair,
}

#[derive(Clone, Copy)]
pub enum PermissionType {
    Read,
    Write,
    Receive,
}

// permission.rs
#[derive(Clone, Copy)]
pub struct GroupPermission {
    pub group_id: u16,
    pub read_perm: bool,
    pub write_perm: bool,
    pub receive_perm: bool,
    pub keys: KeyPairSet,
}

pub fn get_private_key(group_id: u16, permission_type: PermissionType) -> Option<[u8; 32]> {
    for group in PERMISSIONS {
        if group.group_id != group_id {
            continue;
        }
        match permission_type {
            PermissionType::Read => return group.keys.read_keys.private_key,
            PermissionType::Write => return group.keys.write_keys.private_key,
            PermissionType::Receive => return group.keys.receive_keys.private_key,
        }
    }
    None
}

pub fn get_public_key(group_id: u16, permission_type: PermissionType) -> Option<[u8; 32]> {
    for group in PERMISSIONS {
        if group.group_id != group_id {
            continue;
        }
        match permission_type {
            PermissionType::Read => return Some(group.keys.read_keys.public_key),
            PermissionType::Write => return Some(group.keys.write_keys.public_key),
            PermissionType::Receive => return Some(group.keys.receive_keys.public_key),
        }
    }
    None
}

pub fn has_permission(group_id: u16, permission_type: PermissionType) -> bool {
    for group in PERMISSIONS {
        if group.group_id != group_id {
            continue;
        }
        match permission_type {
            PermissionType::Read => return group.read_perm,
            PermissionType::Write => return group.write_perm,
            PermissionType::Receive => return group.receive_perm,
        }
    }
    false
}

/// Pre-compute Diffie-Hellman shared secrets to save on encryption time.
pub fn gen_shared_secrets(secret: StaticSecret) -> [SharedSecrets; NUM_SHARED_SECRETS] {
    let mut secret_list: Vec<SharedSecrets, NUM_SHARED_SECRETS> = Vec::new();
    for group in PERMISSIONS {
        let read_pub_key = get_public_key(group.group_id, PermissionType::Read).unwrap();
        let recv_pub_key = get_public_key(group.group_id, PermissionType::Receive).unwrap();
        let read_shared_secret = secret.diffie_hellman(&PublicKey::from(read_pub_key));
        let recv_shared_secret = secret.diffie_hellman(&PublicKey::from(recv_pub_key));

        let hk = Hkdf::<Sha256>::new(None, read_shared_secret.as_bytes());
        let mut read_aes_key: [u8; 16] = [0; 16];
        hk.expand(b"aes-gcm key", &mut read_aes_key).unwrap();

        let hk = Hkdf::<Sha256>::new(None, recv_shared_secret.as_bytes());
        let mut recv_aes_key: [u8; 16] = [0; 16];
        hk.expand(b"aes-gcm key", &mut recv_aes_key).unwrap();

        println!("read_pub_key: {:?}", read_pub_key);
        let _ = secret_list.push(SharedSecrets {
            public_key: read_pub_key.into(),
            shared_secret: read_aes_key,
        });
        println!("recv_pub_key: {:?}", recv_pub_key);
        let _ = secret_list.push(SharedSecrets {
            public_key: recv_pub_key.into(),
            shared_secret: recv_aes_key,
        });
    }
    match secret_list.into_array() {
        Ok(list) => list,
        Err(_) => panic!(),
    }
}
