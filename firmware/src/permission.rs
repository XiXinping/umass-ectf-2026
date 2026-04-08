use heapless::Vec;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

use crate::secrets::{NUM_PERMS, PERMISSIONS};

#[derive(Clone, Copy)]
pub struct KeyPair {
    pub public_key: [u8; 32], // adjust size to match your actual key length
    pub private_key: Option<[u8; 32]>,
}

#[derive(Clone, Copy)]
pub struct KeyPairSet {
    pub read_keys: KeyPair,
    pub write_keys: KeyPair,
    pub receive_keys: KeyPair,
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

pub struct SharedSecrets {
    group_id: u16,
    read_secret: SharedSecret,
    receive_secret: SharedSecret,
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

pub fn gen_shared_secrets(secret: StaticSecret) -> [SharedSecrets; NUM_PERMS] {
    let mut secret_list: Vec<SharedSecrets, NUM_PERMS> = Vec::new();
    for group in PERMISSIONS {
        let read_pub_key = get_public_key(group.group_id, PermissionType::Read).unwrap();
        let recv_pub_key = get_public_key(group.group_id, PermissionType::Receive).unwrap();
        let _ = secret_list.push(SharedSecrets {
            group_id: group.group_id,
            read_secret: secret.diffie_hellman(&PublicKey::from(read_pub_key)),
            receive_secret: secret.diffie_hellman(&PublicKey::from(recv_pub_key)),
        });
    }
    match secret_list.into_array() {
        Ok(list) => list,
        Err(_) => panic!(),
    }
}
