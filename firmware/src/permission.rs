use crate::secrets::PERMISSIONS;

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
