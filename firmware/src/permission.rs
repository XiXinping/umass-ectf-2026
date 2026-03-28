use elliptic_curve::{PublicKey, SecretKey};

pub struct KeyPair {
    pub public_key: PublicKey, // adjust size to match your actual key length
    pub private_key: Option<SecretKey>,
}

pub struct KeyPairSet {
    pub read_keys: KeyPair,
    pub write_keys: KeyPair,
    pub receive_keys: KeyPair,
}

// permission.rs
pub struct GroupPermission {
    pub group_id: u16,
    pub read_perm: bool,
    pub write_perm: bool,
    pub receive_perm: bool,
    pub keys: KeyPairSet,
}
