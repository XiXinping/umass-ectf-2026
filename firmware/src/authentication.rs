use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

pub const PIN_HASH_SIZE: usize = 32;
pub const PIN_SALT_SIZE: usize = 16;
pub const PIN_LENGTH: usize = 6;

/// The result of a pin verification.
pub enum SecurityStatus {
    /// Successfully verified the pin against the provided hash.
    Success,
    /// The pin was not 6 digits.
    InvalidLength,
    /// Failed to verify the pin against the provided hash.
    AuthFail,
}

/// Verify that the pin matches the expected hash by performing 5 rounds of PBKDF2 using the
/// provided salt.
pub fn verify_pin(pin: &[u8], pin_salt: &[u8], expected_hash: &[u8]) -> SecurityStatus {
    if pin.len() != PIN_LENGTH || pin_salt.len() != PIN_SALT_SIZE {
        return SecurityStatus::InvalidLength;
    }

    let mut derived = [0u8; PIN_HASH_SIZE];

    if pbkdf2::<Hmac<Sha256>>(pin, pin_salt, 5, &mut derived).is_err() {
        return SecurityStatus::AuthFail;
    }

    let matches = derived.ct_eq(expected_hash);

    derived.zeroize();

    if matches.into() {
        SecurityStatus::Success
    } else {
        SecurityStatus::AuthFail
    }
}
