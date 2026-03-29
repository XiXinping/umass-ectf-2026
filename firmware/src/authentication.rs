use pbkdf2::pbkdf2;
use sha2::Sha256;
use hmac::Hmac;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

pub enum SecurityStatus {
    Success,
    InvalidLength,
    AuthFail,
}

pub const PIN_HASH_SIZE: usize = 32;

pub const PIN_SALT_SIZE: usize = 16;

pub const PIN_LENGTH: usize = 6;

/* 
pub fn pin_is_lower_hex(pin: &[u8]) -> bool {
    if pin.len() != PIN_LENGTH {
        return false;
    }

    pin.iter().all(|&c| {
        let is_digit = c >= b'0' && c <= b'9';
        let is_lower_hex_alpha = c >= b'a' && c <= b'f';
        is_digit || is_lower_hex_alpha
    })
}
*/

pub fn verify_pin(pin: &[u8], pin_salt: &[u8], expected_hash: &[u8]) -> SecurityStatus {
    if pin.len() != PIN_LENGTH || pin_salt.len() != PIN_SALT_SIZE {
        return SecurityStatus::InvalidLength;
    }

    let mut derived  = [0u8; PIN_HASH_SIZE];

    if pbkdf2::<Hmac<Sha256>>(pin, pin_salt, 1_234_567, &mut derived).is_err() {
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