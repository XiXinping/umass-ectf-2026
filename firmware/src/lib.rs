#![no_std]
#![no_main]

use defmt_rtt as _;

pub mod aes_hardware_accel;
pub mod authentication;
pub mod challenge_response;
pub mod command;
pub mod crypto;
pub mod filesystem;
pub mod flash;
pub mod host;
pub mod permission;
pub mod random;
pub mod secrets;
pub mod secure_filesystem;
pub mod serialization;
// pub mod serde_signature;
// pub mod serde_x25519_pubkey;

#[cfg(test)]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// #[cfg(test)]
// use defmt_rtt as _;
