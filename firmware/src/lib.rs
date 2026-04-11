#![no_std]
#![no_main]

use defmt_rtt as _;

use crate::random::SecureRng;

use core::cell::RefCell;
use critical_section::Mutex;

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

pub static GLOBAL_RNG: Mutex<RefCell<Option<SecureRng>>> = Mutex::new(RefCell::new(None));

#[cfg(test)]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
