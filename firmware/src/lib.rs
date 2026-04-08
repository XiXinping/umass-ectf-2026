#![no_std]
#![no_main]

use defmt_rtt as _;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::permission::SharedSecrets;
use crate::random::SecureRng;
use crate::secrets::NUM_PERMS;

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

pub static GLOBAL_SECRET: Mutex<RefCell<Option<StaticSecret>>> = Mutex::new(RefCell::new(None));
pub static GLOBAL_PUB_KEY: Mutex<RefCell<Option<PublicKey>>> = Mutex::new(RefCell::new(None));
pub static GLOBAL_RNG: Mutex<RefCell<Option<SecureRng>>> = Mutex::new(RefCell::new(None));
pub static GLOBAL_SHARED_SECRETS: Mutex<RefCell<Option<[SharedSecrets; NUM_PERMS]>>> =
    Mutex::new(RefCell::new(None));

#[cfg(test)]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
