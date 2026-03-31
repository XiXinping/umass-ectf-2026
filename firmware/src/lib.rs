#![no_std]
#![no_main]

use defmt_rtt as _;

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

#[cfg(test)]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// #[cfg(test)]
// use defmt_rtt as _;
