#![no_std]
#![no_main]

use defmt::*;
use ectf_2026::authentication::verify_pin;
use ectf_2026::command;
use ectf_2026::crypto::AsymmetricEncrypted;
use ectf_2026::crypto::asymmetric_decrypt;
use ectf_2026::crypto::asymmetric_encrypt;
use ectf_2026::flash::HwFlash;
use ectf_2026::host::HostUart;
use ectf_2026::random::SecureRng;
use ectf_2026::secrets::PIN_HASH;
use ectf_2026::secrets::PIN_SALT;
use ectf_2026::secure_filesystem::Filesystem;
use embassy_mspm0::uart::{Config, Uart};
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

// use defmt_rtt as _;
use {defmt_rtt as _, panic_probe as _};

/// Custom NMI handler — clears SRAM ECC DED NMI and returns.
/// MSPM0L2228 fires SRAMDED NMI on reads of uninitialized SRAM.
#[cortex_m_rt::exception]
unsafe fn NonMaskableInt() {
    const SYSCTL_NMIICLR: *mut u32 = 0x400B_0078 as *mut u32;
    unsafe { core::ptr::write_volatile(SYSCTL_NMIICLR, 0x7F) };
}

/// Set VTOR to the application vector table address.
unsafe fn set_vtor(addr: u32) {
    const VTOR: *mut u32 = 0xE000_ED08 as *mut u32;
    unsafe { core::ptr::write_volatile(VTOR, addr) };
}

/// Maximum message buffer size (matches sizeof(write_command_t) in C)
const MAX_MSG_SIZE: usize = 8268;

#[cortex_m_rt::entry]
fn main() -> ! {
    unsafe { set_vtor(0x0000_6000) };

    let p = embassy_mspm0::init(Default::default());

    let mut config = Config::default();
    config.baudrate = 115200;

    // UART0 — host/control interface
    let uart0 = unwrap!(Uart::new_blocking(p.UART0, p.PA11, p.PA10, config));
    let mut host = HostUart::new(uart0);
    host.print_debug("Hello Embassy World!");

    // UART1 — transfer interface (neighbor HSM): PA8 TX, PA9 RX
    let uart1 = unwrap!(Uart::new_blocking(p.UART1, p.PA9, p.PA8, config));
    let mut transfer = HostUart::new(uart1);

    let mut hw_flash = HwFlash;
    let mut fs = Filesystem::init(&hw_flash);

    let pin_attempt = "abcdef";
    verify_pin(pin_attempt.as_bytes(), &PIN_SALT, &PIN_HASH);

    loop {
        let mut buf = [0u8; MAX_MSG_SIZE];
        match host.read_packet(&mut buf, MAX_MSG_SIZE as u16) {
            Ok((msg_type, len)) => {
                host.print_debug("Got cmd:");
                host.print_hex_debug(&[msg_type as u8]);
                command::handle_command(
                    &mut host,
                    &mut transfer,
                    msg_type,
                    len,
                    &mut buf,
                    &mut hw_flash,
                    &mut fs,
                );
            }
            Err(_) => {
                host.print_error("read failed");
            }
        }
    }
}
