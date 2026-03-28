#![no_std]
#![no_main]

#[path = "../filesystem.rs"]
mod filesystem;
#[path = "../flash.rs"]
mod flash;

use defmt::*;
use embassy_time::Instant;
use {defmt_rtt as _, panic_probe as _};

// Diagnostic scaffolding (kept commented for future re-enable)
// const RESULT_ADDR: *mut u32 = 0x2020_7FFC as *mut u32;
// const RESULT_STAT_ADDR: *mut u32 = 0x2020_7FF8 as *mut u32;
// const FLASHCTL_STATCMD_ADDR: *const u32 = 0x400C_E3D0 as *const u32;
// const RESULT_STATADDR_ADDR: *mut u32 = 0x2020_7FDC as *mut u32;
// const FLASHCTL_STATADDR_ADDR: *const u32 = 0x400C_E3D4 as *const u32;
// const RESULT_PROT_A_ADDR: *mut u32 = 0x2020_7FE0 as *mut u32;
// const RESULT_PROT_B_ADDR: *mut u32 = 0x2020_7FE4 as *mut u32;
// const RESULT_PROT_C_ADDR: *mut u32 = 0x2020_7FE8 as *mut u32;
// const RESULT_PROT_NM_ADDR: *mut u32 = 0x2020_7FEC as *mut u32;
// const RESULT_PROT_TR_ADDR: *mut u32 = 0x2020_7FF0 as *mut u32;
// const RESULT_PROT_EN_ADDR: *mut u32 = 0x2020_7FF4 as *mut u32;
// const FLASHCTL_CMDWEPROTA_ADDR: *const u32 = 0x400C_E1D0 as *const u32;
// const FLASHCTL_CMDWEPROTB_ADDR: *const u32 = 0x400C_E1D4 as *const u32;
// const FLASHCTL_CMDWEPROTC_ADDR: *const u32 = 0x400C_E1D8 as *const u32;
// const FLASHCTL_CMDWEPROTNM_ADDR: *const u32 = 0x400C_E210 as *const u32;
// const FLASHCTL_CMDWEPROTTR_ADDR: *const u32 = 0x400C_E214 as *const u32;
// const FLASHCTL_CMDWEPROTEN_ADDR: *const u32 = 0x400C_E218 as *const u32;
//
// fn set_result(code: u32) {
//     unsafe { core::ptr::write_volatile(RESULT_ADDR, code) }
// }
//
// fn set_result_stat(code: u32) {
//     unsafe { core::ptr::write_volatile(RESULT_STAT_ADDR, code) }
// }
//
// fn set_result_stataddr(addr: u32) {
//     unsafe { core::ptr::write_volatile(RESULT_STATADDR_ADDR, addr) }
// }
//
// fn set_prot_readback() {
//     unsafe {
//         core::ptr::write_volatile(
//             RESULT_PROT_A_ADDR,
//             core::ptr::read_volatile(FLASHCTL_CMDWEPROTA_ADDR),
//         );
//         core::ptr::write_volatile(
//             RESULT_PROT_B_ADDR,
//             core::ptr::read_volatile(FLASHCTL_CMDWEPROTB_ADDR),
//         );
//         core::ptr::write_volatile(
//             RESULT_PROT_C_ADDR,
//             core::ptr::read_volatile(FLASHCTL_CMDWEPROTC_ADDR),
//         );
//         core::ptr::write_volatile(
//             RESULT_PROT_NM_ADDR,
//             core::ptr::read_volatile(FLASHCTL_CMDWEPROTNM_ADDR),
//         );
//         core::ptr::write_volatile(
//             RESULT_PROT_TR_ADDR,
//             core::ptr::read_volatile(FLASHCTL_CMDWEPROTTR_ADDR),
//         );
//         core::ptr::write_volatile(
//             RESULT_PROT_EN_ADDR,
//             core::ptr::read_volatile(FLASHCTL_CMDWEPROTEN_ADDR),
//         );
//     }
// }

#[cortex_m_rt::exception]
unsafe fn NonMaskableInt() {
    const SYSCTL_NMIICLR: *mut u32 = 0x400B_0078 as *mut u32;
    unsafe { core::ptr::write_volatile(SYSCTL_NMIICLR, 0x7F) };
}

unsafe fn set_vtor(addr: u32) {
    const VTOR: *mut u32 = 0xE000_ED08 as *mut u32;
    unsafe { core::ptr::write_volatile(VTOR, addr) };
}

fn fs_error_code(err: filesystem::FsError) -> u8 {
    match err {
        filesystem::FsError::InvalidSlot => 1,
        filesystem::FsError::NameTooLong => 2,
        filesystem::FsError::ContentsTooLarge => 3,
        filesystem::FsError::InvalidFatEntry => 4,
        filesystem::FsError::FlashWriteError => 5,
    }
}

fn elapsed_ms(boot: Instant) -> u64 {
    Instant::now().duration_since(boot).as_millis()
}

#[cortex_m_rt::entry]
fn main() -> ! {
    // set_result(0xA000_0001);
    unsafe { set_vtor(0x0000_6000) };
    let _p = embassy_mspm0::init(Default::default());
    let boot = Instant::now();
    info!("[+{} ms] write_file_test boot", 0u64);
    // set_result(0xA000_0002);

    let mut hw_flash = flash::HwFlash;
    let mut fs = filesystem::Filesystem::init(&mut hw_flash);
    // set_result(0xA000_0003);

    let name = b"wf_test";
    let contents = b"write_file smoke test";
    let uuid = [0xAB; filesystem::UUID_SIZE];
    // set_result(0xA000_0004);
    let create_start = Instant::now();
    info!("[+{} ms] create_file start", elapsed_ms(boot));
    let file = match filesystem::Filesystem::create_file_timed(1, name, contents, boot) {
        Ok(file) => file,
        Err(err) => {
            // set_result(0xE100_0000 | fs_error_code(err) as u32);
            error!(
                "[+{} ms] create_file failed, code={}",
                elapsed_ms(boot),
                fs_error_code(err)
            );
            loop {
                cortex_m::asm::wfi();
            }
        }
    };
    let create_duration_ms = Instant::now().duration_since(create_start).as_millis();
    info!(
        "[+{} ms] create_file done (duration={} ms)",
        elapsed_ms(boot),
        create_duration_ms
    );
    // set_result(0xA000_0005);

    // set_result(0xA000_0006);
    let write_start = Instant::now();
    info!("[+{} ms] write_file start", elapsed_ms(boot));
    match fs.write_file_timed(0, &file, &uuid, &mut hw_flash, boot) {
        Ok(()) => {
            // set_result(0xA000_00FF);
            let write_duration_ms = Instant::now().duration_since(write_start).as_millis();
            info!(
                "[+{} ms] write_file test passed (duration={} ms)",
                elapsed_ms(boot),
                write_duration_ms
            );
        }
        Err(err) => {
            // let stat = unsafe { core::ptr::read_volatile(FLASHCTL_STATCMD_ADDR) };
            // let stataddr = unsafe { core::ptr::read_volatile(FLASHCTL_STATADDR_ADDR) };
            // set_prot_readback();
            // set_result_stat(stat);
            // set_result_stataddr(stataddr);
            // set_result(0xE200_0000 | fs_error_code(err) as u32);
            let write_duration_ms = Instant::now().duration_since(write_start).as_millis();
            error!(
                "[+{} ms] write_file failed, code={}, duration={} ms",
                elapsed_ms(boot),
                fs_error_code(err),
                write_duration_ms
            );
        }
    }

    loop {
        cortex_m::asm::wfi();
    }
}
