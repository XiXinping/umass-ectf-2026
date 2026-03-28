//! Simple flash interface for MSPM0L2228
//!
//! Port of `simple_flash.c` using direct register access.
//! Provides erase, read, and write operations against on-chip flash.
//!
//! The execute+poll core is placed in `.data` so `cortex-m-rt` copies it
//! to SRAM at startup — this is required because we cannot run code from
//! a flash bank while that bank is being erased or programmed.

use core::ptr;
use defmt::info;
use embassy_time::Instant;

use crate::filesystem::FsError;

/// Flash page (sector) size in bytes.
pub const FLASH_PAGE_SIZE: u32 = 1024;

// ─── FLASHCTL register offsets (base = 0x400C_D000) ────────────────
const FLASHCTL_BASE: u32 = 0x400C_D000;
const FLASHCTL_CMDTYPE: *mut u32 = (FLASHCTL_BASE + 0x1104) as *mut u32;
const FLASHCTL_CMDCTL: *mut u32 = (FLASHCTL_BASE + 0x1108) as *mut u32;
const FLASHCTL_CMDADDR: *mut u32 = (FLASHCTL_BASE + 0x1120) as *mut u32;
const FLASHCTL_CMDBYTEN: *mut u32 = (FLASHCTL_BASE + 0x1124) as *mut u32;
const FLASHCTL_CMDDATA0: *mut u32 = (FLASHCTL_BASE + 0x1130) as *mut u32;
const FLASHCTL_CMDDATA1: *mut u32 = (FLASHCTL_BASE + 0x1134) as *mut u32;
const FLASHCTL_CMDEXEC: *mut u32 = (FLASHCTL_BASE + 0x1100) as *mut u32;
const FLASHCTL_STATCMD: *mut u32 = (FLASHCTL_BASE + 0x13D0) as *mut u32;
const FLASHCTL_CMDWEPROTA: *mut u32 = (FLASHCTL_BASE + 0x11D0) as *mut u32;
const FLASHCTL_CMDWEPROTB: *mut u32 = (FLASHCTL_BASE + 0x11D4) as *mut u32;
const FLASHCTL_CMDWEPROTC: *mut u32 = (FLASHCTL_BASE + 0x11D8) as *mut u32;
const FLASHCTL_CMDWEPROTNM: *mut u32 = (FLASHCTL_BASE + 0x1210) as *mut u32;
const FLASHCTL_CMDWEPROTTR: *mut u32 = (FLASHCTL_BASE + 0x1214) as *mut u32;
const FLASHCTL_CMDWEPROTEN: *mut u32 = (FLASHCTL_BASE + 0x1218) as *mut u32;

// STATCMD bit positions
const STATCMD_CMDDONE: u32 = 1 << 0;
const STATCMD_CMDPASS: u32 = 1 << 1;

// CMDEXEC execute value
const CMDEXEC_EXECUTE: u32 = 0x01;
const CMD_DONE_TIMEOUT_LOOPS: u32 = 2_000_000;
const PROGRAM_CMDCTL_MAIN_SYSTEM_ADDR: u32 = 0x0000_0000;
const PROGRAM_64_WITH_ECC_MASK: u32 = 0x1FF;

#[inline(always)]
fn elapsed_ms(since: Instant) -> u64 {
    Instant::now().duration_since(since).as_millis()
}

#[inline(always)]
#[unsafe(link_section = ".data")]
unsafe fn reg_write(addr: *mut u32, val: u32) {
    unsafe { ptr::write_volatile(addr, val) };
}

#[inline(always)]
#[unsafe(link_section = ".data")]
unsafe fn reg_read(addr: *mut u32) -> u32 {
    unsafe { ptr::read_volatile(addr) }
}

/// Wait for the current flash command to finish and return success/failure.
///
/// This function is placed in SRAM (`.data` section) so it can execute
/// while flash is being erased or programmed.
#[inline(never)]
#[unsafe(link_section = ".data")]
fn wait_cmd_done() -> bool {
    let mut loops = 0u32;
    loop {
        let stat = unsafe { reg_read(FLASHCTL_STATCMD) };
        if stat & STATCMD_CMDDONE != 0 {
            return stat & STATCMD_CMDPASS != 0;
        }

        loops = loops.wrapping_add(1);
        if loops >= CMD_DONE_TIMEOUT_LOOPS {
            return false;
        }
    }
}

/// Clear any stale status flags before issuing a new command.
#[unsafe(link_section = ".data")]
fn clear_status() {
    unsafe {
        // CMDTYPE: COMMAND = ClearStatus (0x5), SIZE = 0
        reg_write(FLASHCTL_CMDTYPE, 0x05);
        reg_write(FLASHCTL_CMDEXEC, CMDEXEC_EXECUTE);
    }
}

#[unsafe(link_section = ".data")]
fn clear_status_blocking() {
    clear_status();
    let _ = wait_cmd_done();
}

/// Unprotect all sectors so erase/program can proceed.
#[unsafe(link_section = ".data")]
fn unprotect_sectors() {
    unsafe {
        reg_write(FLASHCTL_CMDWEPROTA, 0x0000_0000);
        reg_write(FLASHCTL_CMDWEPROTB, 0x0000_0000);
        reg_write(FLASHCTL_CMDWEPROTC, 0x0000_0000);
        reg_write(FLASHCTL_CMDWEPROTNM, 0x0000_0000);
        reg_write(FLASHCTL_CMDWEPROTTR, 0x0000_0000);
        reg_write(FLASHCTL_CMDWEPROTEN, 0x0000_0000);
    }
}

#[unsafe(link_section = ".data")]
fn are_sectors_unprotected() -> bool {
    unsafe {
        reg_read(FLASHCTL_CMDWEPROTA) == 0
            && reg_read(FLASHCTL_CMDWEPROTB) == 0
            && reg_read(FLASHCTL_CMDWEPROTC) == 0
            && reg_read(FLASHCTL_CMDWEPROTNM) == 0
            && reg_read(FLASHCTL_CMDWEPROTTR) == 0
            && reg_read(FLASHCTL_CMDWEPROTEN) == 0
    }
}

/// Erase one flash sector (1024 bytes).
///
/// The address must be sector-aligned.
#[unsafe(link_section = ".data")]
pub fn flash_simple_erase_page(address: u32) -> Result<(), FsError> {
    clear_status_blocking();
    unprotect_sectors();
    if !are_sectors_unprotected() {
        return Err(FsError::FlashWriteError);
    }

    unsafe {
        // CMDTYPE: COMMAND = Erase (0x2), SIZE = Sector (0x4)
        reg_write(FLASHCTL_CMDTYPE, (0x04 << 4) | 0x02);
        // CMDCTL: MODESEL = EraseSect (0xC). Address translation selects bank/region.
        reg_write(FLASHCTL_CMDCTL, 0x0C);
        // Target address
        reg_write(FLASHCTL_CMDADDR, address);
        // Execute
        reg_write(FLASHCTL_CMDEXEC, CMDEXEC_EXECUTE);
    }

    if !wait_cmd_done() {
        return Err(FsError::FlashWriteError);
    }

    Ok(())
}

/// Read `size` bytes from flash at `address` into `buffer`.
///
/// Flash is memory-mapped, so this is a simple volatile copy.
pub fn flash_simple_read(address: u32, buffer: &mut [u8]) {
    let src = address as *const u8;
    for (i, byte) in buffer.iter_mut().enumerate() {
        *byte = unsafe { ptr::read_volatile(src.add(i)) };
    }
}

/// Read one byte from `data`, or return 0xFF (erased state) if past the end.
#[inline(always)]
fn data_byte_or_pad(data: &[u8], idx: usize) -> u8 {
    if idx < data.len() { data[idx] } else { 0xFF }
}

/// Write `data` to flash at `address`.
///
/// The flash region must have been erased first. Data is programmed in
/// 64-bit (8-byte) chunks using multi-word programming with ECC generation.
/// Reads directly from `data` with no large copy buffer (stack-safe).
#[inline(never)]
#[unsafe(link_section = ".data")]
pub fn flash_simple_write(address: u32, data: &[u8]) -> Result<(), FsError> {
    let op_start = Instant::now();

    // Round size up to an even number of 32-bit words (8-byte flash word).
    let size = data.len();
    let size_32b = ((size + 3) / 4 + 1) & !1;
    let padded_byte_len = size_32b * 4;
    let chunk_count = padded_byte_len / 8;

    info!(
        "[+{} ms] flash_simple_write start addr=0x{:08x} size={} padded={} chunks={}",
        elapsed_ms(op_start),
        address,
        size,
        padded_byte_len,
        chunk_count
    );

    let mut dump_offset: usize = 0;
    while dump_offset < padded_byte_len {
        let b0 = data_byte_or_pad(data, dump_offset);
        let b1 = data_byte_or_pad(data, dump_offset + 1);
        let b2 = data_byte_or_pad(data, dump_offset + 2);
        let b3 = data_byte_or_pad(data, dump_offset + 3);
        let b4 = data_byte_or_pad(data, dump_offset + 4);
        let b5 = data_byte_or_pad(data, dump_offset + 5);
        let b6 = data_byte_or_pad(data, dump_offset + 6);
        let b7 = data_byte_or_pad(data, dump_offset + 7);

        info!(
            "[+{} ms] flash_simple_write prebuf chunk={} addr=0x{:08x} bytes={:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
            elapsed_ms(op_start),
            dump_offset / 8,
            address + dump_offset as u32,
            b0,
            b1,
            b2,
            b3,
            b4,
            b5,
            b6,
            b7
        );

        dump_offset += 8;
    }

    // Program in 8-byte (64-bit flash-word) chunks directly from source
    let mut offset: usize = 0;
    while offset < padded_byte_len {
        let chunk_start = Instant::now();

        clear_status();
        info!(
            "[+{} ms] flash_simple_write chunk={} clear_status done (step={} ms)",
            elapsed_ms(op_start),
            offset / 8,
            elapsed_ms(chunk_start)
        );

        let unprotect_start = Instant::now();
        unprotect_sectors();
        info!(
            "[+{} ms] flash_simple_write chunk={} unprotect done (step={} ms)",
            elapsed_ms(op_start),
            offset / 8,
            elapsed_ms(unprotect_start)
        );

        let word0 = u32::from_le_bytes([
            data_byte_or_pad(data, offset),
            data_byte_or_pad(data, offset + 1),
            data_byte_or_pad(data, offset + 2),
            data_byte_or_pad(data, offset + 3),
        ]);
        let word1 = u32::from_le_bytes([
            data_byte_or_pad(data, offset + 4),
            data_byte_or_pad(data, offset + 5),
            data_byte_or_pad(data, offset + 6),
            data_byte_or_pad(data, offset + 7),
        ]);

        info!(
            "[+{} ms] flash_simple_write chunk={} calc addr=0x{:08x} word0=0x{:08x} word1=0x{:08x}",
            elapsed_ms(op_start),
            offset / 8,
            address + offset as u32,
            word0,
            word1
        );

        unsafe {
            reg_write(FLASHCTL_CMDTYPE, 0x01);
            reg_write(FLASHCTL_CMDCTL, PROGRAM_CMDCTL_MAIN_SYSTEM_ADDR);
            reg_write(FLASHCTL_CMDADDR, address + offset as u32);
            reg_write(FLASHCTL_CMDBYTEN, PROGRAM_64_WITH_ECC_MASK);
            reg_write(FLASHCTL_CMDDATA0, word0);
            reg_write(FLASHCTL_CMDDATA1, word1);
            reg_write(FLASHCTL_CMDEXEC, CMDEXEC_EXECUTE);
        }

        info!(
            "[+{} ms] flash_simple_write chunk={} regs written cmdtype=0x01 cmdctl=0x0E byteen=0xFF",
            elapsed_ms(op_start),
            offset / 8
        );

        let wait_start = Instant::now();

        if !wait_cmd_done() {
            info!(
                "[+{} ms] flash_simple_write chunk={} wait failed (step={} ms)",
                elapsed_ms(op_start),
                offset / 8,
                elapsed_ms(wait_start)
            );
            return Err(FsError::FlashWriteError);
        }

        info!(
            "[+{} ms] flash_simple_write chunk={} write done (wait_step={} ms total_chunk={} ms)",
            elapsed_ms(op_start),
            offset / 8,
            elapsed_ms(wait_start),
            elapsed_ms(chunk_start)
        );

        offset += 8;
    }

    info!(
        "[+{} ms] flash_simple_write done total={} ms",
        elapsed_ms(op_start),
        elapsed_ms(op_start)
    );

    Ok(())
}

/// Implementation of the `filesystem::Flash` trait using real hardware.
pub struct HwFlash;

impl crate::filesystem::Flash for HwFlash {
    fn read(&self, address: u32, buf: &mut [u8]) {
        flash_simple_read(address, buf);
    }

    fn write(&mut self, address: u32, data: &[u8]) -> Result<(), FsError> {
        flash_simple_write(address, data)
    }

    fn erase_page(&mut self, address: u32) -> Result<(), FsError> {
        flash_simple_erase_page(address)
    }
}
