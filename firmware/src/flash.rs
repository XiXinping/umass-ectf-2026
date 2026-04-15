//! Flash driver for MSPM0L2228
//!
//! Provides erase, read, and write operations against on-chip flash via
//! direct FLASHCTL register access.

use core::ptr;

use crate::secure_filesystem::{Flash, FsError};

/// Flash page (sector) size in bytes.
pub const FLASH_PAGE_SIZE: u32 = 1024;

// ─── FLASHCTL register addresses (base = 0x400C_D000) ──────────────
const FLASHCTL_BASE: u32 = 0x400C_D000;
const FLASHCTL_CMDEXEC: *mut u32 = (FLASHCTL_BASE + 0x1100) as *mut u32;
const FLASHCTL_CMDTYPE: *mut u32 = (FLASHCTL_BASE + 0x1104) as *mut u32;
const FLASHCTL_CMDCTL: *mut u32 = (FLASHCTL_BASE + 0x1108) as *mut u32;
const FLASHCTL_CMDADDR: *mut u32 = (FLASHCTL_BASE + 0x1120) as *mut u32;
const FLASHCTL_CMDBYTEN: *mut u32 = (FLASHCTL_BASE + 0x1124) as *mut u32;
const FLASHCTL_CMDDATA0: *mut u32 = (FLASHCTL_BASE + 0x1130) as *mut u32;
const FLASHCTL_CMDDATA1: *mut u32 = (FLASHCTL_BASE + 0x1134) as *mut u32;
const FLASHCTL_CMDWEPROTA: *mut u32 = (FLASHCTL_BASE + 0x11D0) as *mut u32;
const FLASHCTL_CMDWEPROTB: *mut u32 = (FLASHCTL_BASE + 0x11D4) as *mut u32;
const FLASHCTL_CMDWEPROTC: *mut u32 = (FLASHCTL_BASE + 0x11D8) as *mut u32;
const FLASHCTL_CMDWEPROTNM: *mut u32 = (FLASHCTL_BASE + 0x1210) as *mut u32;
const FLASHCTL_CMDWEPROTTR: *mut u32 = (FLASHCTL_BASE + 0x1214) as *mut u32;
const FLASHCTL_CMDWEPROTEN: *mut u32 = (FLASHCTL_BASE + 0x1218) as *mut u32;
const FLASHCTL_STATCMD: *mut u32 = (FLASHCTL_BASE + 0x13D0) as *mut u32;

// STATCMD bit masks
const STATCMD_CMDDONE: u32 = 1 << 0;
const STATCMD_CMDPASS: u32 = 1 << 1;

// Command execution trigger value
const CMDEXEC_EXECUTE: u32 = 0x01;

/// Maximum iterations to poll STATCMD before declaring a timeout.
const CMD_DONE_TIMEOUT_LOOPS: u32 = 2_000_000;

/// CMDCTL value that selects main/system flash region for programming.
const PROGRAM_CMDCTL_MAIN: u32 = 0x0000_0000;

/// CMDBYTEN mask enabling 64-bit (8-byte) programming with ECC.
const PROGRAM_64BIT_ECC_MASK: u32 = 0x1FF;

// ─── Low-level register helpers (SRAM-resident) ────────────────────

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

/// Poll STATCMD until the current command completes or the timeout expires.
///
/// Returns `true` if the command finished successfully (CMDDONE + CMDPASS).
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

/// Issue a ClearStatus command to reset stale STATCMD flags.
#[inline(never)]
#[unsafe(link_section = ".data")]
fn clear_status() {
    unsafe {
        reg_write(FLASHCTL_CMDTYPE, 0x05); // COMMAND = ClearStatus, SIZE = 0
        reg_write(FLASHCTL_CMDEXEC, CMDEXEC_EXECUTE);
    }
}

/// Issue ClearStatus and block until it completes.
#[inline(never)]
#[unsafe(link_section = ".data")]
fn clear_status_blocking() {
    clear_status();
    let _ = wait_cmd_done();
}

/// Zero all write/erase protection registers so erase and program can proceed.
#[inline(never)]
#[unsafe(link_section = ".data")]
fn unprotect_sectors() {
    unsafe {
        reg_write(FLASHCTL_CMDWEPROTA, 0);
        reg_write(FLASHCTL_CMDWEPROTB, 0);
        reg_write(FLASHCTL_CMDWEPROTC, 0);
        reg_write(FLASHCTL_CMDWEPROTNM, 0);
        reg_write(FLASHCTL_CMDWEPROTTR, 0);
        reg_write(FLASHCTL_CMDWEPROTEN, 0);
    }
}

/// Verify that all write/erase protection registers read back as zero.
#[inline(never)]
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

// ─── Public flash operations ───────────────────────────────────────

/// Erase one 1024-byte flash sector.
///
/// `address` must be sector-aligned (a multiple of [`FLASH_PAGE_SIZE`]).
#[inline(never)]
#[unsafe(link_section = ".data")]
pub fn flash_simple_erase_page(address: u32) -> Result<(), FsError> {
    clear_status();
    unprotect_sectors();
    if !are_sectors_unprotected() {
        return Err(FsError::FlashWriteError);
    }

    unsafe {
        reg_write(FLASHCTL_CMDTYPE, (0x04 << 4) | 0x02); // Erase, sector-size
        reg_write(FLASHCTL_CMDCTL, 0x0C); // MODESEL = EraseSect
        reg_write(FLASHCTL_CMDADDR, address);
        reg_write(FLASHCTL_CMDEXEC, CMDEXEC_EXECUTE);
    }

    if !wait_cmd_done() {
        return Err(FsError::FlashWriteError);
    }

    Ok(())
}

/// Read bytes from flash into `buffer` via volatile loads.
///
/// Flash is memory-mapped so this is a byte-by-byte volatile copy.
pub fn flash_simple_read(address: u32, buffer: &mut [u8]) {
    let src = address as *const u8;
    for (i, byte) in buffer.iter_mut().enumerate() {
        *byte = unsafe { ptr::read_volatile(src.add(i)) };
    }
}

/// Return `data[idx]`, or `0xFF` (erased flash state) if `idx` is out of bounds.
#[inline(always)]
fn data_byte_or_pad(data: &[u8], idx: usize) -> u8 {
    if idx < data.len() { data[idx] } else { 0xFF }
}

/// Program `data` into flash at `address`.
///
/// The target region **must** have been erased beforehand. Data is written in
/// 64-bit (8-byte) flash-word chunks with hardware ECC generation. Bytes
/// beyond `data.len()` are padded with `0xFF` to fill the final flash word.
///
/// No intermediate buffer is allocated — bytes are read directly from `data`,
/// keeping stack usage minimal.
#[inline(never)]
#[unsafe(link_section = ".data")]
pub fn flash_simple_write(address: u32, data: &[u8]) -> Result<(), FsError> {
    // Round up to a whole number of 8-byte flash words.
    let size_in_words = ((data.len() + 3) / 4 + 1) & !1;
    let padded_len = size_in_words * 4;

    clear_status_blocking();

    let mut offset: usize = 0;
    while offset < padded_len {
        unprotect_sectors();

        // Assemble two 32-bit words from source data (with 0xFF padding).
        let lo = u32::from_le_bytes([
            data_byte_or_pad(data, offset),
            data_byte_or_pad(data, offset + 1),
            data_byte_or_pad(data, offset + 2),
            data_byte_or_pad(data, offset + 3),
        ]);
        let hi = u32::from_le_bytes([
            data_byte_or_pad(data, offset + 4),
            data_byte_or_pad(data, offset + 5),
            data_byte_or_pad(data, offset + 6),
            data_byte_or_pad(data, offset + 7),
        ]);

        unsafe {
            reg_write(FLASHCTL_CMDTYPE, 0x01); // Program command
            reg_write(FLASHCTL_CMDCTL, PROGRAM_CMDCTL_MAIN);
            reg_write(FLASHCTL_CMDADDR, address + offset as u32);
            reg_write(FLASHCTL_CMDBYTEN, PROGRAM_64BIT_ECC_MASK);
            reg_write(FLASHCTL_CMDDATA0, lo);
            reg_write(FLASHCTL_CMDDATA1, hi);
            reg_write(FLASHCTL_CMDEXEC, CMDEXEC_EXECUTE);
        }

        if !wait_cmd_done() {
            return Err(FsError::FlashWriteError);
        }

        offset += 8;
    }

    Ok(())
}

// ─── Flash trait implementation ────────────────────────────────────

/// Hardware-backed [`Flash`] implementation for the MSPM0L2228.
pub struct HwFlash;

impl Flash for HwFlash {
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