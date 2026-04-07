//! Low-level register interface for the MSPM0L2228 AESADV peripheral.
//!
//! Provides direct volatile register access for AES-128-GCM operations
//! using the on-chip hardware accelerator. No PAC crate is used because
//! the AESADV block has no generated peripheral driver for this target.

use core::ptr;

/// AESADV memory-mapped peripheral base address.
pub const AESADV_BASE: u32 = 0x4044_2000;

// ─── Register offsets ──────────────────────────────────────────────

pub const PWREN_OFFSET: u32 = 0x0800;
pub const RSTCTL_OFFSET: u32 = 0x0804;
pub const STAT_PERIPH_OFFSET: u32 = 0x0814;
pub const GCMCCM_TAG0_OFFSET: u32 = 0x1100;
pub const GCMCCM_TAG1_OFFSET: u32 = 0x1104;
pub const GCMCCM_TAG2_OFFSET: u32 = 0x1108;
pub const GCMCCM_TAG3_OFFSET: u32 = 0x110C;
pub const KEY0_OFFSET: u32 = 0x1120;
pub const IV0_OFFSET: u32 = 0x1140;
pub const CTRL_OFFSET: u32 = 0x1150;
pub const C_LENGTH_0_OFFSET: u32 = 0x1154;
pub const C_LENGTH_1_OFFSET: u32 = 0x1158;
pub const AAD_LENGTH_OFFSET: u32 = 0x115C;
pub const DATA0_OFFSET: u32 = 0x1160;
pub const TAG0_OFFSET: u32 = 0x1170;
pub const FORCE_IN_AV_OFFSET: u32 = 0x1180;

// ─── Keyed register fields ─────────────────────────────────────────

const PWREN_KEY: u32 = 0x26;
const RSTCTL_KEY: u32 = 0xB1;
const KEY_SHIFT: u32 = 24;

// ─── CTRL register bit definitions ─────────────────────────────────

pub const CTRL_CNTXT_RDY: u32 = 1 << 31;
pub const CTRL_SAVED_CNTXT_RDY: u32 = 1 << 30;
pub const CTRL_SAVE_CNTXT: u32 = 1 << 29;
pub const CTRL_GCM_AUTONOMOUS: u32 = 0b11 << 16;
pub const CTRL_GCM_MASK: u32 = 0b11 << 16;
pub const CTRL_CTR: u32 = 1 << 6;
pub const CTRL_CTR_WIDTH_MASK: u32 = 0b11 << 6;
pub const CTRL_KEYSIZE_128: u32 = 0b01 << 3;
pub const CTRL_KEYSIZE_MASK: u32 = 0b11 << 3;
pub const CTRL_DIR_ENCRYPT: u32 = 1 << 2;
pub const CTRL_DIR_MASK: u32 = 1 << 2;
pub const CTRL_INPUT_RDY: u32 = 1 << 1;
pub const CTRL_OUTPUT_RDY: u32 = 1 << 0;

/// Bitmask covering the fields that must be set atomically when
/// starting a new GCM context: mode, direction, counter width, and
/// context-save enable.
pub const CTRL_GCM_SETUP_MASK: u32 =
    CTRL_GCM_MASK | CTRL_DIR_MASK | CTRL_CTR_WIDTH_MASK | CTRL_SAVE_CNTXT | CTRL_CTR;

// ─── Raw register helpers ──────────────────────────────────────────

#[inline(always)]
fn reg(offset: u32) -> *mut u32 {
    (AESADV_BASE + offset) as *mut u32
}

#[inline(always)]
fn reg_read(offset: u32) -> u32 {
    unsafe { ptr::read_volatile(reg(offset)) }
}

#[inline(always)]
fn reg_write(offset: u32, value: u32) {
    unsafe { ptr::write_volatile(reg(offset), value) }
}

// ─── Peripheral handle ─────────────────────────────────────────────

/// Zero-sized handle for the AESADV hardware accelerator.
///
/// All methods operate directly on the memory-mapped registers.
/// The struct carries no state — it exists only to namespace the
/// register operations and make call sites self-documenting.
#[derive(Clone, Copy, Default)]
pub struct GcmEngine;

impl GcmEngine {
    #[inline(always)]
    pub const fn new() -> Self {
        Self
    }

    /// Enable peripheral power by writing the unlock key + enable bit.
    #[inline(always)]
    pub fn enable_power(&self) {
        reg_write(PWREN_OFFSET, (PWREN_KEY << KEY_SHIFT) | 0x1);
    }

    #[inline(always)]
    pub fn pwren(&self) -> u32 {
        reg_read(PWREN_OFFSET)
    }

    #[inline(always)]
    pub fn stat_periph(&self) -> u32 {
        reg_read(STAT_PERIPH_OFFSET)
    }

    /// Assert a peripheral reset via RSTCTL (key-protected).
    #[inline(always)]
    pub fn write_rstctl(&self, value: u32) {
        reg_write(RSTCTL_OFFSET, (RSTCTL_KEY << KEY_SHIFT) | value);
    }

    /// Zero the intermediate GCM/CCM tag registers.
    ///
    /// Must be called before each new GCM operation so that residual
    /// state from a previous computation does not corrupt the result.
    #[inline(always)]
    pub fn zero_gcm_tag_state(&self) {
        reg_write(GCMCCM_TAG0_OFFSET, 0);
        reg_write(GCMCCM_TAG1_OFFSET, 0);
        reg_write(GCMCCM_TAG2_OFFSET, 0);
        reg_write(GCMCCM_TAG3_OFFSET, 0);
    }

    #[inline(always)]
    pub fn ctrl(&self) -> u32 {
        reg_read(CTRL_OFFSET)
    }

    /// Read-modify-write the CTRL register: clears bits in `mask`,
    /// then sets the bits from `value` that fall within `mask`.
    #[inline(always)]
    pub fn modify_ctrl(&self, mask: u32, value: u32) {
        let cur = self.ctrl();
        reg_write(CTRL_OFFSET, (cur & !mask) | (value & mask));
    }

    // ── Polling helpers (with timeout) ─────────────────────────────

    #[inline(always)]
    pub fn poll_cntxt_rdy(&self, max_iters: u32) -> bool {
        let mut iters = 0;
        while (self.ctrl() & CTRL_CNTXT_RDY) == 0 {
            iters += 1;
            if iters >= max_iters {
                return false;
            }
            cortex_m::asm::nop();
        }
        true
    }

    #[inline(always)]
    pub fn poll_input_rdy(&self, max_iters: u32) -> bool {
        let mut iters = 0;
        while (self.ctrl() & CTRL_INPUT_RDY) == 0 {
            iters += 1;
            if iters >= max_iters {
                return false;
            }
            cortex_m::asm::nop();
        }
        true
    }

    #[inline(always)]
    pub fn poll_output_rdy(&self, max_iters: u32) -> bool {
        let mut iters = 0;
        while (self.ctrl() & CTRL_OUTPUT_RDY) == 0 {
            iters += 1;
            if iters >= max_iters {
                return false;
            }
            cortex_m::asm::nop();
        }
        true
    }

    #[inline(always)]
    pub fn poll_saved_cntxt_rdy(&self, max_iters: u32) -> bool {
        let mut iters = 0;
        while (self.ctrl() & CTRL_SAVED_CNTXT_RDY) == 0 {
            iters += 1;
            if iters >= max_iters {
                return false;
            }
            cortex_m::asm::nop();
        }
        true
    }

    // ── Key / IV / length loading ──────────────────────────────────

    /// Load a 128-bit key into KEY0–KEY3 and set KEYSIZE to 128.
    #[inline(always)]
    pub fn load_key_128(&self, key: &[u8; 16]) {
        self.modify_ctrl(CTRL_KEYSIZE_MASK, CTRL_KEYSIZE_128);
        for i in 0..4 {
            let off = i * 4;
            let word = u32::from_le_bytes([key[off], key[off + 1], key[off + 2], key[off + 3]]);
            reg_write(KEY0_OFFSET + (i as u32) * 4, word);
        }
    }

    /// Load a 128-bit IV into IV0–IV3.
    #[inline(always)]
    pub fn load_iv(&self, iv_words: &[u32; 4]) {
        let mut off = IV0_OFFSET;
        for &word in iv_words {
            reg_write(off, word);
            off += 4;
        }
    }

    /// Program the crypto-length and AAD-length registers.
    #[inline(always)]
    pub fn set_lengths(&self, c_length_low: u32, c_length_high: u32, aad_length: u32) {
        reg_write(C_LENGTH_0_OFFSET, c_length_low);
        reg_write(C_LENGTH_1_OFFSET, c_length_high);
        reg_write(AAD_LENGTH_OFFSET, aad_length);
    }

    /// Configure CTRL for GCM autonomous mode via read-modify-write.
    ///
    /// Sets GCM autonomous mode, CTR, 32-bit counter width, and
    /// context saving. Direction is set to encrypt or decrypt based
    /// on the `encrypt` flag.
    #[inline(always)]
    pub fn configure_gcm_mode(&self, encrypt: bool) {
        let dir = if encrypt { CTRL_DIR_ENCRYPT } else { 0 };
        let value = CTRL_GCM_AUTONOMOUS | CTRL_CTR | dir | CTRL_SAVE_CNTXT;
        self.modify_ctrl(CTRL_GCM_SETUP_MASK, value);
    }

    // ── Data path ──────────────────────────────────────────────────

    /// Write a 128-bit data block into DATA0–DATA3.
    #[inline(always)]
    pub fn submit_data_block(&self, block: &[u32; 4]) {
        let mut off = DATA0_OFFSET;
        for &word in block {
            reg_write(off, word);
            off += 4;
        }
    }

    /// Read a 128-bit result block from DATA0–DATA3.
    #[inline(always)]
    pub fn collect_data_block(&self) -> [u32; 4] {
        [
            reg_read(DATA0_OFFSET),
            reg_read(DATA0_OFFSET + 4),
            reg_read(DATA0_OFFSET + 8),
            reg_read(DATA0_OFFSET + 12),
        ]
    }

    /// Read the 128-bit authentication tag from TAG0–TAG3.
    #[inline(always)]
    pub fn collect_tag(&self) -> [u32; 4] {
        [
            reg_read(TAG0_OFFSET),
            reg_read(TAG0_OFFSET + 4),
            reg_read(TAG0_OFFSET + 8),
            reg_read(TAG0_OFFSET + 12),
        ]
    }

    /// Signal that the current (partial) input block is complete.
    ///
    /// Required when the final data or AAD block is shorter than 16
    /// bytes — writing fewer than 4 DATA registers does not
    /// automatically trigger processing.
    #[inline(always)]
    pub fn signal_partial_block(&self) {
        reg_write(FORCE_IN_AV_OFFSET, 0xDEABDEEF);
    }
}