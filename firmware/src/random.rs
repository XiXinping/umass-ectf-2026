// rng.rs — Random number generation with hardware TRNG seeding a ChaCha20 CSPRNG.
//
// Cargo.toml dependencies:
//   embassy-mspm0 = { version = "...", features = ["mspm0l2228"] }
//   chacha20       = { version = "0.9", default-features = false }
//   defmt          = "0.3"          # (optional, for logging on embedded)

#![no_std]

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use embassy_mspm0::pac;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during random number generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RngError {
    /// TRNG hardware seed generation failed.
    SeedFailed,
    /// CSPRNG initialisation failed.
    InitFailed,
    /// Block generation failed.
    GenerateFailed,
    /// Freeing the RNG context failed.
    FreeFailed,
}

// ---------------------------------------------------------------------------
// TRNG seed generation
// ---------------------------------------------------------------------------

/// Fill `output` with raw bytes read directly from the hardware TRNG.
///
/// Issues repeated NORM_FUNC commands, polls for capture-ready,
/// then extracts individual bytes from each 32-bit capture word.
///
/// # Register mapping (MSPM0 TRNG peripheral)
///
/// | C DriverLib call              | Register / field               |
/// |-------------------------------|--------------------------------|
/// | `DL_TRNG_sendCommand(…)`      | `CMD.CMD = NORM_FUNC (0x01)`   |
/// | `DL_TRNG_isCaptureReady(…)`   | `STAT.CAPTURE_RDY`             |
/// | `DL_TRNG_getCapture(…)`       | `DATA_CAPTURE[0]`              |
/// | `DL_TRNG_disablePower(…)`     | `PWREN.ENABLE = 0`             |
///
/// **NOTE:** The exact accessor names below follow the chiptool/metapac
/// convention used by `embassy-mspm0`.  If PAC version differs,
/// do something else
pub fn trng_gen_seed(output: &mut [u8]) -> Result<(), RngError> {
    // Grab the PAC singleton for the TRNG peripheral.
    // embassy-mspm0 exposes this as a zero-sized token pointing at the
    // memory-mapped register block.
    let trng = pac::TRNG;

    let mut i: usize = 0;
    while i < output.len() {
        // ── Issue a normal-function capture command ──────────────────
        // C:  DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_NORM_FUNC);
        trng.cmd().write(|w| {
            w.set_cmd(0x01); // NORM_FUNC
        });

        // ── Spin until the capture result is ready ──────────────────
        // C:  while (!DL_TRNG_isCaptureReady(TRNG));
        while trng.stat().read().capture_rdy() == false {
            core::hint::spin_loop();
        }

        // ── Read the 32-bit captured random word ────────────────────
        // C:  uint32_t word = DL_TRNG_getCapture(TRNG);
        let word: u32 = trng.data_capture(0).read();

        // ── Scatter the word into the output buffer, byte-by-byte ───
        for j in 0u32..4 {
            if i >= output.len() {
                break;
            }
            output[i] = (word >> (j * 8)) as u8;
            i += 1;
        }
    }

    // ── Power off the TRNG ──────────────────────────────────────────
    // C:  DL_TRNG_disablePower(TRNG);
    trng.pwren().write(|w| {
        w.set_enable(false);
    });

    Ok(())
}

// ---------------------------------------------------------------------------
// CSPRNG wrapper (replaces `WC_RNG` and related functions)
// ---------------------------------------------------------------------------

/// A ChaCha20-based CSPRNG seeded by the hardware TRNG.
///
/// Replaces `WC_RNG` from WolfCrypt.  Internally it holds a ChaCha20
/// stream cipher keyed with 32 bytes of hardware entropy and a 12-byte
/// random nonce, both sourced from [`trng_gen_seed`].
pub struct Rng {
    cipher: ChaCha20,
}

impl Rng {
    // ChaCha20 takes a 256-bit key (32 bytes) and a 96-bit nonce (12 bytes).
    const KEY_LEN: usize = 32;
    const NONCE_LEN: usize = 12;

    /// Create and seed a new CSPRNG from the hardware TRNG.
    pub fn new() -> Result<Self, RngError> {
        let mut key = [0u8; Self::KEY_LEN];
        let mut nonce = [0u8; Self::NONCE_LEN];

        trng_gen_seed(&mut key).map_err(|_| RngError::InitFailed)?;
        trng_gen_seed(&mut nonce).map_err(|_| RngError::InitFailed)?;

        let cipher = ChaCha20::new((&key).into(), (&nonce).into());

        // Zeroize the stack copies so key material doesn't linger.
        key.fill(0);
        nonce.fill(0);

        Ok(Self { cipher })
    }

    /// Fill `output` with CSPRNG bytes.
    ///
    /// Internally encrypts a zero buffer through ChaCha20, which produces a
    /// cryptographically secure pseudorandom stream.
    pub fn fill(&mut self, output: &mut [u8]) -> Result<(), RngError> {
        // Zeroed plaintext → the ciphertext *is* the keystream.
        output.fill(0);
        self.cipher
            .try_apply_keystream(output)
            .map_err(|_| RngError::GenerateFailed)
    }

    /// Explicitly destroy the CSPRNG state.
    ///
    /// In Rust the struct is also cleaned up when it goes out of scope, but
    /// this method lets callers opt-in to immediate zeroisation.
    pub fn free(mut self) -> Result<(), RngError> {
        // Overwrite internal state by re-keying with zeros, then drop.
        let zero_key = [0u8; Self::KEY_LEN];
        let zero_nonce = [0u8; Self::NONCE_LEN];
        self.cipher = ChaCha20::new((&zero_key).into(), (&zero_nonce).into());
        drop(self);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

/// Generate `output.len()` random bytes in one call.
///
/// Seeds a fresh ChaCha20.
/// CSPRNG from the hardware TRNG, generates the requested bytes, and
/// immediately destroys the internal state.
pub fn gen_random(output: &mut [u8]) -> Result<(), RngError> {
    let mut rng = Rng::new()?;
    rng.fill(output)?;
    rng.free()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Size of a PRNG nonce in bytes (e.g. 32 bytes / 256 bits).
pub const NONCE_LEN: usize = 32;

/// Size of a PRNG block in bytes (e.g. 32 bytes / 256 bits).
pub const BLOCK_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Convenience helpers (replace PRNG_nonce / PRNG_block from the C header)
// ---------------------------------------------------------------------------

/// Generate a random nonce.
///
/// Equivalent to the C `PRNG_nonce` function.
pub fn prng_nonce(output: &mut [u8; NONCE_LEN]) -> Result<(), RngError> {
    gen_random(output)
}

/// Generate a random block.
///
/// Equivalent to the C `PRNG_block` function.
pub fn prng_block(output: &mut [u8; BLOCK_LEN]) -> Result<(), RngError> {
    gen_random(output)
}