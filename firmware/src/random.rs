// rng.rs — Random number generation with hardware TRNG seeding a ChaCha20 CSPRNG.

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use embassy_mspm0::peripherals;
use embassy_mspm0::trng::Trng;
use heapless::Vec;
use rand_core::TryRngCore;
use zeroize::Zeroize;

/// Errors that can occur during random number generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
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
pub fn trng_gen_seed<const N: usize>() -> Result<[u8; N], RngError> {
    let mut output = [0; N];
    // Grab the PAC singleton for the TRNG peripheral.
    // embassy-mspm0 exposes this as a zero-sized token pointing at the
    // memory-mapped register block.
    let mut trng =
        Trng::new(unsafe { peripherals::TRNG::steal() }).map_err(|_| RngError::SeedFailed)?;

    trng.try_fill_bytes(&mut output)
        .map_err(|_| RngError::SeedFailed)?;

    Ok(output)
}

/// A ChaCha20-based CSPRNG seeded by the hardware TRNG.
///
/// Internally it holds a ChaCha20 stream cipher keyed with 32 bytes of hardware entropy and a
/// 12-byte random nonce, both sourced from [`trng_gen_seed`].
pub struct SecureRng {
    cipher: ChaCha20,
}

impl SecureRng {
    // ChaCha20 takes a 256-bit key (32 bytes) and a 96-bit nonce (12 bytes).
    const KEY_LEN: usize = 32;
    const NONCE_LEN: usize = 12;

    /// Create and seed a new CSPRNG from the hardware TRNG.
    pub fn new() -> Result<Self, RngError> {
        let mut key = trng_gen_seed::<{ Self::KEY_LEN }>().map_err(|_| RngError::InitFailed)?;
        let mut nonce = trng_gen_seed::<{ Self::NONCE_LEN }>().map_err(|_| RngError::InitFailed)?;

        let cipher = ChaCha20::new((&key).into(), (&nonce).into());

        // Zeroize the stack copies so key material doesn't linger.
        key.zeroize();
        nonce.zeroize();

        Ok(Self { cipher })
    }

    /// Generate N random bytes from the CSPRNG.
    pub fn random_bytes<const N: usize>(&mut self) -> Result<Vec<u8, N>, RngError> {
        // Zeroed plaintext → the ciphertext *is* the keystream.
        let mut output = [0; N];
        self.cipher
            .try_apply_keystream(&mut output)
            .map_err(|_| RngError::GenerateFailed)?;
        Ok(Vec::from(output))
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
        Ok(())
    }
}
