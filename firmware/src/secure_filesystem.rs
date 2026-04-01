// Secure Filesystem Implementation
// provides a secure interface for file operations

use core::{char::MAX, mem};
use defmt::info;
use embassy_time::Instant;

// ─── Constants (must match C functional spec) ───────────────────────
pub const MAX_FILE_COUNT: usize = 8;
pub const MAX_NAME_SIZE: usize = 32;
pub const MAX_CONTENTS_SIZE: usize = 8192;
pub const UUID_SIZE: usize = 16;

// protected file structure constants
pub const NONCE_SIZE: usize = 12; // AES-GCM nonce size
pub const AUTH_TAG_SIZE: usize = 16; // AES-GCM tag size
pub const SIGNATURE_SIZE: usize = 32; // Ed25519 signature size

/// FAT location is fixed by the eCTF functional spec — do NOT change.
const FLASH_FAT_START: u32 = 0x0003_a000;

/// Flash page (sector) size on MSPM0L2228.
const FLASH_PAGE_SIZE: u32 = 1024;

/// Each file occupies 9 pages: 8 for contents + 1 for metadata.
const FILE_PAGE_COUNT: u32 = 9;
const STORED_FILE_SIZE: u32 = FLASH_PAGE_SIZE * FILE_PAGE_COUNT;

/// First flash address for file storage.
const FILES_START_ADDR: u32 = 0x0001_0000;

/// Sentinel value indicating a slot is in use.
pub const FILE_IN_USE: u32 = 0xDEAD_BEEF;

// ─── Error type ─────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsError {
    /// Slot index is out of range (must be 0..MAX_FILE_COUNT).
    InvalidSlot,
    /// File name exceeds MAX_NAME_SIZE - 1 bytes (must leave room for NUL).
    NameTooLong,
    /// File contents exceed MAX_CONTENTS_SIZE bytes.
    ContentsTooLarge,
    /// FAT entry contains an invalid flash address or length.
    InvalidFatEntry,
    /// Flash write failed.
    FlashWriteError,
}

// ─── Flash abstraction trait ────────────────────────────────────────

/// Thin abstraction over raw flash so the filesystem can be tested
/// without hardware. The implementor provides erase/read/write.
pub trait Flash {
    fn read(&self, address: u32, buf: &mut [u8]);
    fn write(&mut self, address: u32, data: &[u8]) -> Result<(), FsError>;
    fn erase_page(&mut self, address: u32) -> Result<(), FsError>;
}

// ─── On-flash data structures (repr(C) for binary compatibility) ───

/// FAT entry — matches the C `filesystem_entry_t` layout exactly.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FatEntry {
    pub uuid: [u8; UUID_SIZE],
    pub length: u16,
    pub padding: u16,
    pub flash_addr: u32,
}

impl FatEntry {
    /// Returns `true` when this entry is empty (zeroed or erased flash).
    pub fn is_empty(&self) -> bool {
        (self.flash_addr == 0 && self.length == 0)
            || (self.flash_addr == 0xFFFF_FFFF && self.length == 0xFFFF)
    }
}

impl Default for FatEntry {
    fn default() -> Self {
        Self {
            uuid: [0u8; UUID_SIZE],
            length: 0,
            padding: 0,
            flash_addr: 0,
        }
    }
}

/// On-flash protected file structure
#[repr(C)]
#[derive(Clone)]
pub struct ProtectedFile {
    // metadata
    pub in_use: u32,
    pub group_id: u16,
    pub name: [u8; MAX_NAME_SIZE],
    pub nonce: [u8; NONCE_SIZE],
    pub auth_tag: [u8; AUTH_TAG_SIZE],
    pub signature: [u8; SIGNATURE_SIZE],
    pub contents_length: u16, // length of encrypted contents
    // actual contents (encrypted)
    pub contents: [u8; MAX_CONTENTS_SIZE],
    
}

impl Default for ProtectedFile {
    fn default() -> Self {
        Self {
            in_use: 0,
            group_id: 0,
            name: [0u8; MAX_NAME_SIZE],
            nonce: [0u8; NONCE_SIZE],
            auth_tag: [0u8; AUTH_TAG_SIZE],
            signature: [0u8; SIGNATURE_SIZE],
            contents_length: 0,
            contents: [0u8; MAX_CONTENTS_SIZE],

        }
    }
}

// ─── Filesystem state ───────────────────────────────────────────────

/// In-memory filesystem state: a cached copy of the FAT.
pub struct Filesystem {
    fat: [FatEntry; MAX_FILE_COUNT],
}

impl Filesystem {
    /// Create an empty filesystem without loading from flash (for testing).
    pub fn empty() -> Self {
        Self {
            fat: [FatEntry::default(); MAX_FILE_COUNT],
        }
    }

    /// Create a new filesystem and load the FAT from flash.
    pub fn init(flash: &impl Flash) -> Self {
        let mut fs = Self {
            fat: [FatEntry::default(); MAX_FILE_COUNT],
        };
        fs.load_fat(flash);
        fs
    }

    // ─── FAT persistence ────────────────────────────────────────────

    fn load_fat(&mut self, flash: &impl Flash) {
        let buf = unsafe {
            core::slice::from_raw_parts_mut(
                self.fat.as_mut_ptr() as *mut u8,
                mem::size_of_val(&self.fat),
            )
        };
        flash.read(FLASH_FAT_START, buf);
    }

    fn store_fat(&self, flash: &mut impl Flash) -> Result<(), FsError> {
        flash.erase_page(FLASH_FAT_START)?;
        let buf = unsafe {
            core::slice::from_raw_parts(
                self.fat.as_ptr() as *const u8,
                mem::size_of_val(&self.fat),
            )
        };
        flash.write(FLASH_FAT_START, buf)
    }

    // ─── Slot validation ────────────────────────────────────────────

    fn validate_slot(slot: u8) -> Result<usize, FsError> {
        let idx = slot as usize;
        if idx >= MAX_FILE_COUNT {
            return Err(FsError::InvalidSlot);
        }
        Ok(idx)
    }

    // ─── Public API ─────────────────────────────────────────────────

    /// Check whether a file slot is occupied.
    pub fn is_slot_in_use(&self, slot: u8, flash: &impl Flash) -> Result<bool, FsError> {
        let mut file = ProtectedFile::default();
        self.read_file(slot, &mut file, flash)?;
        Ok(file.in_use == FILE_IN_USE)
    }

    /// Create a new `File` in memory with validated inputs.
    ///
    /// This is the safe replacement for the C `create_file` which had
    /// unbounded `strcpy` and `memcpy`.
    pub fn create_file(
        group_id: u16,
        name: &[u8],
        contents: &[u8],
    ) -> Result<ProtectedFile, FsError> {
        Self::create_file_inner(group_id, name, contents, None)
    }

    /// Create a new `File` in memory with boot-relative sub-step logging.
    pub fn create_file_timed(
        group_id: u16,
        name: &[u8],
        contents: &[u8],
        boot: Instant,
    ) -> Result<ProtectedFile, FsError> {
        Self::create_file_inner(group_id, name, contents, Some(boot))
    }

    fn create_file_inner(
        group_id: u16,
        name: &[u8],
        contents: &[u8],
        boot: Option<Instant>,
    ) -> Result<ProtectedFile, FsError> {
        if let Some(boot) = boot {
            info!("[+{} ms] create_file inner start", elapsed_ms(boot));
        }

        // Reject names that won't fit (need room for at least one NUL terminator)
        let name_check_start = Instant::now();
        if name.len() >= MAX_NAME_SIZE {
            return Err(FsError::NameTooLong);
        }
        if let Some(boot) = boot {
            info!(
                "[+{} ms] create_file name check done (step={} ms)",
                elapsed_ms(boot),
                elapsed_ms(name_check_start)
            );
        }

        let contents_check_start = Instant::now();
        if contents.len() > MAX_CONTENTS_SIZE {
            return Err(FsError::ContentsTooLarge);
        }
        if let Some(boot) = boot {
            info!(
                "[+{} ms] create_file contents check done (step={} ms)",
                elapsed_ms(boot),
                elapsed_ms(contents_check_start)
            );
        }

        let init_start = Instant::now();
        let mut file = ProtectedFile::default(); // zeroed
        file.in_use = FILE_IN_USE;
        file.group_id = group_id;
        file.contents_len = contents.len() as u16;
        if let Some(boot) = boot {
            info!(
                "[+{} ms] create_file init done (step={} ms)",
                elapsed_ms(boot),
                elapsed_ms(init_start)
            );
        }

        // Safe bounded copies — panics are impossible because we checked above
        let name_copy_start = Instant::now();
        file.name[..name.len()].copy_from_slice(name);
        if let Some(boot) = boot {
            info!(
                "[+{} ms] create_file name copy done (step={} ms)",
                elapsed_ms(boot),
                elapsed_ms(name_copy_start)
            );
        }

        let contents_copy_start = Instant::now();
        // Remaining bytes are already 0 (NUL padded) from Default
        file.contents[..contents.len()].copy_from_slice(contents);
        if let Some(boot) = boot {
            info!(
                "[+{} ms] create_file contents copy done (step={} ms)",
                elapsed_ms(boot),
                elapsed_ms(contents_copy_start)
            );
            info!("[+{} ms] create_file inner done", elapsed_ms(boot));
        }

        Ok(file)
    }

    /// Write a file to persistent flash storage.
    pub fn write_file(
        &mut self,
        slot: u8,
        file: &ProtectedFile,
        uuid: &[u8; UUID_SIZE],
        flash: &mut impl Flash,
    ) -> Result<(), FsError> {
        self.write_file_inner(slot, file, uuid, flash, None)
    }

    /// Write a file to persistent flash storage with boot-relative sub-step logging.
    pub fn write_file_timed(
        &mut self,
        slot: u8,
        file: &ProtectedFile,
        uuid: &[u8; UUID_SIZE],
        flash: &mut impl Flash,
        boot: Instant,
    ) -> Result<(), FsError> {
        self.write_file_inner(slot, file, uuid, flash, Some(boot))
    }

    fn write_file_inner(
        &mut self,
        slot: u8,
        file: &ProtectedFile,
        uuid: &[u8; UUID_SIZE],
        flash: &mut impl Flash,
        boot: Option<Instant>,
    ) -> Result<(), FsError> {
        let idx = Self::validate_slot(slot)?;
        if let Some(boot) = boot {
            info!("[+{} ms] write_file inner start", elapsed_ms(boot));
        }

        let flash_addr = FILES_START_ADDR + STORED_FILE_SIZE * (idx as u32);
        let length = file_total_size(file.contents_len);

        // Update the cached FAT
        self.fat[idx].uuid.copy_from_slice(uuid);
        self.fat[idx].flash_addr = flash_addr;
        self.fat[idx].length = length;
        let fat_start = Instant::now();
        self.store_fat(flash)?;
        if let Some(boot) = boot {
            info!(
                "[+{} ms] write_file store_fat done (step={} ms)",
                elapsed_ms(boot),
                elapsed_ms(fat_start)
            );
        }

        // Only erase the pages needed for the actual data (not all 9)
        let pages_needed = (length as u32 + FLASH_PAGE_SIZE - 1) / FLASH_PAGE_SIZE;
        for i in 0..pages_needed {
            let erase_start = Instant::now();
            flash.erase_page(flash_addr + FLASH_PAGE_SIZE * i)?;
            if let Some(boot) = boot {
                info!(
                    "[+{} ms] write_file erase_page {} done (step={} ms)",
                    elapsed_ms(boot),
                    i,
                    elapsed_ms(erase_start)
                );
            }
        }

        // Write the file to flash
        let file_bytes = unsafe {
            core::slice::from_raw_parts(file as *const ProtectedFile as *const u8, length as usize)
        };
        let write_start = Instant::now();
        flash.write(flash_addr, file_bytes)?;
        if let Some(boot) = boot {
            info!(
                "[+{} ms] write_file payload write done (step={} ms)",
                elapsed_ms(boot),
                elapsed_ms(write_start)
            );
            info!("[+{} ms] write_file inner done", elapsed_ms(boot));
        }

        Ok(())
    }

    /// Read a file from persistent flash storage.
    pub fn read_file(
        &self,
        slot: u8,
        dest: &mut ProtectedFile,
        flash: &impl Flash,
    ) -> Result<(), FsError> {
        let idx = Self::validate_slot(slot)?;

        let entry = &self.fat[idx];
        if entry.is_empty() {
            return Err(FsError::InvalidFatEntry);
        }

        let buf = unsafe {
            core::slice::from_raw_parts_mut(
                dest as *mut ProtectedFile as *mut u8,
                entry.length as usize,
            )
        };
        flash.read(entry.flash_addr, buf);

        Ok(())
    }

    /// Get read-only access to a FAT entry's metadata.
    pub fn get_file_metadata(&self, slot: u8) -> Result<&FatEntry, FsError> {
        let idx = Self::validate_slot(slot)?;
        Ok(&self.fat[idx])
    }
}

// ─── Helpers ────────────────────────────────────────────────────────

/// Total bytes to write for a file: metadata fields + contents.
/// Equivalent to C `FILE_TOTAL_SIZE` but without the macro precedence bug.
fn file_total_size(contents_len: u16) -> u16 {
    // offset of `contents` in File = in_use(4) + group_id(2) + name(32) + contents_len(2) = 40
    let metadata_size = mem::offset_of!(ProtectedFile, contents) as u16;
    metadata_size + contents_len
}

fn elapsed_ms(since: Instant) -> u64 {
    Instant::now().duration_since(since).as_millis()
}
