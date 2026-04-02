// Secure Filesystem Implementation
// provides a secure interface for file operations

use core::{mem, ptr};
use defmt::info;
use embassy_time::Instant;
use heapless::Vec;
use hmac::{Hmac, Mac};
use p256::ecdsa::Signature;
use sha2::Sha256;
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};

use aes_gcm::Tag as GcmTag;

use crate::{
    crypto::{
        asymmetric_decrypt, asymmetric_encrypt, ecc_sign_file_digest, ecc_verify_file_digest,
    },
    permission::{self, PermissionType, get_public_key},
};

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
    /// Slot contains no file. Only occurs when trying to read from an empty slot.
    EmptySlot,
    /// File name exceeds MAX_NAME_SIZE - 1 bytes (must leave room for NUL).
    NameTooLong,
    /// File contents exceed MAX_CONTENTS_SIZE bytes.
    ContentsTooLarge,
    /// FAT entry contains an invalid flash address or length.
    InvalidFatEntry,
    /// Flash write failed.
    FlashWriteError,
    /// Invalid signature
    InvalidSignature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileError {
    /// HSM does not have valid read permission for a protected file's group.
    NoReadPermission,
    /// HSM does not have valid write permission for a protected file's group.
    NoWritePermission,
    /// Error while decrypting encrypted contents.
    DecryptError,
    /// Invalid group ID.
    InvalidGroupId,
    /// Invalid file signature
    InvalidSignature,
    /// Error while encrypting file contents.
    EncryptError,
    /// Error while generating file signature.
    GenSignatureError,
    /// Something that really shouldn't have failed ended up failing.
    BullshitError,
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
    pub uuid: Uuid,
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
            uuid: Uuid::nil(),
            length: 0,
            padding: 0,
            flash_addr: 0,
        }
    }
}

/// On-flash protected file structure
#[repr(C)]
#[derive(PartialEq, Debug)]
pub struct ProtectedFile {
    // Metadata
    pub in_use: u32,
    pub group_id: u16,
    pub name: [u8; MAX_NAME_SIZE],
    pub uuid: Uuid,
    pub nonce: [u8; NONCE_SIZE],
    pub auth_tag: GcmTag,
    pub signature: Signature,
    pub ciphertext_public_key: PublicKey,
    /// The encrypted contents of the file.
    pub contents: Vec<u8, MAX_CONTENTS_SIZE>,
}

// TO-DO: Add signature check
impl ProtectedFile {
    pub fn verify_signature(&self) -> Result<(), FileError> {
        // Get the write public key for the group ID
        let write_public_key_bytes = get_public_key(self.group_id, PermissionType::Write)
            .ok_or(FileError::InvalidGroupId)?;

        // The digest should contain the encrypted contents, group ID, UUID, and filename
        let mut mac = Hmac::<Sha256>::new_from_slice(self.contents.as_slice()).unwrap();
        mac.update(&self.name);
        mac.update(&self.group_id.to_le_bytes());
        mac.update(self.uuid.as_bytes());

        let digest = mac.finalize().into_bytes();

        ecc_verify_file_digest(&self.signature, &digest, &write_public_key_bytes)
            .map_err(|_| FileError::InvalidSignature)
    }
    /// Attempt to return the decrypted contents of the file.
    pub fn decrypt(&self) -> Result<Vec<u8, MAX_CONTENTS_SIZE>, FileError> {
        let read_key_bytes = permission::get_private_key(self.group_id, PermissionType::Read)
            .ok_or(FileError::NoReadPermission)?;

        asymmetric_decrypt(
            &self.contents,
            &self.nonce,
            &self.ciphertext_public_key,
            &self.auth_tag,
            &StaticSecret::from(read_key_bytes),
        )
        .map_err(|_| FileError::DecryptError)
    }

    // Create a new protected file from plaintext contents
    pub fn create(
        group_id: u16,
        uuid: Uuid,
        name: &[u8; MAX_NAME_SIZE],
        contents: &Vec<u8, MAX_CONTENTS_SIZE>,
    ) -> Result<Self, FileError> {
        let write_key_bytes = permission::get_private_key(group_id, PermissionType::Write)
            .ok_or(FileError::NoWritePermission)?;

        // The read public key corresponding to the group ID of the file.
        let group_read_public_key = permission::get_public_key(group_id, PermissionType::Read)
            .ok_or(FileError::InvalidGroupId)?;

        // Encrypt the contents of the file
        let encrypted = asymmetric_encrypt(contents, &PublicKey::from(group_read_public_key))
            .map_err(|_| FileError::EncryptError)?;

        let digest = Self::digest(group_id, uuid, name, &encrypted.ciphertext);
        let signature = ecc_sign_file_digest(&digest, &write_key_bytes)
            .map_err(|_| FileError::GenSignatureError)?;

        let ciphertext =
            Vec::from_slice(digest.as_slice()).map_err(|_| FileError::BullshitError)?;

        Ok(ProtectedFile {
            in_use: 0,
            group_id,
            uuid,
            name: *name,
            nonce: encrypted.nonce,
            auth_tag: encrypted.auth_tag,
            signature,
            ciphertext_public_key: encrypted.cipher_public_key,
            contents: ciphertext,
        })
    }

    /// Create a cryptographic digest using HMAC with SHA-256 using a file's contents, group ID,
    /// UUID, and name.
    pub fn digest(
        group_id: u16,
        uuid: Uuid,
        name: &[u8; MAX_NAME_SIZE],
        contents: &Vec<u8, MAX_CONTENTS_SIZE>,
    ) -> [u8; 32] {
        // The digest should contain the encrypted contents, group ID, UUID, and filename
        let mut mac = Hmac::<Sha256>::new_from_slice(contents.as_slice()).unwrap();
        mac.update(name);
        mac.update(&group_id.to_le_bytes());
        mac.update(uuid.as_bytes());

        mac.finalize().into_bytes().into()
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
            core::slice::from_raw_parts(self.fat.as_ptr() as *const u8, mem::size_of_val(&self.fat))
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
        let file = self.read_file(slot, flash)?;
        Ok(file.in_use == FILE_IN_USE)
    }

    /// Write a file to persistent flash storage.
    pub fn write_file(
        &mut self,
        slot: u8,
        file: &ProtectedFile,
        uuid: Uuid,
        flash: &mut impl Flash,
    ) -> Result<(), FsError> {
        self.write_file_inner(slot, file, uuid, flash, None)
    }

    /// Write a file to persistent flash storage with boot-relative sub-step logging.
    pub fn write_file_timed(
        &mut self,
        slot: u8,
        file: &ProtectedFile,
        uuid: Uuid,
        flash: &mut impl Flash,
        boot: Instant,
    ) -> Result<(), FsError> {
        self.write_file_inner(slot, file, uuid, flash, Some(boot))
    }

    fn write_file_inner(
        &mut self,
        slot: u8,
        file: &ProtectedFile,
        uuid: Uuid,
        flash: &mut impl Flash,
        boot: Option<Instant>,
    ) -> Result<(), FsError> {
        let idx = Self::validate_slot(slot)?;
        if let Some(boot) = boot {
            info!("[+{} ms] write_file inner start", elapsed_ms(boot));
        }

        let flash_addr = FILES_START_ADDR + STORED_FILE_SIZE * (idx as u32);
        let length = file_total_size(file.contents.len() as u16);

        // Update the cached FAT
        self.fat[idx].uuid = uuid;
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
        let pages_needed = (length as u32).div_ceil(FLASH_PAGE_SIZE);
        // let pages_needed = (length as u32 + FLASH_PAGE_SIZE - 1) / FLASH_PAGE_SIZE;
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
    pub fn read_file(&self, slot: u8, flash: &impl Flash) -> Result<ProtectedFile, FsError> {
        let idx = Self::validate_slot(slot)?;

        let entry = &self.fat[idx];
        if entry.is_empty() {
            return Err(FsError::InvalidFatEntry);
        }
        // Allocate a local uninitialized buffer for the bytes
        let mut bytes = [0u8; size_of::<ProtectedFile>()];

        // Read from flash into bytes
        flash.read(entry.flash_addr, &mut bytes);

        // Interpret bytes as ProtectedFile
        let file = unsafe {
            // pointer to bytes as *const ProtectedFile
            let p = bytes.as_ptr() as *const ProtectedFile;
            // read_unaligned to avoid alignment UB if alignment isn't guaranteed
            ptr::read_unaligned(p)
        };
        match file.verify_signature() {
            Ok(()) => Ok(file),
            Err(_) => Err(FsError::InvalidSignature),
        }
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
