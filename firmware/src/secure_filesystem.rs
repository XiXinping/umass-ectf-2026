// Secure Filesystem Implementation
// provides a secure interface for file operations

use crate::crypto::{
    AUTH_TAG_SIZE, NONCE_SIZE, PUBLIC_KEY_SIZE, SIGNATURE_SIZE, asymmetric_decrypt_in_place,
    asymmetric_encrypt_in_place, ecc_sign_file_digest, ecc_verify_file_digest,
};
use crate::permission::{self, get_verifying_key};

use core::mem;
use defmt::{info, println};
use ed25519_dalek::{Signature, Signer, Verifier};
use embassy_time::Instant;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, transmute, transmute_mut};

// ─── Constants (must match C functional spec) ───────────────────────
pub const MAX_FILE_COUNT: usize = 8;
pub const MAX_NAME_SIZE: usize = 32;
pub const MAX_CONTENTS_SIZE: usize = 8192;
pub const MAX_SERIALIZED_FILE: usize = MAX_CONTENTS_SIZE + 512;
pub const UUID_SIZE: usize = 16;

// protected file structure constants

/// FAT location is fixed by the eCTF functional spec — do NOT change.
const FLASH_FAT_START: u32 = 0x0003_a000;

/// Flash page (sector) size on MSPM0L2228.
const FLASH_PAGE_SIZE: u32 = 1024;

/// Each file occupies 9 pages: 8 for contents + 1 for metadata.
const FILE_PAGE_COUNT: u32 = 9;
const STORED_FILE_SIZE: u32 = FLASH_PAGE_SIZE * FILE_PAGE_COUNT;

/// First flash address for file storage.
const FILES_START_ADDR: u32 = 0x0002_8000;

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
#[derive(Clone, Copy, defmt::Format, Default)]
pub struct FatEntry {
    pub uuid: [u8; 16],
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

/// On-flash protected file structure
#[repr(Rust, packed)]
#[derive(PartialEq, Debug, Immutable, KnownLayout, FromBytes, IntoBytes)]
pub struct ProtectedFile {
    // Metadata
    pub in_use: u32,
    pub group_id: u16,
    pub name: [u8; MAX_NAME_SIZE],
    // pub uuid: Uuid,
    pub uuid: [u8; 16],
    pub nonce: [u8; NONCE_SIZE],
    pub auth_tag: [u8; 16],
    // pub signature: Signature,
    pub signature: [u8; 64],
    // pub ciphertext_public_key: PublicKey,
    pub ciphertext_public_key: [u8; 32],
    // The encrypted contents of the file.
    // pub contents: Vec<u8, MAX_CONTENTS_SIZE>,
    // pub contents: Contents,
    // The plaintext may be shorter than the ciphertext
    pub plaintext_len: usize,
    pub ciphertext: [u8; MAX_CONTENTS_SIZE],
    // The padding brings the size of ProtectedFile to a multiple of the AES block cipher so it can
    // easily be encrpyted and decrypted in place.
    _padding: [u8; 10],
}

#[repr(Rust, packed)]
#[derive(PartialEq, Debug, Immutable, KnownLayout, FromBytes, IntoBytes)]
pub struct UnprotectedFile {
    pub in_use: u32,
    pub group_id: u16,
    pub name: [u8; MAX_NAME_SIZE],
    pub uuid: [u8; 16],
    pub plaintext_len: usize,
    pub plaintext: [u8; MAX_CONTENTS_SIZE],
}

#[repr(Rust, packed)]
#[derive(Copy, Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct FileMetadata {
    pub slot: u8,
    pub group_id: u16,
    pub name: [u8; MAX_NAME_SIZE],
}

impl Default for ProtectedFile {
    fn default() -> ProtectedFile {
        ProtectedFile {
            in_use: 0,
            group_id: 0,
            uuid: [0; UUID_SIZE],
            name: [0; MAX_NAME_SIZE],
            nonce: [0; NONCE_SIZE],
            auth_tag: [0; AUTH_TAG_SIZE],
            signature: [0; SIGNATURE_SIZE],
            ciphertext_public_key: [0; PUBLIC_KEY_SIZE],
            ciphertext: [0; MAX_CONTENTS_SIZE],
            plaintext_len: 0,
            _padding: [0; 10],
        }
    }
}

// TO-DO: Add signature check
impl ProtectedFile {
    pub fn signature(&self) -> Signature {
        Signature::from_slice(&self.signature).unwrap()
    }
    pub fn ciphertext_public_key(&self) -> PublicKey {
        PublicKey::from(self.ciphertext_public_key)
    }
    pub fn verify_signature(&self) -> Result<(), FileError> {
        // Get the write verifying key for the group ID
        let write_verifying_key =
            get_verifying_key(self.group_id).ok_or(FileError::InvalidGroupId)?;

        // The digest should contain the encrypted contents, group ID, UUID, and filename
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.ciphertext).unwrap();
        mac.update(&self.name);
        mac.update(&self.group_id.to_le_bytes());
        mac.update(&self.uuid);

        let digest = mac.finalize().into_bytes();

        write_verifying_key
            .verify(&digest, &self.signature())
            .map_err(|_| FileError::InvalidSignature)
    }
    // Attempt to return the decrypted contents of the file.
    // pub fn decrypt(&self) -> Result<Vec<u8, MAX_CONTENTS_SIZE>, FileError> {
    //     let read_key_bytes = permission::get_private_key(self.group_id, PermissionType::Read)
    //         .ok_or(FileError::NoReadPermission)?;
    //
    //     asymmetric_decrypt(
    //         &self.contents,
    //         &self.nonce,
    //         &self.ciphertext_public_key,
    //         &self.auth_tag,
    //         &StaticSecret::from(read_key_bytes),
    //     )
    //     .map_err(|_| FileError::DecryptError)
    // }

    pub fn to_unprotected_file(mut self) -> Result<UnprotectedFile, FileError> {
        let read_key_bytes =
            permission::get_read_decrypt_key(self.group_id).ok_or(FileError::NoReadPermission)?;
        let nonce = self.nonce;
        let ciphertext_public_key = self.ciphertext_public_key();
        let auth_tag = self.auth_tag;
        asymmetric_decrypt_in_place(
            &mut self.ciphertext,
            &nonce,
            &ciphertext_public_key,
            &auth_tag,
            &StaticSecret::from(read_key_bytes),
        )
        .map_err(|_| FileError::DecryptError)?;
        Ok(UnprotectedFile {
            in_use: self.in_use,
            group_id: self.group_id,
            name: self.name,
            uuid: self.uuid,
            plaintext_len: self.plaintext_len,
            plaintext: self.ciphertext,
        })
    }

    /// Create a new ProtectedFile and output to an already existing file. This avoids creating
    /// unnecessaary copies on the stack.
    pub fn create_in(
        out: &mut ProtectedFile,
        group_id: u16,
        uuid: [u8; 16],
        name: &[u8; MAX_NAME_SIZE],
        contents: &[u8],
    ) -> Result<(), FileError> {
        let contents = if contents.len() > MAX_CONTENTS_SIZE {
            &contents[..MAX_CONTENTS_SIZE]
        } else {
            contents
        };

        let write_key =
            permission::get_signing_key(group_id).ok_or(FileError::NoWritePermission)?;
        let read_encrypt_key =
            permission::get_read_encrypt_key(group_id).ok_or(FileError::InvalidGroupId)?;

        out.ciphertext[..contents.len()].copy_from_slice(contents);

        let (nonce, auth_tag, cipher_public_key) =
            asymmetric_encrypt_in_place::<MAX_CONTENTS_SIZE>(
                &mut out.ciphertext,
                &read_encrypt_key,
            )
            .map_err(|_| FileError::EncryptError)?;

        let digest = Self::digest(group_id, uuid, name, &out.ciphertext);
        let signature = write_key.sign(&digest);
        out.in_use = FILE_IN_USE;
        out.group_id = group_id;
        out.uuid = uuid;
        out.name = *name;
        out.nonce = nonce;
        out.auth_tag = auth_tag;
        out.signature = signature.to_bytes();
        out.ciphertext_public_key = cipher_public_key.to_bytes();
        out.plaintext_len = contents.len();
        out._padding = [0; 10];

        Ok(())
    }

    /// Create a cryptographic digest using HMAC with SHA-256 using a file's contents, group ID,
    /// UUID, and name.
    pub fn digest(
        group_id: u16,
        uuid: [u8; 16],
        name: &[u8; MAX_NAME_SIZE],
        contents: &[u8],
    ) -> [u8; 32] {
        // The digest should contain the encrypted contents, group ID, UUID, and filename
        let mut mac = Hmac::<Sha256>::new_from_slice(contents).unwrap();
        mac.update(name);
        mac.update(&group_id.to_le_bytes());
        mac.update(uuid.as_bytes());

        mac.finalize().into_bytes().into()
    }

    pub fn metadata(&self, slot: u8) -> FileMetadata {
        FileMetadata {
            slot,
            group_id: self.group_id,
            name: self.name,
        }
    }
}

// impl UnprotectedFile {
//     pub fn to_protected_file(mut self) -> Result<ProtectedFile, FileError> {
//         let read_public_key =
//             get_public_key(self.group_id, PermissionType::Read).ok_or(FileError::InvalidGroupId)?;
//
//         let write_private_key = get_prviate_key()
//
//         let encryption_metadata =
//             asymmetric_encrypt_in_place(&mut self.contents, &PublicKey::from(read_public_key))
//                 .map_err(|_| FileError::EncryptError)?;
//
//         let digest = ProtectedFile::digest(self.group_id, self.uuid, self.name, &self.contents);
//         let signature = ecc_sign_file_digest(&digest, &write_key_bytes)
//             .map_err(|_| FileError::GenSignatureError)?;
//
//         Ok(ProtectedFile {
//             in_use: self.in_use,
//             group_id: self.group_id,
//             name: self.name,
//             uuid: self.uuid,
//             nonce: encryption_metadata.nonce,
//             auth_tag: encryption_metadata.auth_tag,
//             ciphertext_public_key: encryption_metadata.cipher_public_key,
//             signature: encryption_metadata,
//             contents: self.contents,
//         })
//     }
//     pub fn metadata(&self, slot: u8) -> FileMetadata {
//         FileMetadata {
//             slot,
//             group_id: self.group_id,
//             name: self.name,
//         }
//     }
// }

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
        uuid: [u8; 16],
        flash: &mut impl Flash,
    ) -> Result<(), FsError> {
        self.write_file_inner(slot, file, uuid, flash, None)
    }

    /// Write a file to persistent flash storage with boot-relative sub-step logging.
    pub fn write_file_timed(
        &mut self,
        slot: u8,
        file: &ProtectedFile,
        uuid: [u8; 16],
        flash: &mut impl Flash,
        boot: Instant,
    ) -> Result<(), FsError> {
        self.write_file_inner(slot, file, uuid, flash, Some(boot))
    }

    fn write_file_inner(
        &mut self,
        slot: u8,
        file: &ProtectedFile,
        uuid: [u8; 16],
        flash: &mut impl Flash,
        boot: Option<Instant>,
    ) -> Result<(), FsError> {
        let idx = Self::validate_slot(slot)?;
        if let Some(boot) = boot {
            println!("[+{} ms] write_file inner start", elapsed_ms(boot));
        }

        let length = file.as_bytes().len() as u16;

        let flash_addr = FILES_START_ADDR + STORED_FILE_SIZE * (idx as u32);
        // let length = file_total_size(file.contents.len() as u16);

        // Update the cached FAT
        self.fat[idx].uuid = uuid;
        self.fat[idx].flash_addr = flash_addr;
        self.fat[idx].length = length;
        let fat_start = Instant::now();
        self.store_fat(flash)?;
        if let Some(boot) = boot {
            println!(
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
        // let file_bytes = unsafe {
        //     core::slice::from_raw_parts(file as *const ProtectedFile as *const u8, length as usize)
        // };
        let write_start = Instant::now();
        flash.write(flash_addr, file.as_bytes())?;
        if let Some(boot) = boot {
            println!(
                "[+{} ms] write_file payload write done (step={} ms)",
                elapsed_ms(boot),
                elapsed_ms(write_start)
            );
            println!("[+{} ms] write_file inner done", elapsed_ms(boot));
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

        let len = entry.length as usize;
        if len > MAX_SERIALIZED_FILE {
            return Err(FsError::InvalidFatEntry);
        }
        let mut buf = [0u8; size_of::<ProtectedFile>()];
        // Read from flash into bytes
        flash.read(entry.flash_addr, &mut buf[..len]);
        // Interpret bytes as ProtectedFile struct
        let file: ProtectedFile = transmute!(buf);

        match file.verify_signature() {
            Ok(()) => Ok(file),
            Err(_) => Err(FsError::InvalidSignature),
        }
    }

    pub fn read_file_in(
        &self,
        out: &mut ProtectedFile,
        slot: u8,
        flash: &impl Flash,
    ) -> Result<(), FsError> {
        let idx = Self::validate_slot(slot)?;

        let entry = &self.fat[idx];

        if entry.is_empty() {
            return Err(FsError::InvalidFatEntry);
        }

        let len = entry.length as usize;
        if len > MAX_SERIALIZED_FILE {
            return Err(FsError::InvalidFatEntry);
        }
        let buf: &mut [u8; size_of::<ProtectedFile>()] = transmute_mut!(out);
        // Read from flash into bytes
        flash.read(entry.flash_addr, &mut buf[..len]);

        out.verify_signature()
            .map_err(|_| FsError::InvalidSignature)?;

        Ok(())
    }

    /// Get read-only access to a FAT entry's metadata.
    pub fn get_file_metadata(&self, slot: u8) -> Result<&FatEntry, FsError> {
        let idx = Self::validate_slot(slot)?;
        Ok(&self.fat[idx])
    }
}

// ─── Helpers ────────────────────────────────────────────────────────

fn elapsed_ms(since: Instant) -> u64 {
    Instant::now().duration_since(since).as_millis()
}
