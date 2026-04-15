//! Command dispatch and handlers for the eCTF host protocol.
//!
//! Each handler will validate the packet, authenticate
//! the PIN (for protected commands), perform the operation, and send a typed
//! response back to the host. On failure an Error message is sent instead.

use x25519_dalek::{PublicKey, StaticSecret};
use zerocopy::transmute_mut;

use crate::authentication::{PIN_LENGTH, SecurityStatus, verify_pin};
use crate::crypto::{
    AUTH_TAG_SIZE, NONCE_SIZE, PUBLIC_KEY_SIZE, asymmetric_decrypt_in_place,
    asymmetric_encrypt_in_place,
};
use crate::host::{HostUart, MsgType};
use crate::permission::{
    self, PermissionType, get_receive_decrypt_key, get_receive_encrypt_key, has_permission,
};
use crate::secrets::{PIN_HASH, PIN_SALT};
use crate::secure_filesystem::{
    self, FILE_IN_USE, FileError, Filesystem, Flash, FsError, MAX_CONTENTS_SIZE, MAX_FILE_COUNT,
    MAX_NAME_SIZE, ProtectedFile, UUID_SIZE,
};
use heapless::format;

/// Maximum transfer payload size: encrypted `ProtectedFile` plus crypto header.
pub const TRANSFER_PAYLOAD_SIZE: usize =
    size_of::<ProtectedFile>() + NONCE_SIZE + AUTH_TAG_SIZE + PUBLIC_KEY_SIZE + 2;

// ─── PIN verification helper ───────────────────────────────────────

/// Verify the PIN from `buf` against the stored hash. Sends an error message
/// to `host` and returns `false` on failure.
fn verify_pin_or_error(host: &mut HostUart, buf: &[u8]) -> bool {
    let pin = &buf[0..PIN_LENGTH];
    match verify_pin(pin, &PIN_SALT, &PIN_HASH) {
        SecurityStatus::InvalidLength => {
            host.print_error("Invalid pin length. Pin must be 6 digits.");
            false
        }
        SecurityStatus::AuthFail => {
            host.print_error("Nice try! Invalid pin!");
            false
        }
        SecurityStatus::Success => true,
    }
}

// ─── Command dispatch ──────────────────────────────────────────────

/// Route an incoming host command to the appropriate handler.
#[inline(never)]
pub fn handle_command(
    host: &mut HostUart,
    uart1: &mut HostUart,
    cmd: MsgType,
    pkt_len: u16,
    buf: &mut [u8],
    flash: &mut impl Flash,
    fs: &mut Filesystem,
) {
    match cmd {
        MsgType::List => cmd_list(host, pkt_len, buf, flash, fs),
        MsgType::Read => cmd_read(host, pkt_len, buf, flash, fs),
        MsgType::Write => cmd_write(host, pkt_len, buf, flash, fs),
        MsgType::Receive => cmd_receive(host, uart1, pkt_len, buf, flash, fs),
        MsgType::Interrogate => cmd_interrogate(host, uart1, pkt_len, buf),
        MsgType::Listen => cmd_listen(host, uart1, pkt_len, buf, flash, fs),
        _ => {
            host.print_error("Invalid Command");
        }
    }
}

// ─── List ──────────────────────────────────────────────────────────

/// List all files stored on this HSM (pin-protected).
///
/// Response: `nfiles(4B) + [slot(1) + group_id(2) + name(32)] * nfiles`
#[inline(never)]
fn cmd_list(
    host: &mut HostUart,
    pkt_len: u16,
    buf: &mut [u8],
    flash: &impl Flash,
    fs: &Filesystem,
) {
    if pkt_len < PIN_LENGTH as u16 {
        host.print_error("Invalid pin length!");
        return;
    }
    if !verify_pin_or_error(host, buf) {
        return;
    }

    const ENTRY_SIZE: usize = 1 + 2 + MAX_NAME_SIZE; // 35 bytes per file
    const HEADER_SIZE: usize = 4; // nfiles u32

    // On-flash file header: in_use(4) + group_id(2) + name(32) = 38 bytes.
    // The first 38 bytes of `buf` are used as scratch for flash reads;
    // the response is assembled immediately after.
    const FILE_HDR_SIZE: usize = 4 + 2 + MAX_NAME_SIZE;
    let resp_off = FILE_HDR_SIZE;

    let mut nfiles: u32 = 0;

    for slot in 0..(MAX_FILE_COUNT as u8) {
        let entry = match fs.get_file_metadata(slot) {
            Ok(e) => e,
            Err(_) => continue,
        };
        if entry.is_empty() {
            continue;
        }

        // Read file header into scratch area buf[..38].
        flash.read(entry.flash_addr, &mut buf[..FILE_HDR_SIZE]);

        let in_use = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if in_use != secure_filesystem::FILE_IN_USE {
            continue;
        }

        // Capture values from scratch before overwriting the response region.
        let group_lo = buf[4];
        let group_hi = buf[5];
        let mut name = [0u8; MAX_NAME_SIZE];
        name.copy_from_slice(&buf[6..6 + MAX_NAME_SIZE]);

        let entry_off = resp_off + HEADER_SIZE + (nfiles as usize) * ENTRY_SIZE;
        buf[entry_off] = slot;
        buf[entry_off + 1] = group_lo;
        buf[entry_off + 2] = group_hi;
        buf[entry_off + 3..entry_off + 3 + MAX_NAME_SIZE].copy_from_slice(&name);

        nfiles += 1;
    }

    buf[resp_off..resp_off + 4].copy_from_slice(&nfiles.to_le_bytes());

    let total_len = HEADER_SIZE + (nfiles as usize) * ENTRY_SIZE;
    let _ = host.write_packet(MsgType::List, &buf[resp_off..resp_off + total_len]);
}

// ─── Read ──────────────────────────────────────────────────────────

/// Read a file from the HSM and return its plaintext (pin-protected).
///
/// Response: `name(32B) + plaintext(variable)`
#[inline(never)]
fn cmd_read(host: &mut HostUart, pkt_len: u16, buf: &[u8], flash: &impl Flash, fs: &Filesystem) {
    const SLOT_OFF: usize = 6;
    const CMD_SIZE: usize = 7; // pin(6) + slot(1)

    if (pkt_len as usize) < CMD_SIZE {
        host.print_error("Read packet too short");
        return;
    }
    if !verify_pin_or_error(host, buf) {
        return;
    }

    let slot = buf[SLOT_OFF];

    let mut file = ProtectedFile::default();
    match fs.read_file(&mut file, slot, flash) {
        Ok(()) => (),
        Err(FsError::EmptySlot) => {
            host.print_error(&format!(20; "Slot {} is empty", slot).unwrap());
            return;
        }
        Err(FsError::InvalidSlot) => {
            host.print_error(&format!(20; "Invalid slot: {}", slot).unwrap());
            return;
        }
        Err(FsError::InvalidSignature) => {
            host.print_error("Invalid signature");
            return;
        }
        Err(e) => {
            host.print_error(&format!(64; "Read failed: {}", e).unwrap());
            return;
        }
    };

    let group_id = file.group_id;

    let read_key = if let Some(bytes) = permission::get_read_decrypt_key(file.group_id) {
        StaticSecret::from(bytes)
    } else {
        host.print_error(
            &format!(64; "HSM has no permissions to read files from group: {:#x}", group_id)
                .unwrap(),
        );
        return;
    };

    if asymmetric_decrypt_in_place(
        &mut file.ciphertext,
        &file.nonce,
        &PublicKey::from(file.ciphertext_public_key),
        &file.auth_tag,
        &read_key,
    )
    .is_err()
    {
        host.print_error("Error while decrypting file!");
        return;
    };
    let plaintext = &file.ciphertext[..file.plaintext_len];

    let _ = host.write_packet_chunks(MsgType::Read, &[&file.name, plaintext]);
}

// ─── Write ─────────────────────────────────────────────────────────

/// Write a file to the HSM (pin-protected).
///
/// Command body layout:
///   pin(6) + slot(1) + group_id(2) + name(32) + uuid(16) + contents_len(2) + contents(N)
///
/// Response: empty body on success.
#[inline(never)]
fn cmd_write(
    host: &mut HostUart,
    pkt_len: u16,
    buf: &[u8],
    flash: &mut impl Flash,
    fs: &mut Filesystem,
) {
    // SysTick timer — used for performance profiling during development.
    const SYST_RVR: *mut u32 = 0xE000_E014 as *mut u32;
    const SYST_CVR: *mut u32 = 0xE000_E018 as *mut u32;
    const SYST_CSR: *mut u32 = 0xE000_E010 as *mut u32;
    unsafe {
        core::ptr::write_volatile(SYST_RVR, 0x00FF_FFFF); // max 24-bit reload
        core::ptr::write_volatile(SYST_CVR, 0); // clear current value
        core::ptr::write_volatile(SYST_CSR, 0x05); // enable, processor clock, no IRQ
    }

    // Field offsets within the command body.
    const SLOT_OFF: usize = 6;
    const GROUP_OFF: usize = 7;
    const NAME_OFF: usize = 9;
    const UUID_OFF: usize = 41;
    const CLEN_OFF: usize = 57;
    const CONTENTS_OFF: usize = 59;

    if (pkt_len as usize) < CONTENTS_OFF {
        host.print_error("Write packet too short");
        return;
    }
    if !verify_pin_or_error(host, buf) {
        return;
    }

    let slot = buf[SLOT_OFF];
    let group_id = u16::from_le_bytes([buf[GROUP_OFF], buf[GROUP_OFF + 1]]);
    let name: [u8; 32] = buf[NAME_OFF..NAME_OFF + MAX_NAME_SIZE].try_into().unwrap();
    let uuid: [u8; 16] = buf[UUID_OFF..UUID_OFF + UUID_SIZE].try_into().unwrap();
    let contents_len = u16::from_le_bytes([buf[CLEN_OFF], buf[CLEN_OFF + 1]]) as usize;

    if contents_len > MAX_CONTENTS_SIZE || CONTENTS_OFF + contents_len > pkt_len as usize {
        host.print_error("Invalid contents length");
        return;
    }

    let contents = &buf[CONTENTS_OFF..CONTENTS_OFF + contents_len];

    let mut file = ProtectedFile::default();
    match ProtectedFile::create_in(&mut file, group_id, uuid, &name, contents) {
        Ok(()) => (),
        Err(FileError::NoWritePermission) => {
            host.print_error(
                &format!(
                    64; "HSM does not have permission to write files from group: {:#x}",
                    group_id
                )
                .unwrap(),
            );
            return;
        }
        Err(e) => {
            host.print_error(&format!(64; "File creation failed: {}", e).unwrap());
            return;
        }
    };

    if let Err(e) = fs.write_file(slot, &file, uuid, flash) {
        host.print_error(&format!(64; "Flash write failed: {}", e).unwrap());
        return;
    }

    let _ = host.write_packet(MsgType::Write, &[]);
}

// ─── Receive ───────────────────────────────────────────────────────

/// Receive a file from a neighbor HSM via UART1 and store it locally (pin-protected).
///
/// Command body: `pin(6) + read_slot(1) + write_slot(1)`
///
/// The local HSM sends a Receive request to the neighbor, which responds with
/// a crypto header (group_id + nonce + auth_tag + public_key) followed by the
/// encrypted `ProtectedFile`. After decryption and signature verification the
/// file is written to `write_slot`.
///
/// Response: empty body on success.
#[inline(never)]
fn cmd_receive(
    host: &mut HostUart,
    uart1: &mut HostUart,
    _pkt_len: u16,
    buf: &mut [u8],
    flash: &mut impl Flash,
    fs: &mut Filesystem,
) {
    if buf.len() < 8 {
        host.print_error("Invalid packet length!");
        return;
    }

    const READ_SLOT_OFF: usize = 6;
    const WRITE_SLOT_OFF: usize = 7;

    let read_slot = buf[READ_SLOT_OFF];
    let write_slot = buf[WRITE_SLOT_OFF];

    let pin = &buf[0..PIN_LENGTH];
    match verify_pin(pin, &PIN_SALT, &PIN_HASH) {
        SecurityStatus::InvalidLength => {
            host.print_error("Invalid pin length. Pin must be 6 digits.");
            return;
        }
        SecurityStatus::AuthFail => {
            host.print_error("Nice try! Invalid pin!");
            return;
        }
        SecurityStatus::Success => (),
    };

    // Request the file from the neighbor HSM.
    let _ = uart1.write_packet(MsgType::Receive, &[read_slot]);

    // Read response: group_id(2) + nonce(12) + auth_tag(16) + pubkey(32) + encrypted file.
    let (cmd, recv_len) = match uart1.read_packet(buf, buf.len() as u16) {
        Ok(v) => v,
        Err(e) => {
            host.print_error(&format!(128; "Receive: Read from neighbor failed. {}", e).unwrap());
            return;
        }
    };

    if cmd != MsgType::Receive {
        host.print_error("Receive: opcode mismatch");
        return;
    }

    if recv_len < TRANSFER_PAYLOAD_SIZE as u16 {
        host.print_error("Received file is incorrect size");
        return;
    }

    // Extract the crypto header before modifying `buf`.
    const CRYPTO_HDR: usize = NONCE_SIZE + AUTH_TAG_SIZE + PUBLIC_KEY_SIZE;

    let group_id = u16::from_le_bytes([buf[0], buf[1]]);
    let mut nonce_copy = [0u8; NONCE_SIZE];
    nonce_copy.copy_from_slice(&buf[2..NONCE_SIZE + 2]);

    let mut auth_tag_copy = [0u8; AUTH_TAG_SIZE];
    auth_tag_copy.copy_from_slice(&buf[2 + NONCE_SIZE..2 + NONCE_SIZE + AUTH_TAG_SIZE]);

    let mut pubkey_bytes = [0u8; PUBLIC_KEY_SIZE];
    pubkey_bytes.copy_from_slice(
        &buf[2 + NONCE_SIZE + AUTH_TAG_SIZE..2 + NONCE_SIZE + AUTH_TAG_SIZE + PUBLIC_KEY_SIZE],
    );
    let ciphertext_public_key = PublicKey::from(pubkey_bytes);

    // Shift the encrypted ProtectedFile to the start of `buf`.
    let ct_size = size_of::<ProtectedFile>();
    buf.copy_within(2 + CRYPTO_HDR..2 + CRYPTO_HDR + ct_size, 0);

    // Decrypt in-place.
    let ciphertext = &mut buf[..ct_size];

    let receive_decrypt_key = match get_receive_decrypt_key(group_id) {
        Some(receive_key) => receive_key,
        None => {
            host.print_error("HSM does not have permission to receive file!");
            return;
        }
    };
    match asymmetric_decrypt_in_place(
        ciphertext,
        &nonce_copy,
        &ciphertext_public_key,
        &auth_tag_copy,
        &StaticSecret::from(receive_decrypt_key),
    ) {
        Ok(()) => (),
        Err(e) => {
            host.print_error(&format!(128; "Unable to decrypt received file! {}", e).unwrap());
            return;
        }
    };

    // Reinterpret the decrypted bytes as a ProtectedFile (zero-copy).
    let file: &ProtectedFile =
        match zerocopy::Ref::<&[u8], ProtectedFile>::from_bytes(&buf[..ct_size]) {
            Ok(r) => zerocopy::Ref::<&[u8], ProtectedFile>::into_ref(r),
            Err(_) => {
                host.print_error("Failed to parse received file");
                return;
            }
        };

    // Signature check
    if file.verify_signature().is_err() {
        host.print_error("Invalid signature on received file");
        return;
    }

    // Write received file to local flash
    if let Err(e) = fs.write_file(write_slot, file, file.uuid, flash) {
        host.print_error(&format!(64; "Writing received file failed: {}", e).unwrap());
        return;
    }

    // Empty success message
    let _ = host.write_packet(MsgType::Receive, &[]);
}

// ─── Interrogate ───────────────────────────────────────────────────

/// Ask a neighbor HSM for its file list, filtered to groups this HSM can
/// receive (pin-protected).
///
/// Response: `nfiles(4B) + [slot(1) + group_id(2) + name(32)] * nfiles`
/// (only files whose group this HSM has receive permission for).
#[inline(never)]
fn cmd_interrogate(host: &mut HostUart, uart1: &mut HostUart, _pkt_len: u16, buf: &mut [u8]) {
    if !verify_pin_or_error(host, buf) {
        return;
    }

    // Send an empty Interrogate request to the neighbor.
    let _ = uart1.write_packet(MsgType::Interrogate, &[]);

    // Read the neighbor's file list response.
    let (cmd, recv_len) = match uart1.read_packet(buf, buf.len() as u16) {
        Ok(v) => v,
        Err(e) => {
            host.print_error(
                &format!(128; "Interrogate: Read from neighbor failed! Have you tried enhanced interrogation? {}", e).unwrap(),
            );
            return;
        }
    };

    if cmd != MsgType::Interrogate {
        host.print_error("Interrogate: opcode mismatch");
        return;
    }

    const ENTRY_SIZE: usize = 1 + 2 + MAX_NAME_SIZE; // 35
    const HEADER_SIZE: usize = 4;

    let recv_len = recv_len as usize;
    if recv_len < HEADER_SIZE {
        host.print_error("Interrogate: response too short");
        return;
    }

    let total_files = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;

    // Filter in-place: keep only entries whose group this HSM can receive.
    let mut num_receivable: u32 = 0;
    for i in 0..total_files {
        let src_off = HEADER_SIZE + i * ENTRY_SIZE;
        if src_off + ENTRY_SIZE > recv_len {
            break;
        }

        let group_id = u16::from_le_bytes([buf[src_off + 1], buf[src_off + 2]]);
        if has_permission(group_id, PermissionType::Receive) {
            let dst_off = HEADER_SIZE + (num_receivable as usize) * ENTRY_SIZE;
            if dst_off != src_off {
                for j in 0..ENTRY_SIZE {
                    buf[dst_off + j] = buf[src_off + j];
                }
            }
            num_receivable += 1;
        }
    }

    buf[..4].copy_from_slice(&num_receivable.to_le_bytes());

    let total_len = HEADER_SIZE + (num_receivable as usize) * ENTRY_SIZE;
    let _ = host.write_packet(MsgType::Interrogate, &buf[..total_len]);
}

// ─── Listen ────────────────────────────────────────────────────────

/// Wait for an Interrogate or Receive request from a neighbor HSM on UART1
/// and handle it (not pin-protected).
///
/// - **Interrogate**: reply with this HSM's full file list.
/// - **Receive**: encrypt and send the requested file to the neighbor.
///
/// Response to host: empty body on success.
#[inline(never)]
fn cmd_listen(
    host: &mut HostUart,
    uart1: &mut HostUart,
    _pkt_len: u16,
    buf: &mut [u8],
    flash: &impl Flash,
    fs: &Filesystem,
) {
    // Read an inbound request from the neighbor HSM.
    let mut uart_buf = [0u8; 41];
    let max_len = uart_buf.len() as u16;
    let (cmd, _read_len) = match uart1.read_packet(&mut uart_buf, max_len) {
        Ok(v) => v,
        Err(e) => {
            host.print_error(&format!(128; "Listen: Read from neighbor failed. {}", e).unwrap());
            return;
        }
    };

    match cmd {
        MsgType::Interrogate => {
            // Build the same file-list response format used by cmd_list.
            const ENTRY_SIZE: usize = 1 + 2 + MAX_NAME_SIZE;
            const HEADER_SIZE: usize = 4;
            const FILE_HDR_SIZE: usize = 4 + 2 + MAX_NAME_SIZE;

            let mut nfiles: u32 = 0;
            let resp_off = FILE_HDR_SIZE;

            for slot in 0..(MAX_FILE_COUNT as u8) {
                let entry = match fs.get_file_metadata(slot) {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                if entry.is_empty() {
                    continue;
                }

                flash.read(entry.flash_addr, &mut buf[..FILE_HDR_SIZE]);

                let in_use = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                if in_use != FILE_IN_USE {
                    continue;
                }

                let group_lo = buf[4];
                let group_hi = buf[5];
                let mut name = [0u8; MAX_NAME_SIZE];
                name.copy_from_slice(&buf[6..6 + MAX_NAME_SIZE]);

                let entry_off = resp_off + HEADER_SIZE + (nfiles as usize) * ENTRY_SIZE;
                buf[entry_off] = slot;
                buf[entry_off + 1] = group_lo;
                buf[entry_off + 2] = group_hi;
                buf[entry_off + 3..entry_off + 3 + MAX_NAME_SIZE].copy_from_slice(&name);

                nfiles += 1;
            }

            buf[resp_off..resp_off + 4].copy_from_slice(&nfiles.to_le_bytes());

            let total_len = HEADER_SIZE + (nfiles as usize) * ENTRY_SIZE;
            let _ = uart1.write_packet(MsgType::Interrogate, &buf[resp_off..resp_off + total_len]);
        }
        MsgType::Receive => {
            let slot = uart_buf[0];

            let mut file = ProtectedFile::default();
            match fs.read_file_no_verify(&mut file, slot, flash) {
                Ok(()) => (),
                Err(FsError::EmptySlot) | Err(FsError::InvalidFatEntry) => {
                    host.print_error(&format!(20; "Slot {} is empty", slot).unwrap());
                    return;
                }
                Err(FsError::InvalidSlot) => {
                    host.print_error(&format!(20; "Invalid slot: {}", slot).unwrap());
                    return;
                }
                Err(FsError::InvalidSignature) => {
                    host.print_error("File has invalid signature!");
                    return;
                }
                Err(e) => {
                    host.print_error(&format!(64; "Read failed: {}", e).unwrap());
                    return;
                }
            };

            let group_id = file.group_id;

            let receive_encrypt_key = match get_receive_encrypt_key(group_id) {
                Some(key) => key,
                None => {
                    host.print_error("Invalid group ID");
                    return;
                }
            };

            // Encrypt the file in-place via transmute_mut to avoid extra copies.
            let file_buf: &mut [u8; size_of::<ProtectedFile>()] = transmute_mut!(&mut file);
            let (nonce, auth_tag, cipher_public_key) = match asymmetric_encrypt_in_place::<
                { size_of::<ProtectedFile>() },
            >(
                file_buf, &receive_encrypt_key
            ) {
                Ok(metadata) => metadata,
                Err(_) => {
                    host.print_error("Failed to encrypt file!");
                    return;
                }
            };

            uart1.write_packet_chunks(
                MsgType::Receive,
                &[
                    &group_id.to_le_bytes(),
                    &nonce,
                    &auth_tag,
                    &cipher_public_key.to_bytes(),
                    file_buf,
                ],
            );
        }
        _ => {
            host.print_error("Listen: bad message type from neighbor");
            return;
        }
    }

    let _ = host.write_packet(MsgType::Listen, &[]);
}