//! Command dispatch and handlers for the eCTF host protocol.

use embassy_time::Instant;
use heapless::{Vec, format};
use x25519_dalek::{PublicKey, StaticSecret};
use zerocopy::transmute;
use zerocopy::transmute_mut;

use crate::authentication::{PIN_LENGTH, SecurityStatus, verify_pin};
use crate::crypto::{
    AUTH_TAG_SIZE, CryptoError, NONCE_SIZE, PUBLIC_KEY_SIZE, asymmetric_decrypt_in_place,
    asymmetric_encrypt_in_place,
};
use crate::host::{HostUart, MsgType};
use crate::permission::{
    self, PermissionType, get_receive_decrypt_key, get_receive_encrypt_key, has_permission,
};
use crate::secrets::{self, PIN_HASH, PIN_SALT};
use crate::secure_filesystem::{
    self, FILE_IN_USE, FileError, FileMetadata, Filesystem, Flash, FsError, MAX_CONTENTS_SIZE,
    MAX_FILE_COUNT, MAX_NAME_SIZE, ProtectedFile, UUID_SIZE,
};

pub const TRANSFER_PAYLOAD_SIZE: usize =
    size_of::<ProtectedFile>() + NONCE_SIZE + AUTH_TAG_SIZE + PUBLIC_KEY_SIZE + 2;

/// Dispatch a received command to the appropriate handler.
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

// ─── Command handler stubs ──────────────────────────────────────────

#[inline(never)]
fn cmd_list(
    host: &mut HostUart,
    pkt_len: u16,
    buf: &mut [u8],
    flash: &impl Flash,
    fs: &Filesystem,
) {
    host.print_debug("Checking PIN\n");
    if pkt_len < PIN_LENGTH as u16 {
        host.print_error("Invalid pin length!");
        return;
    }
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
        SecurityStatus::Success => host.print_debug("Pin successfully verified!"),
    };

    // Response format expected by host tools:
    //   nfiles (4 bytes u32 LE) + per-file entries (35 bytes each)
    // Entry: slot(1) + group_id(2) + name(32)
    const ENTRY_SIZE: usize = 1 + 2 + MAX_NAME_SIZE; // 35
    const HEADER_SIZE: usize = 4; // nfiles u32

    // Read file header from flash: in_use(4) + group_id(2) + name(32)
    const FILE_HDR_SIZE: usize = 4 + 2 + MAX_NAME_SIZE; // 38

    let mut nfiles: u32 = 0;
    // Build the response body in buf starting after a 38-byte scratch area
    // Layout: [scratch 38 bytes for flash reads][response: nfiles(4) + entries...]
    let resp_off = FILE_HDR_SIZE; // start response after scratch area

    for slot in 0..(MAX_FILE_COUNT as u8) {
        let entry = match fs.get_file_metadata(slot) {
            Ok(e) => e,
            Err(_) => continue,
        };

        if entry.is_empty() {
            continue;
        }

        // Read file header into scratch area buf[..38]
        flash.read(entry.flash_addr, &mut buf[..FILE_HDR_SIZE]);

        let in_use = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if in_use != secure_filesystem::FILE_IN_USE {
            continue;
        }

        // Save values from scratch area before writing into response area
        let group_lo = buf[4];
        let group_hi = buf[5];
        let mut name = [0u8; MAX_NAME_SIZE];
        name.copy_from_slice(&buf[6..6 + MAX_NAME_SIZE]);

        // Copy entry into response area
        let entry_off = resp_off + HEADER_SIZE + (nfiles as usize) * ENTRY_SIZE;
        buf[entry_off] = slot;
        buf[entry_off + 1] = group_lo;
        buf[entry_off + 2] = group_hi;
        buf[entry_off + 3..entry_off + 3 + MAX_NAME_SIZE].copy_from_slice(&name);

        nfiles += 1;
    }

    // Write nfiles header
    buf[resp_off..resp_off + 4].copy_from_slice(&nfiles.to_le_bytes());

    let total_len = HEADER_SIZE + (nfiles as usize) * ENTRY_SIZE;
    let _ = host.write_packet(MsgType::List, &buf[resp_off..resp_off + total_len]);
}

#[inline(never)]
fn cmd_read(host: &mut HostUart, pkt_len: u16, buf: &[u8], flash: &impl Flash, fs: &Filesystem) {
    const PIN_OFF: usize = 0;
    const SLOT_OFF: usize = 6;
    const CMD_SIZE: usize = 7;

    if (pkt_len as usize) < CMD_SIZE {
        host.print_error("Read packet too short");
        return;
    }

    host.print_debug("Checking PIN\n");

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
        SecurityStatus::Success => host.print_debug("Pin successfully verified!"),
    };

    let _pin = &buf[PIN_OFF..PIN_OFF + 6];
    let slot = buf[SLOT_OFF];
    host.print_debug("Read: Parsed slot and UUID\n");

    let mut file = ProtectedFile::default();
    match fs.read_file_in(&mut file, slot, flash) {
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
    host.print_debug("Read: Sent file contents response\n");
}

#[inline(never)]
fn cmd_write(
    host: &mut HostUart,
    pkt_len: u16,
    buf: &[u8],
    flash: &mut impl Flash,
    fs: &mut Filesystem,
) {
    // Start SysTick timer immediately to capture total command time
    const SYST_RVR: *mut u32 = 0xE000_E014 as *mut u32;
    const SYST_CVR: *mut u32 = 0xE000_E018 as *mut u32;
    const SYST_CSR: *mut u32 = 0xE000_E010 as *mut u32;
    unsafe {
        core::ptr::write_volatile(SYST_RVR, 0x00FF_FFFF); // max 24-bit
        core::ptr::write_volatile(SYST_CVR, 0); // clear current
        core::ptr::write_volatile(SYST_CSR, 0x05); // enable, processor clock, no interrupt
    }

    const PIN_OFF: usize = 0;
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
    host.print_debug("Checking PIN\n");
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
        SecurityStatus::Success => host.print_debug("Pin successfully verified!"),
    };

    let _pin = &buf[PIN_OFF..PIN_OFF + 6];
    let slot = buf[SLOT_OFF];
    let group_id = u16::from_le_bytes([buf[GROUP_OFF], buf[GROUP_OFF + 1]]);
    let name: [u8; 32] = buf[NAME_OFF..NAME_OFF + MAX_NAME_SIZE].try_into().unwrap();
    let uuid: [u8; 16] = buf[UUID_OFF..UUID_OFF + UUID_SIZE].try_into().unwrap();
    let contents_len = u16::from_le_bytes([buf[CLEN_OFF], buf[CLEN_OFF + 1]]) as usize;

    // Validate contents_len against actual packet payload
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

    // host.print_hex_debug(&flash_us.to_le_bytes());
    // Success — empty body
    let _ = host.write_packet(MsgType::Write, &[]);
}

#[inline(never)]
fn cmd_receive(
    host: &mut HostUart,
    uart1: &mut HostUart,
    _pkt_len: u16,
    buf: &mut [u8],
    flash: &mut impl Flash,
    fs: &mut Filesystem,
) {
    // Parse receive_command_t: pin(6) + read_slot(1) + write_slot(1) = 8 bytes
    if buf.len() < 8 {
        host.print_error("Invalid packet length!");
        return;
    }
    const READ_SLOT_OFF: usize = 6;
    const WRITE_SLOT_OFF: usize = 7;

    let read_slot = buf[READ_SLOT_OFF];
    let write_slot = buf[WRITE_SLOT_OFF];

    host.print_debug("Checking PIN\n");
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
        SecurityStatus::Success => host.print_debug("Pin successfully verified!"),
    };

    // Send receive request to neighbor (just the slot)
    let mut request_buf = [0u8; 1];
    request_buf[0] = read_slot;
    let _ = uart1.write_packet(MsgType::Receive, &request_buf);

    // Read response: nonce(12) + auth_tag(16) + pubkey(32) + encrypted ProtectedFile
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

    // ── Copy the 60-byte crypto header out of buf before we modify it ──
    const CRYPTO_HDR: usize = NONCE_SIZE + AUTH_TAG_SIZE + PUBLIC_KEY_SIZE; // 60

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

    // ── Shift ciphertext to start of buf so it aligns with ProtectedFile ──
    let ct_size = size_of::<ProtectedFile>();
    buf.copy_within(2 + CRYPTO_HDR..2 + CRYPTO_HDR + ct_size, 0);

    // ── Decrypt in-place in buf[..ct_size] ──
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

    // ── Reinterpret buf as ProtectedFile without copying ──
    // buf[..ct_size] now contains the decrypted ProtectedFile bytes.
    // Use zerocopy::Ref to get a reference instead of transmute (which copies).
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
    host.print_debug("Verified signature of received file!");

    // Write received file to local flash
    let flash_write_start = Instant::now();
    if let Err(e) = fs.write_file_timed(write_slot, file, file.uuid, flash, flash_write_start) {
        host.print_error(&format!(64; "Writing received file failed: {}", e).unwrap());
        return;
    }

    // Empty success message
    let _ = host.write_packet(MsgType::Receive, &[]);
}

#[inline(never)]
fn cmd_interrogate(host: &mut HostUart, uart1: &mut HostUart, _pkt_len: u16, buf: &mut [u8]) {
    host.print_debug("Checking PIN\n");
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
        SecurityStatus::Success => host.print_debug("Pin successfully verified!"),
    };

    // Send empty interrogate request to neighbor
    let _ = uart1.write_packet(MsgType::Interrogate, &[]);

    // Read list response from neighbor (standard binary format)
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

    // ── Parse binary response: nfiles(4) + entries(35 each) ──
    const ENTRY_SIZE: usize = 1 + 2 + MAX_NAME_SIZE; // 35
    const HEADER_SIZE: usize = 4;

    let recv_len = recv_len as usize;
    if recv_len < HEADER_SIZE {
        host.print_error("Interrogate: response too short");
        return;
    }

    let total_files = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;

    // ── Filter to files this HSM has receive permission for ──
    // Compact in-place: copy qualifying entries forward
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
                // Shift entry forward (safe: dst < src, no overlap)
                for j in 0..ENTRY_SIZE {
                    buf[dst_off + j] = buf[src_off + j];
                }
            }
            num_receivable += 1;
        }
    }

    // Overwrite nfiles header with filtered count
    buf[..4].copy_from_slice(&num_receivable.to_le_bytes());

    let total_len = HEADER_SIZE + (num_receivable as usize) * ENTRY_SIZE;
    let _ = host.write_packet(MsgType::Interrogate, &buf[..total_len]);
}

#[inline(never)]
fn cmd_listen(
    host: &mut HostUart,
    uart1: &mut HostUart,
    _pkt_len: u16,
    buf: &mut [u8], // ← was _buf; now used as scratch space
    flash: &impl Flash,
    fs: &Filesystem,
) {
    // Receive a packet from neighboring HSM via UART1
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
            host.print_debug("Received interrogate commannd!");
            // Build file list response in buf:
            //   n_files(4 bytes u32 LE) + per-file entries (35 bytes each)
            // Entry: slot(1) + group_id(2) + name(32)
            const ENTRY_SIZE: usize = 1 + 2 + MAX_NAME_SIZE; // 35
            const HEADER_SIZE: usize = 4; // n_files u32

            // On-flash ProtectedFile starts with: in_use(4) + group_id(2) + name(32) = 38
            const FILE_HDR_SIZE: usize = 4 + 2 + MAX_NAME_SIZE; // 38

            let mut nfiles: u32 = 0;
            let resp_off = FILE_HDR_SIZE; // response starts after scratch area

            for slot in 0..(MAX_FILE_COUNT as u8) {
                let entry = match fs.get_file_metadata(slot) {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                if entry.is_empty() {
                    continue;
                }

                // Read only the first 38 bytes (file header) from flash
                flash.read(entry.flash_addr, &mut buf[..FILE_HDR_SIZE]);

                let in_use = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                if in_use != FILE_IN_USE {
                    continue;
                }

                // Extract group_id and name from scratch area
                let group_lo = buf[4];
                let group_hi = buf[5];
                let mut name = [0u8; MAX_NAME_SIZE];
                name.copy_from_slice(&buf[6..6 + MAX_NAME_SIZE]);

                // Append entry to response area (after scratch)
                let entry_off = resp_off + HEADER_SIZE + (nfiles as usize) * ENTRY_SIZE;
                buf[entry_off] = slot;
                buf[entry_off + 1] = group_lo;
                buf[entry_off + 2] = group_hi;
                buf[entry_off + 3..entry_off + 3 + MAX_NAME_SIZE].copy_from_slice(&name);

                nfiles += 1;
            }

            // Write nfiles header
            buf[resp_off..resp_off + 4].copy_from_slice(&nfiles.to_le_bytes());

            let total_len = HEADER_SIZE + (nfiles as usize) * ENTRY_SIZE;
            let _ = uart1.write_packet(MsgType::Interrogate, &buf[resp_off..resp_off + total_len]);
            host.print_debug("Responded to interrogate!");
        }
        MsgType::Receive => {
            host.print_debug("Received receive command!");
            let slot = uart_buf[0];

            // Read file into a stack-allocated ProtectedFile (ONE copy only)
            let mut file = ProtectedFile::default();
            match fs.read_file_in(&mut file, slot, flash) {
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

            // Encrypt in-place via transmute_mut! to avoid extra copies and allocations
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

    // Success — blank message to host
    let _ = host.write_packet(MsgType::Listen, &[]);
}
