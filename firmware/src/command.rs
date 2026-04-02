//! Command dispatch and handlers for the eCTF host protocol.

use heapless::{Vec, format};
use uuid::Uuid;

use crate::authentication::{PIN_LENGTH, SecurityStatus, verify_pin};
use crate::host::{HostUart, MsgType};
use crate::secrets::{PIN_HASH, PIN_SALT};
use crate::secure_filesystem::{
    self, FILE_IN_USE, FileError, Filesystem, Flash, FsError, MAX_CONTENTS_SIZE, MAX_FILE_COUNT,
    MAX_NAME_SIZE, ProtectedFile, UUID_SIZE,
};

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
    if buf.len() < PIN_LENGTH {
        host.print_debug("Invalid pin length!");
        return;
    }
    let pin = &buf[0..PIN_LENGTH];
    match verify_pin(pin, &PIN_SALT, &PIN_HASH) {
        SecurityStatus::InvalidLength => {
            host.print_debug("Invalid pin length. Pin must be 6 digits.");
            return;
        }
        SecurityStatus::AuthFail => {
            host.print_debug("Nice try! Invalid pin!");
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
    const UUID_OFF: usize = 7;
    const HEADER_SIZE: usize = 23;

    if (pkt_len as usize) < HEADER_SIZE {
        host.print_error("Read packet too short");
        return;
    }

    host.print_debug("Checking PIN\n");
    if buf.len() < PIN_LENGTH {
        host.print_debug("Invalid pin length!");
        return;
    }
    let pin = &buf[0..PIN_LENGTH];
    match verify_pin(pin, &PIN_SALT, &PIN_HASH) {
        SecurityStatus::InvalidLength => {
            host.print_debug("Invalid pin length. Pin must be 6 digits.");
            return;
        }
        SecurityStatus::AuthFail => {
            host.print_debug("Nice try! Invalid pin!");
            return;
        }
        SecurityStatus::Success => host.print_debug("Pin successfully verified!"),
    };

    let _pin = &buf[PIN_OFF..PIN_OFF + 6];
    let slot = buf[SLOT_OFF];
    let uuid = Uuid::from_slice(&buf[UUID_OFF..UUID_OFF + UUID_SIZE]).unwrap();
    host.print_debug("Read: Parsed slot and UUID\n");

    let file = match fs.read_file(slot, flash) {
        Ok(f) => f,
        Err(FsError::EmptySlot) => {
            host.print_debug(&format!(20; "Slot {} is empty", slot).unwrap());
            return;
        }
        Err(FsError::InvalidSlot) => {
            host.print_debug(&format!(20; "Invalid slot: {}", slot).unwrap());
            return;
        }
        Err(_) => {
            host.print_debug("Something has gone wrong!");
            return;
        }
    };

    // Check that the file UUID matches the requested UUID
    if file.uuid != uuid {
        host.print_debug("UUID does not match requested file UUID!");
        return;
    }

    // // Get file metadata from FAT
    // let entry = match fs.get_file_metadata(slot) {
    //     Ok(e) => e,
    //     Err(_) => {
    //         host.print_error("Invalid file slot");
    //         return;
    //     }
    // };
    // host.print_debug("Read: Got FAT entry\n");
    //
    // // Verify the entry is valid
    // if entry.is_empty() {
    //     host.print_error("File slot empty");
    //     return;
    // }
    // host.print_debug("Read: Entry is not empty\n");
    //
    // // Verify UUID matches
    // if entry.uuid != uuid {
    //     host.print_error("UUID mismatch");
    //     return;
    // }
    // host.print_debug("Read: UUID verified\n");

    // Allocate buffer and read file from flash
    // let mut file_buf = [0u8; size_of::<ProtectedFile>()]; // +40 for metadata
    // if entry.length as usize > file_buf.len() {
    //     host.print_error("File too large");
    //     return;
    // }
    //
    // flash.read(entry.flash_addr, &mut file_buf[..entry.length as usize]);
    // host.print_debug("Read: File loaded from flash\n");
    //
    // // Extract the contents from the file structure
    // // Layout: in_use(4) + group_id(2) + name(32) + contents_len(2) + contents(...)
    // const CONTENTS_LEN_OFF: usize = 4 + 2 + MAX_NAME_SIZE; // 38
    // const METADATA_SIZE: usize = CONTENTS_LEN_OFF + 2; // 40
    // if (entry.length as usize) < METADATA_SIZE {
    //     host.print_error("Stored file metadata too short");
    //     return;
    // }
    // let contents_len =
    //     u16::from_le_bytes([file_buf[CONTENTS_LEN_OFF], file_buf[CONTENTS_LEN_OFF + 1]]) as usize;
    // host.print_debug("Read: Extracted contents length\n");
    //
    // if contents_len > MAX_CONTENTS_SIZE || METADATA_SIZE + contents_len > entry.length as usize {
    //     host.print_error("Invalid file contents length");
    //     return;
    // }
    // host.print_debug("Read: Contents length validated\n");
    //
    // // Send back payload in host-tools format: name(32) + contents
    // const NAME_OFF: usize = 4 + 2; // after in_use + group_id
    // let name = &file_buf[NAME_OFF..NAME_OFF + MAX_NAME_SIZE];
    // let contents = &file_buf[METADATA_SIZE..METADATA_SIZE + contents_len];
    // let file = fs.read_file(flash);
    let contents = match file.decrypt() {
        Ok(contents) => contents,
        Err(FileError::NoReadPermission) => {
            host.print_debug(
                &format!(
                    64; "HSM does not have permission to write files from group: {:#x}",
                    file.group_id
                )
                .unwrap(),
            );
            return;
        }
        Err(FileError::DecryptError) => {
            host.print_debug("Error while decrypting file!");
            return;
        }
        Err(_) => {
            host.print_debug("Something went wrong!");
            return;
        }
    };
    host.print_debug("Read: Contents (hex):");
    host.print_hex_debug(&contents);
    host.print_debug("Read: Contents debug sent\n");

    let mut resp = [0u8; MAX_NAME_SIZE + MAX_CONTENTS_SIZE];
    resp[..MAX_NAME_SIZE].copy_from_slice(&file.name);
    resp[MAX_NAME_SIZE..MAX_NAME_SIZE + contents.len()].copy_from_slice(&contents);

    let resp_len = MAX_NAME_SIZE + contents.len();
    let _ = host.write_packet(MsgType::Read, &resp[..resp_len]);
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
    let t0 = unsafe { core::ptr::read_volatile(SYST_CVR) };

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
            host.print_debug("Invalid pin length. Pin must be 6 digits.");
            return;
        }
        SecurityStatus::AuthFail => {
            host.print_debug("Nice try! Invalid pin!");
            return;
        }
        SecurityStatus::Success => host.print_debug("Pin successfully verified!"),
    };

    let _pin = &buf[PIN_OFF..PIN_OFF + 6];
    let slot = buf[SLOT_OFF];
    let group_id = u16::from_le_bytes([buf[GROUP_OFF], buf[GROUP_OFF + 1]]);
    let name_raw = &buf[NAME_OFF..NAME_OFF + MAX_NAME_SIZE];
    let name_len = name_raw
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(name_raw.len());
    let name = &name_raw[..name_len].as_array().unwrap();
    let uuid: Uuid = Uuid::from_slice(&buf[UUID_OFF..UUID_OFF + UUID_SIZE]).unwrap();
    let contents_len = u16::from_le_bytes([buf[CLEN_OFF], buf[CLEN_OFF + 1]]) as usize;

    // Validate contents_len against actual packet payload
    if contents_len > MAX_CONTENTS_SIZE || CONTENTS_OFF + contents_len > pkt_len as usize {
        host.print_error("Invalid contents length");
        return;
    }

    let contents: Vec<u8, MAX_CONTENTS_SIZE> =
        Vec::from_slice(&buf[CONTENTS_OFF..CONTENTS_OFF + contents_len]).unwrap();

    let file = match ProtectedFile::create(group_id, uuid, name, &contents) {
        Ok(f) => f,
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
        Err(FileError::BullshitError) => {
            host.print_error("Something stupid went wrong.");
            return;
        }
        Err(_) => {
            host.print_error("Something really bad happened.");
            return;
        }
    };

    let t1 = unsafe { core::ptr::read_volatile(SYST_CVR) };

    if let Err(_e) = fs.write_file(slot, &file, uuid, flash) {
        // host.print_debug("write_file failed:");
        // host.print_hex_debug(&[e as u8]);
        host.print_error("Flash write failed");
        return;
    }

    let t2 = unsafe { core::ptr::read_volatile(SYST_CVR) };

    // SysTick counts DOWN at 32 MHz. Delta ticks / 32 = microseconds.
    let create_us = (t0.wrapping_sub(t1) & 0x00FF_FFFF) / 32;
    let flash_us = (t1.wrapping_sub(t2) & 0x00FF_FFFF) / 32;
    host.print_debug("create_us:");
    host.print_hex_debug(&create_us.to_le_bytes());
    host.print_debug("flash_us:");
    host.print_hex_debug(&flash_us.to_le_bytes());
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
        host.print_debug("Invalid packet length!");
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
            host.print_debug("Invalid pin length. Pin must be 6 digits.");
            return;
        }
        SecurityStatus::AuthFail => {
            host.print_debug("Nice try! Invalid pin!");
            return;
        }
        SecurityStatus::Success => host.print_debug("Pin successfully verified!"),
    };

    // Build receive_request_t (41 bytes): slot(1) + group_permission_t[8] (5 bytes each)
    // global_permissions from secrets.h: {0x1234, r, !w, !recv}, {0x4321, r, w, recv}, rest zeroed
    let mut request_buf = [0u8; 41];
    request_buf[0] = read_slot;
    // permission[0]: group_id=0x1234, read=true, write=false, receive=false
    request_buf[1] = 0x34; // group_id LE low
    request_buf[2] = 0x12; // group_id LE high
    request_buf[3] = 1; // read
    request_buf[4] = 0; // write
    request_buf[5] = 0; // receive
    // permission[1]: group_id=0x4321, read=true, write=true, receive=true
    request_buf[6] = 0x21;
    request_buf[7] = 0x43;
    request_buf[8] = 1;
    request_buf[9] = 1;
    request_buf[10] = 1;
    // permissions[2..7] remain zeroed

    // Send request to neighbor
    let _ = uart1.write_packet(MsgType::Receive, &request_buf);

    // Read response: receive_response_t = uuid(16) + file_t(up to 8232)
    let (cmd, recv_len) = match uart1.read_packet(buf, 0xFFFF) {
        Ok(v) => v,
        Err(_) => {
            host.print_error("Receive: read from neighbor failed");
            return;
        }
    };

    // Parse challenge, send response

    if cmd != MsgType::Receive {
        host.print_error("Receive: opcode mismatch");
        return;
    }

    // Parse response: uuid = buf[0..16], file_t = buf[16..]
    let uuid = Uuid::from_slice(&buf[..UUID_SIZE]).unwrap();

    // Reconstruct File from raw bytes at buf[16..]
    let file_off = UUID_SIZE;
    let file_bytes = &buf[file_off..recv_len as usize];

    let file: ProtectedFile =
        unsafe { core::ptr::read_unaligned(file_bytes.as_ptr() as *const ProtectedFile) };

    // Add signature check

    // Write received file to local flash
    if let Err(_) = fs.write_file(write_slot, &file, uuid, flash) {
        host.print_error("Writing received file failed");
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
            host.print_debug("Invalid pin length. Pin must be 6 digits.");
            return;
        }
        SecurityStatus::AuthFail => {
            host.print_debug("Nice try! Invalid pin!");
            return;
        }
        SecurityStatus::Success => host.print_debug("Pin successfully verified!"),
    };

    // Send empty interrogate request to neighbor
    let _ = uart1.write_packet(MsgType::Interrogate, &[]);

    // Read list_response_t from neighbor (up to 284 bytes)
    let (cmd, recv_len) = match uart1.read_packet(buf, 0xFFFF) {
        Ok(v) => v,
        Err(_) => {
            host.print_error("Interrogate: read from neighbor failed");
            return;
        }
    };

    if cmd != MsgType::Interrogate {
        host.print_error("Interrogate: opcode mismatch");
        return;
    }

    // Forward the list response to host as-is
    let _ = host.write_packet(MsgType::Interrogate, &buf[..recv_len as usize]);
}

#[inline(never)]
fn cmd_listen(
    host: &mut HostUart,
    uart1: &mut HostUart,
    _pkt_len: u16,
    buf: &mut [u8],
    flash: &impl Flash,
    fs: &Filesystem,
) {
    // Receive a packet from neighboring HSM via UART1
    let mut uart_buf = [0u8; 41]; // sizeof(receive_request_t): slot(1) + permissions(5*8)
    let max_len = uart_buf.len() as u16;
    let (cmd, _read_len) = match uart1.read_packet(&mut uart_buf, max_len) {
        Ok(v) => v,
        Err(_) => {
            host.print_error("Listen: read from neighbor failed");
            return;
        }
    };

    match cmd {
        MsgType::Interrogate => {
            // Build file list response in buf:
            //   n_files(4 bytes u32 LE) + per-file entries (slot(1) + group_id(2) + name(32) = 35 each)
            const ENTRY_SIZE: usize = 1 + 2 + MAX_NAME_SIZE; // 35
            const HEADER_SIZE: usize = 4; // n_files u32
            const FILE_HDR_SIZE: usize = 4 + 2 + MAX_NAME_SIZE; // 38

            let mut nfiles: u32 = 0;
            let resp_off = FILE_HDR_SIZE; // scratch area for flash reads

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
            let slot = uart_buf[0]; // receive_request_t.slot

            // Read file from flash
            let entry = match fs.get_file_metadata(slot) {
                Ok(e) => e,
                Err(_) => {
                    host.print_error("Listen: invalid file slot");
                    return;
                }
            };
            if entry.is_empty() {
                host.print_error("Listen: file slot empty");
                return;
            }

            // Build receive_response_t in buf: uuid(16) + file_t(8232)
            // Copy UUID from FAT entry
            buf[..UUID_SIZE].copy_from_slice(&entry.uuid.to_bytes_le());

            // Read file_t from flash into buf after UUID
            let file_len = entry.length as usize;
            flash.read(entry.flash_addr, &mut buf[UUID_SIZE..UUID_SIZE + file_len]);

            let total_len = UUID_SIZE + file_len;
            let _ = uart1.write_packet(MsgType::Receive, &buf[..total_len]);
        }
        _ => {
            host.print_error("Listen: bad message type from neighbor");
            return;
        }
    }

    // Success — blank message to host
    let _ = host.write_packet(MsgType::Listen, &[]);
}
