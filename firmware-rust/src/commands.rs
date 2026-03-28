use core::mem::MaybeUninit;

use crate::bindings::{
    get_file_metadata, global_permissions, File, FilesystemEntry, GroupPermission, FILE_IN_USE,
    MAX_FILE_COUNT_U8, PERM_READ, PERM_WRITE, TRANSFER_INTERFACE,
};
use crate::filesystem;
use crate::host_messaging::{print_error, read_packet, send_packet, MsgStatus};
use crate::protocol::{
    MsgType, MAX_CONTENTS_SIZE, MAX_FILE_COUNT, MAX_NAME_SIZE, MAX_PERMS, PIN_LENGTH,
    UUID_SIZE,
};
use crate::security::{permission_ok, pin_ok};

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes.get(offset..offset + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn list_pkt_len(num_files: u32) -> usize {
    4 + (MAX_NAME_SIZE + 2 + 1) * (num_files as usize)
}

fn build_file_metadata(slot: u8, group_id: u16, name: &[u8; MAX_NAME_SIZE], out: &mut [u8]) {
    out[0] = slot;
    out[1..3].copy_from_slice(&group_id.to_le_bytes());
    out[3..3 + MAX_NAME_SIZE].copy_from_slice(name);
}

pub fn list(buf: &[u8]) -> i32 {
    if buf.len() < PIN_LENGTH || !pin_ok(&buf[..PIN_LENGTH]) {
        let _ = print_error(b"Invalid pin\n");
        return -1;
    }

    let mut temp_payload = [0u8; 4 + ((MAX_NAME_SIZE + 2 + 1) * MAX_FILE_COUNT)];
    let mut file_count = 0u32;

    for slot in 0..MAX_FILE_COUNT_U8 {
        if filesystem::slot_in_use(slot) {
            if let Some(file) = filesystem::read(slot) {
                let base = 4 + (file_count as usize) * (MAX_NAME_SIZE + 2 + 1);
                build_file_metadata(slot, file.group_id, &file.name, &mut temp_payload[base..base + (MAX_NAME_SIZE + 2 + 1)]);
                file_count += 1;
            }
        }
    }

    temp_payload[0..4].copy_from_slice(&file_count.to_le_bytes());
    let length = list_pkt_len(file_count);
    let _ = send_packet(0, MsgType::List, Some(&temp_payload[..length]));
    0
}

pub fn read(buf: &[u8]) -> i32 {
    if buf.len() < PIN_LENGTH + 1 {
        return -1;
    }

    if !pin_ok(&buf[..PIN_LENGTH]) {
        let _ = print_error(b"Invalid pin\n");
        return -1;
    }

    let slot = buf[PIN_LENGTH];
    let curr_file = match filesystem::read(slot) {
        Some(value) => value,
        None => {
            let _ = print_error(b"Failed to read file\n");
            return -1;
        }
    };

    if !permission_ok(curr_file.group_id, PERM_READ) {
        let _ = print_error(b"Invalid permission\n");
        return -1;
    }

    let mut response = [0u8; MAX_NAME_SIZE + MAX_CONTENTS_SIZE];
    response[..MAX_NAME_SIZE].copy_from_slice(&curr_file.name);

    let contents_len = curr_file.contents_len as usize;
    response[MAX_NAME_SIZE..MAX_NAME_SIZE + contents_len].copy_from_slice(&curr_file.contents[..contents_len]);

    let _ = send_packet(0, MsgType::Read, Some(&response[..MAX_NAME_SIZE + contents_len]));
    0
}

pub fn write(buf: &[u8]) -> i32 {
    let minimum = PIN_LENGTH + 1 + 2 + MAX_NAME_SIZE + UUID_SIZE + 2;
    if buf.len() < minimum {
        return -1;
    }

    if !pin_ok(&buf[..PIN_LENGTH]) {
        let _ = print_error(b"Invalid pin\n");
        return -1;
    }

    let slot = buf[PIN_LENGTH];
    let group_id = read_u16_le(buf, PIN_LENGTH + 1).unwrap_or(0);
    if !permission_ok(group_id, PERM_WRITE) {
        let _ = print_error(b"Invalid permission\n");
        return -1;
    }

    let name_start = PIN_LENGTH + 1 + 2;
    let uuid_start = name_start + MAX_NAME_SIZE;
    let len_start = uuid_start + UUID_SIZE;
    let contents_len = read_u16_le(buf, len_start).unwrap_or(0) as usize;
    let contents_start = len_start + 2;

    if contents_start + contents_len > buf.len() || contents_len > MAX_CONTENTS_SIZE {
        let _ = print_error(b"Invalid content length\n");
        return -1;
    }

    let mut file = File {
        in_use: FILE_IN_USE,
        group_id,
        name: [0; MAX_NAME_SIZE],
        contents_len: contents_len as u16,
        contents: [0; MAX_CONTENTS_SIZE],
    };

    file.name.copy_from_slice(&buf[name_start..name_start + MAX_NAME_SIZE]);
    file.contents[..contents_len].copy_from_slice(&buf[contents_start..contents_start + contents_len]);

    let mut uuid = [0u8; UUID_SIZE];
    uuid.copy_from_slice(&buf[uuid_start..uuid_start + UUID_SIZE]);

    if !filesystem::write(slot, &mut file, &uuid) {
        let _ = print_error(b"Error storing file\n");
        return -1;
    }

    let _ = send_packet(0, MsgType::Write, None);
    0
}

pub fn receive(buf: &[u8]) -> i32 {
    if buf.len() < PIN_LENGTH + 2 {
        return -1;
    }

    if !pin_ok(&buf[..PIN_LENGTH]) {
        let _ = print_error(b"Invalid pin\n");
        return -1;
    }

    let read_slot = buf[PIN_LENGTH];
    let write_slot = buf[PIN_LENGTH + 1];

    let mut request = [0u8; 1 + (MAX_PERMS * 5)];
    request[0] = read_slot;
    for (i, gp) in unsafe { global_permissions }.iter().enumerate() {
        let base = 1 + (i * 5);
        request[base..base + 2].copy_from_slice(&gp.group_id.to_le_bytes());
        request[base + 2] = gp.read as u8;
        request[base + 3] = gp.write as u8;
        request[base + 4] = gp.receive as u8;
    }

    let _ = send_packet(TRANSFER_INTERFACE, MsgType::Receive, Some(&request));

    let mut cmd = MsgType::Error;
    let mut recv_len: u16 = 0xffff;
    let mut recv_buf = [0u8; UUID_SIZE + core::mem::size_of::<File>()];
    let status = unsafe { read_packet(TRANSFER_INTERFACE, &mut cmd, recv_buf.as_mut_ptr(), &mut recv_len) };
    if status != MsgStatus::Ok || cmd != MsgType::Receive {
        let _ = print_error(b"Opcode mismatch\n");
        return -1;
    }

    if recv_len as usize  < UUID_SIZE {
        return -1;
    }

    let mut uuid = [0u8; UUID_SIZE];
    uuid.copy_from_slice(&recv_buf[..UUID_SIZE]);

    let file_bytes = &recv_buf[UUID_SIZE..(UUID_SIZE + core::mem::size_of::<File>())];
    let mut file = MaybeUninit::<File>::zeroed();
    unsafe {
        core::ptr::copy_nonoverlapping(
            file_bytes.as_ptr(),
            file.as_mut_ptr() as *mut u8,
            core::mem::size_of::<File>(),
        );
    }

    let mut file = unsafe { file.assume_init() };
    if !filesystem::write(write_slot, &mut file, &uuid) {
        let _ = print_error(b"Writing received file failed\n");
        return -1;
    }

    let _ = send_packet(0, MsgType::Receive, None);
    0
}

pub fn interrogate(buf: &[u8]) -> i32 {
    if buf.len() < PIN_LENGTH || !pin_ok(&buf[..PIN_LENGTH]) {
        let _ = print_error(b"Invalid pin\n");
        return -1;
    }

    let _ = send_packet(TRANSFER_INTERFACE, MsgType::Interrogate, None);

    let mut cmd = MsgType::Error;
    let mut recv_len: u16 = 0xffff;
    let mut recv_buf = [0u8; 4 + ((MAX_NAME_SIZE + 2 + 1) * MAX_FILE_COUNT)];
    let status = unsafe { read_packet(TRANSFER_INTERFACE, &mut cmd, recv_buf.as_mut_ptr(), &mut recv_len) };
    if status != MsgStatus::Ok || cmd != MsgType::Interrogate {
        let _ = print_error(b"Opcode mismatch\n");
        return -1;
    }

    let _ = send_packet(0, MsgType::Interrogate, Some(&recv_buf[..recv_len as usize]));
    0
}

pub fn listen() -> i32 {
    let mut cmd = MsgType::Error;
    let mut read_len: u16 = 0xffff;
    let mut uart_buf = [0u8; 64];

    let status = unsafe { read_packet(TRANSFER_INTERFACE, &mut cmd, uart_buf.as_mut_ptr(), &mut read_len) };
    if status != MsgStatus::Ok {
        return -1;
    }

    match cmd {
        MsgType::Interrogate => {
            let mut temp_payload = [0u8; 4 + ((MAX_NAME_SIZE + 2 + 1) * MAX_FILE_COUNT)];
            let mut file_count = 0u32;
            for slot in 0..MAX_FILE_COUNT_U8 {
                if filesystem::slot_in_use(slot) {
                    if let Some(file) = filesystem::read(slot) {
                        let base = 4 + (file_count as usize) * (MAX_NAME_SIZE + 2 + 1);
                        build_file_metadata(
                            slot,
                            file.group_id,
                            &file.name,
                            &mut temp_payload[base..base + (MAX_NAME_SIZE + 2 + 1)],
                        );
                        file_count += 1;
                    }
                }
            }
            temp_payload[0..4].copy_from_slice(&file_count.to_le_bytes());
            let length = list_pkt_len(file_count);
            let _ = send_packet(TRANSFER_INTERFACE, MsgType::Interrogate, Some(&temp_payload[..length]));
        }
        MsgType::Receive => {
            if read_len < 1 {
                return -1;
            }
            let slot = uart_buf[0];
            let file = match filesystem::read(slot) {
                Some(value) => value,
                None => {
                    let _ = print_error(b"Failed to read file\n");
                    return -1;
                }
            };

            let metadata_ptr = unsafe { get_file_metadata(slot) };
            if metadata_ptr.is_null() {
                let _ = print_error(b"Getting metadata failed\n");
                return -1;
            }
            let metadata: &FilesystemEntry = unsafe { &*metadata_ptr };

            let mut payload = [0u8; UUID_SIZE + core::mem::size_of::<File>()];
            payload[..UUID_SIZE].copy_from_slice(&metadata.uuid);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (&file as *const File) as *const u8,
                    payload[UUID_SIZE..].as_mut_ptr(),
                    core::mem::size_of::<File>(),
                );
            }

            let _ = send_packet(TRANSFER_INTERFACE, MsgType::Receive, Some(&payload));
        }
        _ => {
            let _ = print_error(b"Bad message type\n");
            return -1;
        }
    }

    let _ = send_packet(0, MsgType::Listen, None);
    0
}
