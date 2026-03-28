use crate::platform::{uart_readbyte, uart_writebyte};
use crate::protocol::{MsgType, MSG_HEADER_SIZE, MSG_MAGIC};

#[repr(i32)]
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum MsgStatus {
    Ok = 0,
    BadPtr = 1,
    NoAck = 2,
    BadLen = 3,
    UartError = -1,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct MsgHeader {
    magic: u8,
    cmd: u8,
    len: u16,
}

fn read_bytes(uart_id: i32, buf: &mut [u8]) -> MsgStatus {
    for (i, item) in buf.iter_mut().enumerate() {
        if i % 256 == 0 && i != 0 {
            let _ = write_ack(uart_id);
        }
        let value = uart_readbyte(uart_id);
        if value < 0 {
            return MsgStatus::UartError;
        }
        *item = value as u8;
    }
    MsgStatus::Ok
}

fn read_header(uart_id: i32) -> MsgHeader {
    let mut magic = uart_readbyte(uart_id) as u8;
    while magic != MSG_MAGIC {
        magic = uart_readbyte(uart_id) as u8;
    }

    let cmd = uart_readbyte(uart_id) as u8;
    let mut len_bytes = [0u8; 2];
    let _ = read_bytes(uart_id, &mut len_bytes);
    let len = u16::from_le_bytes(len_bytes);

    MsgHeader { magic, cmd, len }
}

fn read_ack(uart_id: i32) -> MsgStatus {
    let header = read_header(uart_id);
    if header.cmd == MsgType::Ack as u8 {
        MsgStatus::Ok
    } else {
        MsgStatus::NoAck
    }
}

fn write_bytes(uart_id: i32, buf: &[u8], should_ack: bool) -> MsgStatus {
    for (i, b) in buf.iter().enumerate() {
        if i % 256 == 0 && i != 0 {
            if should_ack && read_ack(uart_id) != MsgStatus::Ok {
                return MsgStatus::NoAck;
            }
        }
        uart_writebyte(uart_id, *b);
    }
    MsgStatus::Ok
}

pub fn send_packet(uart_id: i32, typ: MsgType, payload: Option<&[u8]>) -> MsgStatus {
    let len = payload.map_or(0usize, |p| p.len());
    let header = MsgHeader {
        magic: MSG_MAGIC,
        cmd: typ as u8,
        len: len as u16,
    };

    let header_bytes = unsafe {
        core::slice::from_raw_parts((&header as *const MsgHeader) as *const u8, MSG_HEADER_SIZE)
    };
    let mut result = write_bytes(uart_id, header_bytes, false);
    if result != MsgStatus::Ok {
        return result;
    }

    if typ == MsgType::Ack {
        return result;
    }

    if typ != MsgType::Debug && read_ack(uart_id) != MsgStatus::Ok {
        return MsgStatus::NoAck;
    }

    if let Some(bytes) = payload {
        if !bytes.is_empty() {
            result = write_bytes(uart_id, bytes, typ != MsgType::Debug);
            if result != MsgStatus::Ok {
                return result;
            }
            if typ != MsgType::Debug && read_ack(uart_id) != MsgStatus::Ok {
                return MsgStatus::NoAck;
            }
        }
    }

    result
}

pub unsafe fn read_packet(
    uart_id: i32,
    cmd: &mut MsgType,
    buf: *mut u8,
    len: &mut u16,
) -> MsgStatus {
    let header = read_header(uart_id);
    *cmd = MsgType::from_u8(header.cmd);

    if *len != 0 && header.len > *len {
        *len = 0;
        return MsgStatus::BadLen;
    }

    *len = header.len;

    if header.cmd != MsgType::Ack as u8 {
        let _ = write_ack(uart_id);

        if header.len > 0 && !buf.is_null() {
            let slice = core::slice::from_raw_parts_mut(buf, header.len as usize);
            if read_bytes(uart_id, slice) != MsgStatus::Ok {
                return MsgStatus::NoAck;
            }
        }

        if header.len > 0 && write_ack(uart_id) != MsgStatus::Ok {
            return MsgStatus::NoAck;
        }
    }

    MsgStatus::Ok
}

pub fn write_ack(uart_id: i32) -> MsgStatus {
    send_packet(uart_id, MsgType::Ack, None)
}

pub fn print_error(msg: &[u8]) -> MsgStatus {
    send_packet(0, MsgType::Error, Some(msg))
}

pub fn print_debug(msg: &[u8]) -> MsgStatus {
    send_packet(0, MsgType::Debug, Some(msg))
}

#[no_mangle]
pub extern "C" fn write_packet_c(uart_id: i32, typ: i32, buf: *const u8, len: u16) -> i32 {
    let msg_type = MsgType::from_u8(typ as u8);
    let payload = if buf.is_null() || len == 0 {
        None
    } else {
        Some(unsafe { core::slice::from_raw_parts(buf, len as usize) })
    };

    send_packet(uart_id, msg_type, payload) as i32
}

#[no_mangle]
pub extern "C" fn write_packet(uart_id: i32, typ: i32, buf: *const u8, len: u16) -> i32 {
    write_packet_c(uart_id, typ, buf, len)
}
