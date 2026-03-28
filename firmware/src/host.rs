//! Host messaging protocol over UART
//!
//! Implements the eCTF packet protocol:
//!   [Magic '%'] [Command byte] [Length u16] [Payload...]
//!
//! Flow control: ACK expected every 256 bytes for non-debug messages.

use embassy_mspm0::mode::Blocking;
use embassy_mspm0::uart::Uart;

/// Magic byte that starts every message header
pub const MSG_MAGIC: u8 = b'%';

/// Message types matching the C enum `msg_type_t`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgType {
    List = b'L',
    Read = b'R',
    Write = b'W',
    Receive = b'C',
    Interrogate = b'I',
    Listen = b'N',
    Ack = b'A',
    Debug = b'D',
    Error = b'E',
}

impl MsgType {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            b'L' => Some(Self::List),
            b'R' => Some(Self::Read),
            b'W' => Some(Self::Write),
            b'C' => Some(Self::Receive),
            b'I' => Some(Self::Interrogate),
            b'N' => Some(Self::Listen),
            b'A' => Some(Self::Ack),
            b'D' => Some(Self::Debug),
            b'E' => Some(Self::Error),
            _ => None,
        }
    }
}

/// Message status codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgStatus {
    Ok,
    BadPtr,
    NoAck,
    BadLen,
    UartError(i32),
}

/// Packed message header: magic (1) + cmd (1) + len (2) = 4 bytes
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct MsgHeader {
    pub magic: u8,
    pub cmd: u8,
    pub len: u16,
}

pub const MSG_HEADER_SIZE: usize = 4;

/// Newtype wrapper around embassy's `Uart` for the eCTF host protocol.
pub struct HostUart<'d> {
    uart: Uart<'d, Blocking>,
}

impl<'d> HostUart<'d> {
    pub fn new(uart: Uart<'d, Blocking>) -> Self {
        Self { uart }
    }

    fn read_byte(&mut self) -> Result<u8, i32> {
        let mut buf = [0u8; 1];
        self.uart.blocking_read(&mut buf).map_err(|_| -1)?;
        Ok(buf[0])
    }

    fn write_byte(&mut self, b: u8) {
        let _ = self.uart.blocking_write(&[b]);
    }

    /// Read `len` bytes from UART, sending ACK every 256 bytes.
    fn read_bytes(&mut self, buf: &mut [u8], len: u16) -> MsgStatus {
        for i in 0..len as usize {
            if i % 256 == 0 && i != 0 {
                let _ = self.write_ack();
            }
            match self.read_byte() {
                Ok(b) => buf[i] = b,
                Err(e) => return MsgStatus::UartError(e),
            }
        }
        MsgStatus::Ok
    }

    /// Read a message header, skipping bytes until magic '%' is found.
    fn read_header(&mut self) -> MsgHeader {
        let mut hdr = MsgHeader::default();

        // Spin until we see the magic byte
        loop {
            match self.read_byte() {
                Ok(b) if b == MSG_MAGIC => break,
                Ok(_) => continue,
                Err(_) => continue,
            }
        }
        hdr.magic = MSG_MAGIC;
        hdr.cmd = self.read_byte().unwrap_or(0);

        // Read 2-byte length (little-endian)
        let mut len_buf = [0u8; 2];
        let _ = self.read_bytes(&mut len_buf, 2);
        hdr.len = u16::from_le_bytes(len_buf);

        hdr
    }

    /// Wait for an ACK from the remote side.
    fn read_ack(&mut self) -> MsgStatus {
        let hdr = self.read_header();
        if hdr.cmd == MsgType::Ack as u8 {
            MsgStatus::Ok
        } else {
            MsgStatus::NoAck
        }
    }

    /// Write raw bytes to UART, expecting ACK every 256 bytes if `should_ack`.
    fn write_bytes_raw(&mut self, buf: &[u8], len: u16, should_ack: bool) -> MsgStatus {
        for i in 0..len as usize {
            if i % 256 == 0 && i != 0 {
                if should_ack && self.read_ack() != MsgStatus::Ok {
                    return MsgStatus::NoAck;
                }
            }
            self.write_byte(buf[i]);
        }
        MsgStatus::Ok
    }

    /// Send an ACK message (header only, no payload, no response expected).
    pub fn write_ack(&mut self) -> MsgStatus {
        self.write_packet(MsgType::Ack, &[])
    }

    /// Send a complete packet.
    ///
    /// Protocol:
    /// 1. Send header
    /// 2. For non-ACK, non-DEBUG: wait for ACK
    /// 3. Send payload (with ACK every 256 bytes for non-DEBUG)
    /// 4. Wait for final ACK (non-DEBUG)
    pub fn write_packet(&mut self, msg_type: MsgType, data: &[u8]) -> MsgStatus {
        let len = data.len() as u16;

        // Build and send header
        let hdr = MsgHeader {
            magic: MSG_MAGIC,
            cmd: msg_type as u8,
            len,
        };
        let hdr_bytes = unsafe {
            core::slice::from_raw_parts(&hdr as *const MsgHeader as *const u8, MSG_HEADER_SIZE)
        };
        let result = self.write_bytes_raw(hdr_bytes, MSG_HEADER_SIZE as u16, false);
        if result != MsgStatus::Ok {
            return result;
        }

        // ACKs don't need a response
        if msg_type == MsgType::Ack {
            return MsgStatus::Ok;
        }

        // Wait for header ACK (not needed for debug messages)
        if msg_type != MsgType::Debug && self.read_ack() != MsgStatus::Ok {
            return MsgStatus::NoAck;
        }

        // Send payload if present
        if len > 0 {
            let result = self.write_bytes_raw(data, len, msg_type != MsgType::Debug);
            if result != MsgStatus::Ok {
                return result;
            }
            // Final ACK for the last block
            if msg_type != MsgType::Debug && self.read_ack() != MsgStatus::Ok {
                return MsgStatus::NoAck;
            }
        }

        MsgStatus::Ok
    }

    /// Read a complete packet from UART.
    ///
    /// Returns (message_type, bytes_read).
    /// `buf` will contain the payload.
    /// `max_len` limits how many bytes we accept; pass 0 for unlimited (up to buf size).
    pub fn read_packet(
        &mut self,
        buf: &mut [u8],
        max_len: u16,
    ) -> Result<(MsgType, u16), MsgStatus> {
        let header = self.read_header();

        let cmd = MsgType::from_byte(header.cmd).ok_or(MsgStatus::BadLen)?;
        let len = header.len;

        // Check length limit (if max_len != 0 and payload exceeds it)
        if max_len != 0 && len > max_len {
            return Err(MsgStatus::BadLen);
        }

        if cmd != MsgType::Ack {
            // ACK the header
            let _ = self.write_ack();

            // Read payload
            if len > 0 && !buf.is_empty() {
                if self.read_bytes(buf, len) != MsgStatus::Ok {
                    return Err(MsgStatus::NoAck);
                }
            }

            // ACK the final block
            if len > 0 {
                let _ = self.write_ack();
            }
        }

        Ok((cmd, len))
    }

    /// Write data as hex-encoded bytes (2 ASCII chars per byte).
    pub fn write_hex(&mut self, msg_type: MsgType, data: &[u8]) -> MsgStatus {
        let hex_len = (data.len() * 2) as u16;

        // Send header with doubled length
        let hdr = MsgHeader {
            magic: MSG_MAGIC,
            cmd: msg_type as u8,
            len: hex_len,
        };
        let hdr_bytes = unsafe {
            core::slice::from_raw_parts(&hdr as *const MsgHeader as *const u8, MSG_HEADER_SIZE)
        };
        let _ = self.write_bytes_raw(hdr_bytes, MSG_HEADER_SIZE as u16, false);

        if msg_type != MsgType::Debug && self.read_ack() != MsgStatus::Ok {
            return MsgStatus::NoAck;
        }

        // Send each byte as 2 hex ASCII characters
        for (i, &byte) in data.iter().enumerate() {
            if i % 128 == 0 && i != 0 {
                if msg_type != MsgType::Debug && self.read_ack() != MsgStatus::Ok {
                    return MsgStatus::NoAck;
                }
            }
            let hi = HEX_TABLE[(byte >> 4) as usize];
            let lo = HEX_TABLE[(byte & 0x0f) as usize];
            self.write_byte(hi);
            self.write_byte(lo);
        }

        MsgStatus::Ok
    }

    /// Send an error message to the host.
    pub fn print_error(&mut self, msg: &str) {
        let _ = self.write_packet(MsgType::Error, msg.as_bytes());
    }

    /// Send a debug message to the host.
    pub fn print_debug(&mut self, msg: &str) {
        let _ = self.write_packet(MsgType::Debug, msg.as_bytes());
    }

    /// Send debug output as hex.
    pub fn print_hex_debug(&mut self, data: &[u8]) {
        let _ = self.write_hex(MsgType::Debug, data);
    }
}

const HEX_TABLE: [u8; 16] = *b"0123456789abcdef";
