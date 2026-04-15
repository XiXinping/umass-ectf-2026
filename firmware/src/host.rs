//! eCTF host messaging implementation.
//! Follows the protocol defined in the eCTF Host Interface specification:
//!   ```
//!   [MAGIC 1B] [OPCODE 1B] [LENGTH 2B] [BODY ...]
//!   ```
//!
//! After the sender transmits the 4-byte header, the receiver sends an ACK.
//! The body is then sent in 256-byte chunks, each followed by an ACK from the
//! receiver. Debug messages are never ACKed.

use embassy_mspm0::mode::Blocking;
use embassy_mspm0::uart::Uart;

/// Magic byte that begins every message header.
pub const MSG_MAGIC: u8 = b'%';

/// Message opcodes as defined by the eCTF Host Interface specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgType {
    /// List all files on the HSM.
    List = b'L',
    /// Read a file from the HSM.
    Read = b'R',
    /// Write a file to the HSM.
    Write = b'W',
    /// Receive a file from a neighbor HSM.
    Receive = b'C',
    /// Interrogate a neighbor HSM for its file list.
    Interrogate = b'I',
    /// Prepare HSM to receive on UART1 (Interrogate or Receive).
    Listen = b'N',
    /// Acknowledge receipt of data.
    Ack = b'A',
    /// Debug output (never ACKed, ignored by test framework).
    Debug = b'D',
    /// Report an error to the host (causes host tool to exit).
    Error = b'E',
}

impl MsgType {
    /// Parse a raw byte into a known message type, if valid.
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

/// Outcome of a send or receive operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgStatus {
    Ok,
    BadPtr,
    NoAck,
    BadLen,
    UartError(i32),
}

impl core::fmt::Display for MsgStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MsgStatus::Ok => write!(f, "Message status ok"),
            MsgStatus::BadPtr => write!(f, "Bad pointer"),
            MsgStatus::NoAck => write!(f, "No ACK"),
            MsgStatus::BadLen => write!(f, "Bad length"),
            MsgStatus::UartError(err_code) => write!(f, "UART Error: {}", err_code),
        }
    }
}

/// Wire-format message header (4 bytes): magic (1) + opcode (1) + length (2)
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct MsgHeader {
    pub magic: u8,
    pub cmd: u8,
    pub len: u16,
}

/// Size of the packed header in bytes.
pub const MSG_HEADER_SIZE: usize = 4;

/// Number of payload bytes between ACK checkpoints.
const ACK_INTERVAL: usize = 256;

/// Wrapper around an Embassy blocking UART that speaks the eCTF host protocol.
pub struct HostUart<'d> {
    uart: Uart<'d, Blocking>,
}

impl<'d> HostUart<'d> {
    pub fn new(uart: Uart<'d, Blocking>) -> Self {
        Self { uart }
    }

    // ── Byte-level I/O ──────────────────────────────────────────────

    fn read_byte(&mut self) -> Result<u8, i32> {
        let mut buf = [0u8; 1];
        self.uart.blocking_read(&mut buf).map_err(|_| -1)?;
        Ok(buf[0])
    }

    fn write_byte(&mut self, b: u8) {
        let _ = self.uart.blocking_write(&[b]);
    }

    fn write_block(&mut self, block: &[u8]) {
        let _ = self.uart.blocking_write(block);
    }

    // ── Chunked I/O with ACK flow control ───────────────────────────

    /// Read `len` bytes from UART into `buf`, sending an ACK every 256 bytes.
    fn read_bytes(&mut self, buf: &mut [u8], len: u16) -> MsgStatus {
        for i in 0..len as usize {
            if i % ACK_INTERVAL == 0 && i != 0 {
                let _ = self.write_ack();
            }
            match self.read_byte() {
                Ok(b) => buf[i] = b,
                Err(e) => return MsgStatus::UartError(e),
            }
        }
        MsgStatus::Ok
    }

    /// Read a message header, discarding bytes until the magic byte is found.
    fn read_header(&mut self) -> MsgHeader {
        // Synchronise on the magic byte.
        loop {
            match self.read_byte() {
                Ok(MSG_MAGIC) => break,
                _ => continue,
            }
        }

        let cmd = self.read_byte().unwrap_or(0);

        let mut len_buf = [0u8; 2];
        let _ = self.read_bytes(&mut len_buf, 2);
        let len = u16::from_le_bytes(len_buf);

        MsgHeader { magic: MSG_MAGIC, cmd, len }
    }

    /// Block until an ACK header arrives; return `NoAck` if anything else appears.
    fn read_ack(&mut self) -> MsgStatus {
        let hdr = self.read_header();
        if hdr.cmd == MsgType::Ack as u8 {
            MsgStatus::Ok
        } else {
            MsgStatus::NoAck
        }
    }

    /// Write raw bytes from one or more slices, optionally expecting an ACK
    /// every 256 bytes.
    ///
    /// The slices in `chunks` are treated as a single contiguous stream;
    /// `total_len` caps the number of bytes actually sent.
    pub fn write_bytes_raw(
        &mut self,
        chunks: &[&[u8]],
        total_len: u16,
        should_ack: bool,
    ) -> MsgStatus {
        let limit = total_len as usize;
        let mut bytes_written: usize = 0;

        for chunk in chunks.iter() {
            let mut offset = 0;
            while offset < chunk.len() && bytes_written < limit {
                // Determine batch size: go up to the next ACK boundary,
                // or to the end of this chunk / total, whichever is smallest.
                let next_ack = if should_ack {
                    ACK_INTERVAL - (bytes_written % ACK_INTERVAL)
                } else {
                    limit - bytes_written
                };

                let batch = (chunk.len() - offset)
                    .min(limit - bytes_written)
                    .min(next_ack);

                self.write_block(&chunk[offset..offset + batch]);
                offset += batch;
                bytes_written += batch;

                // Wait for ACK at every 256-byte boundary (not at the very end).
                if should_ack
                    && bytes_written > 0
                    && bytes_written.is_multiple_of(ACK_INTERVAL)
                    && bytes_written < limit
                    && self.read_ack() != MsgStatus::Ok
                {
                    return MsgStatus::NoAck;
                }
            }
        }

        MsgStatus::Ok
    }

    // ── Packet-level API ────────────────────────────────────────────

    /// Send a bare ACK message (header only, no payload, no response expected).
    pub fn write_ack(&mut self) -> MsgStatus {
        self.write_packet(MsgType::Ack, &[]);
        MsgStatus::Ok
    }

    /// Send a complete packet built from multiple body slices.
    ///
    /// Protocol sequence (non-debug, non-ACK):
    ///   1. Send 4-byte header
    ///   2. Wait for header ACK
    ///   3. Send body in 256-byte chunks, ACK after each
    ///   4. Wait for final ACK
    pub fn write_packet_chunks(&mut self, msg_type: MsgType, body_chunks: &[&[u8]]) -> MsgStatus {
        let total_len: u16 = body_chunks.iter().map(|c| c.len() as u16).sum();

        // Transmit header.
        let hdr = MsgHeader {
            magic: MSG_MAGIC,
            cmd: msg_type as u8,
            len: total_len,
        };
        let hdr_bytes = unsafe {
            core::slice::from_raw_parts(&hdr as *const MsgHeader as *const u8, MSG_HEADER_SIZE)
        };
        let result = self.write_bytes_raw(&[hdr_bytes], MSG_HEADER_SIZE as u16, false);
        if result != MsgStatus::Ok {
            return result;
        }

        // ACK messages need no further handshake.
        if msg_type == MsgType::Ack {
            return MsgStatus::Ok;
        }

        // Wait for the receiver to ACK the header (debug is exempt).
        if msg_type != MsgType::Debug && self.read_ack() != MsgStatus::Ok {
            return MsgStatus::NoAck;
        }

        // Transmit body with per-chunk ACK flow control (debug is exempt).
        if total_len > 0 {
            let result =
                self.write_bytes_raw(body_chunks, total_len, msg_type != MsgType::Debug);
            if result != MsgStatus::Ok {
                return result;
            }
            if msg_type != MsgType::Debug && self.read_ack() != MsgStatus::Ok {
                return MsgStatus::NoAck;
            }
        }

        MsgStatus::Ok
    }

    /// Send a complete packet with a single contiguous body slice.
    pub fn write_packet(&mut self, msg_type: MsgType, body: &[u8]) -> MsgStatus {
        self.write_packet_chunks(msg_type, &[body])
    }

    /// Read a complete packet from UART.
    ///
    /// Returns `(message_type, body_length)`. The body is written into `buf`.
    /// `max_len` caps the accepted body size; pass 0 to accept up to `buf.len()`.
    pub fn read_packet(
        &mut self,
        buf: &mut [u8],
        max_len: u16,
    ) -> Result<(MsgType, u16), MsgStatus> {
        let header = self.read_header();

        let cmd = MsgType::from_byte(header.cmd).ok_or(MsgStatus::BadLen)?;
        let len = header.len;

        if max_len != 0 && len > max_len {
            return Err(MsgStatus::BadLen);
        }

        if cmd != MsgType::Ack {
            // ACK the header so the sender begins transmitting the body.
            let _ = self.write_ack();

            if len > 0 && !buf.is_empty() {
                if self.read_bytes(buf, len) != MsgStatus::Ok {
                    return Err(MsgStatus::NoAck);
                }
            }

            // ACK receipt of the final body chunk.
            if len > 0 {
                let _ = self.write_ack();
            }
        }

        Ok((cmd, len))
    }

    // ── Hex-encoded output ──────────────────────────────────────────

    /// Send `data` as hex-encoded ASCII (2 chars per byte).
    ///
    /// The header's length field is set to `data.len() * 2`. ACK checkpoints
    /// occur every 128 source bytes (256 hex chars).
    pub fn write_hex(&mut self, msg_type: MsgType, data: &[u8]) -> MsgStatus {
        let hex_len = (data.len() * 2) as u16;

        let hdr = MsgHeader {
            magic: MSG_MAGIC,
            cmd: msg_type as u8,
            len: hex_len,
        };
        let hdr_bytes = unsafe {
            core::slice::from_raw_parts(&hdr as *const MsgHeader as *const u8, MSG_HEADER_SIZE)
        };
        let _ = self.write_bytes_raw(&[hdr_bytes], MSG_HEADER_SIZE as u16, false);

        if msg_type != MsgType::Debug && self.read_ack() != MsgStatus::Ok {
            return MsgStatus::NoAck;
        }

        for (i, &byte) in data.iter().enumerate() {
            // ACK every 128 source bytes (= 256 hex chars on the wire).
            if i % 128 == 0 && i != 0 {
                if msg_type != MsgType::Debug && self.read_ack() != MsgStatus::Ok {
                    return MsgStatus::NoAck;
                }
            }
            self.write_byte(HEX_TABLE[(byte >> 4) as usize]);
            self.write_byte(HEX_TABLE[(byte & 0x0F) as usize]);
        }

        MsgStatus::Ok
    }

    // ── Convenience helpers ─────────────────────────────────────────

    /// Send an Error message to the host (causes the host tool to exit).
    pub fn print_error(&mut self, msg: &str) {
        let _ = self.write_packet(MsgType::Error, msg.as_bytes());
    }

    /// Send a Debug message to the host (ignored by the test framework).
    pub fn print_debug(&mut self, msg: &str) {
        let _ = self.write_packet(MsgType::Debug, msg.as_bytes());
    }

    /// Send raw bytes as hex-encoded debug output.
    pub fn print_hex_debug(&mut self, data: &[u8]) {
        let _ = self.write_hex(MsgType::Debug, data);
    }
}

/// Nibble-to-ASCII lookup table for hex encoding.
const HEX_TABLE: [u8; 16] = *b"0123456789abcdef";