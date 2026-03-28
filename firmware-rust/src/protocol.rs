#[repr(u8)]
#[derive(Copy, Clone, Eq, PartialEq)]
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
    pub fn from_u8(value: u8) -> Self {
        match value {
            b'L' => Self::List,
            b'R' => Self::Read,
            b'W' => Self::Write,
            b'C' => Self::Receive,
            b'I' => Self::Interrogate,
            b'N' => Self::Listen,
            b'A' => Self::Ack,
            b'D' => Self::Debug,
            _ => Self::Error,
        }
    }
}

pub const MSG_MAGIC: u8 = b'%';
pub const CMD_TYPE_LEN: usize = 1;
pub const CMD_LEN_LEN: usize = 2;
pub const MSG_HEADER_SIZE: usize = 1 + CMD_TYPE_LEN + CMD_LEN_LEN;

pub const MAX_FILE_COUNT: usize = 8;
pub const MAX_NAME_SIZE: usize = 32;
pub const MAX_CONTENTS_SIZE: usize = 8192;
pub const MAX_PERMS: usize = 8;
pub const UUID_SIZE: usize = 16;
pub const PIN_LENGTH: usize = 6;

pub const MAX_MSG_SIZE: usize = PIN_LENGTH
    + 1
    + 2
    + MAX_NAME_SIZE
    + UUID_SIZE
    + 2
    + MAX_CONTENTS_SIZE;
