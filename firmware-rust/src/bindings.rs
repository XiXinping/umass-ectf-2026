use crate::protocol::{MAX_CONTENTS_SIZE, MAX_FILE_COUNT, MAX_NAME_SIZE, MAX_PERMS, UUID_SIZE};

#[repr(C)]
#[derive(Copy, Clone)]
pub struct GroupPermission {
    pub group_id: u16,
    pub read: bool,
    pub write: bool,
    pub receive: bool,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct File {
    pub in_use: u32,
    pub group_id: u16,
    pub name: [u8; MAX_NAME_SIZE],
    pub contents_len: u16,
    pub contents: [u8; MAX_CONTENTS_SIZE],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FilesystemEntry {
    pub uuid: [u8; UUID_SIZE],
    pub length: u16,
    pub padding: u16,
    pub flash_addr: u32,
}

extern "C" {
    pub fn init_fs() -> i32;
    pub fn is_slot_in_use(slot: u8) -> bool;
    pub fn create_file(dest: *mut File, group_id: u16, name: *const u8, contents_len: u16, contents: *const u8) -> i32;
    pub fn write_file(slot: u8, src: *mut File, uuid: *const u8) -> i32;
    pub fn read_file(slot: u8, dest: *mut File) -> i32;
    pub fn get_file_metadata(slot: u8) -> *const FilesystemEntry;

    pub fn check_pin(pin: *const u8) -> bool;
    pub fn validate_permission(group_id: u16, perm: u8) -> bool;

    pub static global_permissions: [GroupPermission; MAX_PERMS];
}

pub const FILE_IN_USE: u32 = 0xdeadbeef;
pub const PERM_READ: u8 = b'R';
pub const PERM_WRITE: u8 = b'W';
pub const PERM_RECEIVE: u8 = b'C';
pub const CONTROL_INTERFACE: i32 = 0;
pub const TRANSFER_INTERFACE: i32 = 1;
pub const MAX_FILE_COUNT_U8: u8 = MAX_FILE_COUNT as u8;
