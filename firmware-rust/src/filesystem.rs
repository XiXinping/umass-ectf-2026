use core::mem::MaybeUninit;

use crate::bindings::{init_fs, is_slot_in_use, read_file, write_file, File};

pub fn init() {
    unsafe {
        let _ = init_fs();
    }
}

pub fn slot_in_use(slot: u8) -> bool {
    unsafe { is_slot_in_use(slot) }
}

pub fn read(slot: u8) -> Option<File> {
    let mut file = MaybeUninit::<File>::zeroed();
    let result = unsafe { read_file(slot, file.as_mut_ptr()) };
    if result < 0 {
        None
    } else {
        Some(unsafe { file.assume_init() })
    }
}

pub fn write(slot: u8, file: &mut File, uuid: &[u8; 16]) -> bool {
    unsafe { write_file(slot, file as *mut File, uuid.as_ptr()) >= 0 }
}
