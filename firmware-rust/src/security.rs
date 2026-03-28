use crate::bindings::{check_pin, validate_permission};

pub fn pin_ok(pin: &[u8]) -> bool {
    if pin.len() < 6 {
        return false;
    }
    unsafe { check_pin(pin.as_ptr()) }
}

pub fn permission_ok(group_id: u16, perm: u8) -> bool {
    unsafe { validate_permission(group_id, perm) }
}
