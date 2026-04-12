// HSM secret material — generated at build time, initialised once at startup.

// Pull in everything build.rs wrote
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/secrets_generated.rs"
));

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;

// SAFETY: only written once during single-threaded init, read-only after
struct SyncWrapper(UnsafeCell<MaybeUninit<[WriteKeyPair; NUM_PERMS]>>);
unsafe impl Sync for SyncWrapper {}

static WRITE_PERM_STORE: SyncWrapper = SyncWrapper(UnsafeCell::new(MaybeUninit::uninit()));

pub fn init() {
    unsafe { (*WRITE_PERM_STORE.0.get()).write(init_write_keys()) };
}

pub fn write_permissions() -> &'static [WriteKeyPair; NUM_PERMS] {
    unsafe { (*WRITE_PERM_STORE.0.get()).assume_init_ref() }
}
