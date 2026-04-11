#[allow(static_mut_refs)]
/// HSM secret material — generated at build time, initialised once at startup.

// Pull in everything build.rs wrote
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/secrets_generated.rs"
));

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;

// SAFETY: only written once during single-threaded init, read-only after
struct SyncWrapper(UnsafeCell<MaybeUninit<[GroupPermission; NUM_PERMS]>>);
unsafe impl Sync for SyncWrapper {}

static PERM_STORE: SyncWrapper = SyncWrapper(UnsafeCell::new(MaybeUninit::uninit()));

pub fn init() {
    unsafe { (*PERM_STORE.0.get()).write(init_permissions()) };
}

pub fn permissions() -> &'static [GroupPermission; NUM_PERMS] {
    unsafe { (*PERM_STORE.0.get()).assume_init_ref() }
}
