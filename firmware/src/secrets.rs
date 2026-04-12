// HSM secret material — generated at build time, initialised once at startup.

// Pull in everything build.rs wrote
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/secrets_generated.rs"
));
