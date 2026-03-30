#![no_std]
#![no_main]

use defmt_rtt as _;

#[cfg(test)]
#[embedded_test::tests]
mod pin_tests {
    use core::{assert, matches};
    use ectf_2026::authentication;
    use ectf_2026::authentication::SecurityStatus;
    use hex_literal::hex;

    #[test]
    fn test_verify_pin_valid() {
        let pin: &[u8; 6] = b"abcdef";
        const SALT: [u8; 16] = hex!("58df58cb1d011f38e7e9051894bf1580");
        const HASH: [u8; 32] =
            hex!("7b53501b32fdcef73e2d50a785cbff6d108ba2db773d8b82f32023333c36be66");

        let result = authentication::verify_pin(pin, &SALT, &HASH);
        assert!(matches!(result, SecurityStatus::Success));
    }

    #[test]
    fn test_verify_pin_invalid_pin_length() {
        let pin: &[u8; 3] = b"abc";

        const SALT: [u8; 16] = hex!("58df58cb1d011f38e7e9051894bf1580");
        const HASH: [u8; 32] =
            hex!("7b53501b32fdcef73e2d50a785cbff6d108ba2db773d8b82f32023333c36be66");

        let result = authentication::verify_pin(pin, &SALT, &HASH);
        assert!(matches!(result, SecurityStatus::InvalidLength));
    }

    #[test]
    fn test_verify_pin_invalid_pin() {
        let pin: &[u8; 6] = b"deadbe";
        const SALT: [u8; 16] = hex!("58df58cb1d011f38e7e9051894bf1580");
        const HASH: [u8; 32] =
            hex!("7b53501b32fdcef73e2d50a785cbff6d108ba2db773d8b82f32023333c36be66");

        let result = authentication::verify_pin(pin, &SALT, &HASH);
        assert!(matches!(result, SecurityStatus::AuthFail));
    }

    #[test]
    fn test_verify_pin_invalid_hash() {
        let pin: &[u8; 6] = b"456789";
        const SALT: [u8; 16] = hex!("58df58cb1d011f38e7e9051894bf1581");

        const HASH: [u8; 32] =
            hex!("7b53501b32fdcef73e2d50a785cbff6d108ba2db773d8b82f32023333c36be67");

        let result = authentication::verify_pin(pin, &SALT, &HASH);
        assert!(matches!(result, SecurityStatus::AuthFail));
    }

    #[test]
    fn test_verify_pin_invalid_salt() {
        let pin: &[u8; 6] = b"abc123";
        const SALT: [u8; 16] = hex!("58df58cb1d011f38e7e9051894bf1581");

        const HASH: [u8; 32] =
            hex!("7b53501b32fdcef73e2d50a785cbff6d108ba2db773d8b82f32023333c36be66");

        let result = authentication::verify_pin(pin, &SALT, &HASH);
        assert!(matches!(result, SecurityStatus::AuthFail));
    }

    #[test]
    fn test_verify_empty_pin() {
        let pin: &[u8; 0] = b"";
        const SALT: [u8; 16] = hex!("58df58cb1d011f38e7e9051894bf1580");

        const HASH: [u8; 32] =
            hex!("7b53501b32fdcef73e2d50a785cbff6d108ba2db773d8b82f32023333c36be66");

        let result = authentication::verify_pin(pin, &SALT, &HASH);
        assert!(matches!(result, SecurityStatus::InvalidLength));
    }

    #[test]
    fn test_verify_pin_timing_valid() {
        let pin: &[u8; 6] = b"abc123";
        const SALT: [u8; 16] = hex!("58df58cb1d011f38e7e9051894bf1580");
        const HASH: [u8; 32] =
            hex!("7b53501b32fdcef73e2d50a785cbff6d108ba2db773d8b82f32023333c36be66");

        // let start = Instant::now();

        authentication::verify_pin(pin, &SALT, &HASH);
        // let end = Instant::now();
        // let duration = end - start;
        // println!("Took {} ms", duration.as_millis());
        // assert!(duration > Duration::from_secs(3) && duration < Duration::from_secs(5));
    }
}
