use crate::authentication;
use hex_literal::hex;

#[cfg(test)]
#[embedded_test::tests]
mod tests {
    #[test]
    fn test_verify_pin_valid() {
        let pin: &[u8; 6] = b"123456";
        let salt: &[u8; 16] = &hex!("891d3e40af01bd22c3d4e5f67890abcd");
        let hash: &[u8; 32] =
            &hex!("9cd794df1ac380ae42117aebcddb148d261871d8aa06b8f87c92108230d6a388");

        let result = authentication::verify_pin(pin, salt, hash);
        assert!(matches!(result, authenetication::SecurityStatus::Success));
    }

    #[test]
    fn test_verify_pin_invalid_pin_length() {
        let pin: &[u8; 3] = b"123";
        let salt: &[u8; 16] = &hex!("891d3e40af01bd22c3d4e5f67890abcd");
        let hash: &[u8; 32] =
            &hex!("9cd794df1ac380ae42117aebcddb148d261871d8aa06b8f87c92108230d6a388");

        let result = authentication::verify_pin(pin, salt, hash);
        assert!(matches!(
            result,
            authenetication::SecurityStatus::InvalidLength
        ));
    }

    #[test]
    fn test_verify_pin_invalid_pin() {
        let pin: &[u8; 6] = b"456789";
        let salt: &[u8; 16] = &hex!("891d3e40af01bd22c3d4e5f67890abcd");
        let hash: &[u8; 32] =
            &hex!("9cd794df1ac380ae42117aebcddb148d261871d8aa06b8f87c92108230d6a388");

        let result = authentication::verify_pin(pin, salt, hash);
        assert!(matches!(result, authenetication::SecurityStatus::AuthFail));
    }

    #[test]
    fn test_verify_pin_invalid_hash() {
        let pin: &[u8; 6] = b"456789";
        let salt: &[u8; 16] = &hex!("891d3e40af01bd22c3d4e5f67890abcd");
        let hash: &[u8; 32] =
            &hex!("9cd794df1ac380ae42117aebcddb148d261871d8aa06b8f87c92108230d6a389");

        let result = authentication::verify_pin(pin, salt, hash);
        assert!(matches!(result, authenetication::SecurityStatus::AuthFail));
    }

    #[test]
    fn test_verify_pin_invalid_salt() {
        let pin: &[u8; 6] = b"123456";
        let salt: &[u8; 16] = &hex!("891d3e40af01bd22c3d4e5f67890abce");
        let hash: &[u8; 32] =
            &hex!("9cd794df1ac380ae42117aebcddb148d261871d8aa06b8f87c92108230d6a388");

        let result = authentication::verify_pin(pin, salt, hash);
        assert!(matches!(result, authenetication::SecurityStatus::AuthFail));
    }

    #[test]
    fn test_verify_empty_pin() {
        let pin: &[u8; 0] = b"";
        let salt: &[u8; 16] = &hex!("891d3e40af01bd22c3d4e5f67890abcd");
        let hash: &[u8; 32] =
            &hex!("9cd794df1ac380ae42117aebcddb148d261871d8aa06b8f87c92108230d6a388");

        let result = authentication::verify_pin(pin, salt, hash);
        assert!(matches!(
            result,
            authenetication::SecurityStatus::InvalidLength
        ));
    }
}

