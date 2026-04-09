#![no_std]
#![no_main]

use panic_probe as _;

#[cfg(test)]
#[defmt_test::tests]
mod signature_tests {
    use ectf_2026::crypto::{ecc_sign_file_digest, ecc_verify_file_digest};
    use ectf_2026::permission;
    use ectf_2026::permission::PermissionType;

    #[test]
    fn test_signature() {
        let public_key = permission::get_public_key(0xbeef, PermissionType::Write).unwrap();
        let private_key = permission::get_private_key(0xbeef, PermissionType::Write).unwrap();

        let digest = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        let signature =
            ecc_sign_file_digest(&digest, &private_key).expect("Failed to sign digest!");

        ecc_verify_file_digest(&signature, &digest, &public_key)
            .expect("Failed to verify signature");
    }

    #[test]
    #[should_error]
    fn test_fucked_up_digest() -> Result<(), &'static str> {
        let public_key = permission::get_public_key(0xbeef, PermissionType::Write).unwrap();
        let private_key = permission::get_private_key(0xbeef, PermissionType::Write).unwrap();

        let digest = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        let signature =
            ecc_sign_file_digest(&digest, &private_key).expect("Failed to sign digest!");

        let fucked_up_digest = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17];

        ecc_verify_file_digest(&signature, &fucked_up_digest, &public_key)
            .map_err(|_| "Failed to verify signature")?;
        Ok(())
    }
    #[test]
    #[should_error]
    fn test_wrong_verify_key() -> Result<(), &'static str> {
        let private_key = permission::get_private_key(0xbeef, PermissionType::Write).unwrap();
        let wrong_public_key = permission::get_public_key(0xdead, PermissionType::Write).unwrap();

        let digest = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        let signature =
            ecc_sign_file_digest(&digest, &private_key).expect("Failed to sign digest!");

        let fucked_up_digest = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17];

        ecc_verify_file_digest(&signature, &fucked_up_digest, &wrong_public_key)
            .map_err(|_| "Failed to verify signature")?;
        Ok(())
    }
}
