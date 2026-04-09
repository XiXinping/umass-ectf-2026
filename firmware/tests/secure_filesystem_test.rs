#![no_std]
#![no_main]

use panic_probe as _;

#[cfg(test)]
#[defmt_test::tests]
mod gcm_tests {
    use core::assert_eq;
    use core::module_path;
    use ectf_2026::GLOBAL_PUB_KEY;
    use ectf_2026::GLOBAL_RNG;
    use ectf_2026::GLOBAL_SECRET;
    use ectf_2026::GLOBAL_SHARED_SECRETS;
    use ectf_2026::crypto::asymmetric_decrypt_in_place;
    use ectf_2026::flash::HwFlash;
    use ectf_2026::permission;
    use ectf_2026::permission::PermissionType;
    use ectf_2026::permission::SharedSecrets;
    use ectf_2026::permission::gen_shared_secrets;
    use ectf_2026::random::SecureRng;
    use ectf_2026::secrets::NUM_PERMS;
    use ectf_2026::secure_filesystem;
    use ectf_2026::secure_filesystem::ProtectedFile;
    use hex_literal::hex;
    use uuid::Uuid;
    use x25519_dalek::PublicKey;
    use x25519_dalek::StaticSecret;

    /*
    pub struct MockFlash {
        pub data: [u8; 1024 * 16],
    }

    impl MockFlash {
        pub fn new() -> Self {
            Self { data: [0xFF; 1024 * 16] } // Flash usually defaults to 0xFF
        }
    }

    impl Flash for MockFlash {
        fn read(&mut self, address: u32, out: &mut [u8]) -> Result<(), FlashError> {
            let addr = address as usize;
            out.copy_from_slice(&self.data[addr..addr + out.len()]);
            Ok(())
        }

        fn write(&mut self, address: u32, data: &[u8]) -> Result<(), FlashError> {
            let addr = address as usize;
            self.data[addr..addr + data.len()].copy_from_slice(data);
            Ok(())
        }

        fn erase(&mut self, address: u32) -> Result<(), FlashError> {
            let addr = address as usize;
            self.data[addr..addr + 1024].fill(0xFF);
            Ok(())
        }
    }
    */

    #[test]
    fn test_flash_writing() {
        let mut rng = SecureRng::new().expect("RNG init failed");
        let secret = StaticSecret::random_from_rng(&mut rng);
        let pub_key = PublicKey::from(&secret);
        let shared_secrets: [SharedSecrets; NUM_PERMS] = gen_shared_secrets(secret.clone());

        critical_section::with(|cs: critical_section::CriticalSection<'_>| {
            *GLOBAL_RNG.borrow(cs).borrow_mut() = Some(rng);
            *GLOBAL_SECRET.borrow(cs).borrow_mut() = Some(secret.clone());
            *GLOBAL_PUB_KEY.borrow(cs).borrow_mut() = Some(pub_key);
            *GLOBAL_SHARED_SECRETS.borrow(cs).borrow_mut() = Some(shared_secrets);
        });

        let group_id: u16 = 0xbeef;
        const FILE_UUID: [u8; 16] = hex!("67e5504410b1426f9247bb680e5fe0c8");
        let mut file_name = [0u8; 32];

        let input_name = "top_secret.bin";
        let name_bytes = input_name.as_bytes();

        file_name[..name_bytes.len()].copy_from_slice(name_bytes);

        let super_secret_data = b"This is secret data";
        let mut plaintext = [0u8; 8192];
        plaintext[..super_secret_data.len()].copy_from_slice(super_secret_data);

        let mut hw_flash: HwFlash = HwFlash;
        let mut fs = secure_filesystem::Filesystem::init(&hw_flash);

        for _ in 0..2 {
            let mut file = ProtectedFile::default();
            secure_filesystem::ProtectedFile::create_in(
                &mut file, group_id, FILE_UUID, &file_name, &plaintext,
            )
            .expect("Failed to create protected file");

            fs.write_file(4, &file, FILE_UUID, &mut hw_flash)
                .expect("Failed to write to slot!");
        }
    }

    // #[test]
    // fn test_secure_filesystem() {
    //     let group_id: u16 = 0xbeef;
    //     const FILE_UUID: [u8; 16] = hex!("67e5504410b1426f9247bb680e5fe0c8");
    //     let mut file_name = [0u8; 32];
    //
    //     let input_name = "top_secret.bin";
    //     let name_bytes = input_name.as_bytes();
    //
    //     file_name[..name_bytes.len()].copy_from_slice(name_bytes);
    //
    //     let mut plaintext = [0u8; 8192];
    //     plaintext.copy_from_slice(b"This is secret data");
    //
    //     let mut file = ProtectedFile::default();
    //     secure_filesystem::ProtectedFile::create_in(
    //         &mut file, group_id, FILE_UUID, &file_name, &plaintext,
    //     )
    //     .expect("Failed to create protected file");
    //
    //     secure_filesystem::ProtectedFile::digest(
    //         file.group_id,
    //         file.uuid,
    //         &file_name,
    //         &file.ciphertext,
    //     );
    //
    //     file.verify_signature()
    //         .expect("Signature verification failed!");
    //
    //     let read_key = StaticSecret::from(
    //         permission::get_private_key(file.group_id, PermissionType::Read)
    //             .expect("Couldn't get the key!"),
    //     );
    //
    //     asymmetric_decrypt_in_place(
    //         &mut file.ciphertext,
    //         &file.nonce,
    //         &PublicKey::from(file.ciphertext_public_key),
    //         &file.auth_tag,
    //         &read_key,
    //     )
    //     .expect("Decryption failed!");
    //
    //     let decrypted = file.ciphertext;
    //
    //     assert_eq!(plaintext, decrypted);
    //
    //     let mut hw_flash: HwFlash = HwFlash;
    //     let mut fs = secure_filesystem::Filesystem::init(&hw_flash);
    //
    //     fs.write_file(1, &file, FILE_UUID, &mut hw_flash)
    //         .expect("Failed to write to slot!");
    //
    //     let read_back_file = fs.read_file(1, &hw_flash).expect("Failed to read file!");
    //
    //     let read_back_file_metadata = fs
    //         .get_file_metadata(1)
    //         .expect("Failed to read file metadata");
    //
    //     assert_eq!(file, read_back_file);
    //
    //     assert_eq!(FILE_UUID, read_back_file_metadata.uuid);
    // }
}
