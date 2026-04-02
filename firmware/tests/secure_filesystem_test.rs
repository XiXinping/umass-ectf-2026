#![no_std]
#![no_main]

#[cfg(test)]
#[embedded_test::tests]
mod gcm_tests {
    use core::module_path;
    use core::{assert_eq};
    use ectf_2026::secure_filesystem;
    use uuid::Uuid;
    use ectf_2026::flash::HwFlash;

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
    fn test_secure_filesystem() {
        let group_id: u16 = 1;
        const FILE_UUID: Uuid = uuid::uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8");
        let mut file_name = [0u8; 32];

        let input_name = "top_secret.bin";
        let name_bytes = input_name.as_bytes();

        file_name[..name_bytes.len()].copy_from_slice(name_bytes);

        let mut plaintext = heapless::Vec::<u8, 8192>::new();
        plaintext.extend_from_slice(b"This is secret data").unwrap();

        let my_protected_file = secure_filesystem::ProtectedFile::create(
            group_id,
            FILE_UUID,
            &file_name,
            &plaintext
        ).expect("Failed to create protected file");

        secure_filesystem::ProtectedFile::digest(my_protected_file.group_id, my_protected_file.uuid, &file_name, &my_protected_file.contents);

        my_protected_file.verify_signature().expect("Signature verification failed!");

        let decrypted_text = my_protected_file.decrypt().expect("Decryption failed!");

        assert_eq!(b"This is secret data", decrypted_text);

        let mut hw_flash: HwFlash = HwFlash;
        let mut fs = secure_filesystem::Filesystem::init(&hw_flash);


        fs.write_file(1, &my_protected_file, FILE_UUID, &mut hw_flash).expect("Failed to write to slot!");

        let read_back_file = fs.read_file(1, &mut hw_flash).expect("Failed to read file!");

        let read_back_file_metadata = fs.get_file_metadata(1).expect("Failed to read file metadata");

        assert_eq!(my_protected_file, read_back_file);

        assert_eq!(FILE_UUID, read_back_file_metadata.uuid);

    }

}
