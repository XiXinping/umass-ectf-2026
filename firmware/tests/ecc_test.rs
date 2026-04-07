#![no_std]
#![no_main]

use defmt_rtt as _;

// #[embedded_test::setup]
// fn setup_log() {
//     rtt_target::rtt_init_defmt!();
// }

#[cfg(test)]
#[embedded_test::tests]
mod ecc_test {
    use ectf_2026::filesystem::MAX_CONTENTS_SIZE;
    use ectf_2026::random::SecureRng;

    use core::assert_eq;
    use core::module_path;
    use defmt::println;
    use ectf_2026::crypto;
    use x25519_dalek::{PublicKey, StaticSecret};

    // #[test]
    // fn test_ecc_full_case() {
    //     let mut rng = SecureRng::new().expect("Failed to create RNG");
    //
    //     let priv_key = StaticSecret::random_from_rng(&mut rng);
    //
    //     let pub_key = PublicKey::from(&priv_key);
    //
    //     let i_have_a_dream: &str = "I am happy to join with you today in what will go down in \
    //          history as the greatest demonstration for freedom in the history of our nation. \
    //          Five score years ago, a great American, in whose symbolic shadow we stand today, \
    //          signed the Emancipation Proclamation";
    //     let plaintext: &[u8] = i_have_a_dream.as_bytes();
    //
    //     let mut plaintext_vec = heapless::Vec::<u8, MAX_CONTENTS_SIZE>::new();
    //
    //     plaintext_vec
    //         .extend_from_slice(plaintext)
    //         .expect("Plaintext is too large for MAX_CONTENTS_SIZE");
    //
    //     let encrypted: crypto::AsymmetricEncrypted<MAX_CONTENTS_SIZE> =
    //         crypto::asymmetric_encrypt(&plaintext_vec, &pub_key).expect("Encryption failed");
    //
    //     let decrypted = crypto::asymmetric_decrypt(
    //         &encrypted.ciphertext,
    //         &encrypted.nonce,
    //         &encrypted.cipher_public_key,
    //         &encrypted.auth_tag,
    //         &priv_key,
    //     )
    //     .expect("Decryption failed");
    //
    //     assert_eq!(decrypted, i_have_a_dream.as_bytes());
    // }
    //
    // #[test]
    // fn test_ecc_max_capacity() {
    //     let mut rng = SecureRng::new().expect("Failed to create RNG");
    //
    //     let priv_key = StaticSecret::random_from_rng(&mut rng);
    //
    //     let pub_key = PublicKey::from(&priv_key);
    //
    //     let base_string: &str = "0123456789abcdef0123456789abcdef"; // Exactly 32 bytes
    //     let base_bytes = base_string.as_bytes();
    //
    //     let mut plaintext_vec = heapless::Vec::<u8, MAX_CONTENTS_SIZE>::new();
    //
    //     for _ in 0..256 {
    //         plaintext_vec
    //             .extend_from_slice(base_bytes)
    //             .expect("Buffer overflow: ensure MAX_CONTENTS_SIZE is at least 8192");
    //     }
    //
    //     let encrypted: crypto::AsymmetricEncrypted<MAX_CONTENTS_SIZE> =
    //         crypto::asymmetric_encrypt(&plaintext_vec, &pub_key).expect("Encryption failed");
    //
    //     let decrypted = crypto::asymmetric_decrypt(
    //         &encrypted.ciphertext,
    //         &encrypted.nonce,
    //         &encrypted.cipher_public_key,
    //         &encrypted.auth_tag,
    //         &priv_key,
    //     )
    //     .expect("Decryption failed");
    //
    //     assert_eq!(decrypted, plaintext_vec);
    // }
    //
    // #[test]
    // fn test_ecc_auth_tag_fail() {
    //     let mut rng = SecureRng::new().expect("Failed to create RNG");
    //
    //     let priv_key = StaticSecret::random_from_rng(&mut rng);
    //
    //     let pub_key = PublicKey::from(&priv_key);
    //
    //     let i_have_a_dream: &str = "I am happy to join with you today in what will go down in \
    //          history as the greatest demonstration for freedom in the history of our nation. \
    //          Five score years ago, a great American, in whose symbolic shadow we stand today, \
    //          signed the Emancipation Proclamation";
    //     let plaintext: &[u8] = i_have_a_dream.as_bytes();
    //
    //     let mut plaintext_vec = heapless::Vec::<u8, MAX_CONTENTS_SIZE>::new();
    //
    //     plaintext_vec
    //         .extend_from_slice(plaintext)
    //         .expect("Plaintext is too large for MAX_CONTENTS_SIZE");
    //
    //     let encrypted: crypto::AsymmetricEncrypted<MAX_CONTENTS_SIZE> =
    //         crypto::asymmetric_encrypt(&plaintext_vec, &pub_key).expect("Encryption failed");
    //
    //     let mut auth_tag_bytes = [0u8; 16];
    //
    //     for i in 0..16 {
    //         auth_tag_bytes[i] = i as u8;
    //     }
    //
    //     let decrypted = crypto::asymmetric_decrypt(
    //         &encrypted.ciphertext,
    //         &encrypted.nonce,
    //         &encrypted.cipher_public_key,
    //         &auth_tag_bytes,
    //         &priv_key,
    //     );
    //
    //     assert!(
    //         matches!(decrypted, Err(crypto::CryptoError::AesGcmDecryptError)),
    //         "Expected AesGcmDecryptError, but got {:?}",
    //         decrypted
    //     );
    // }
    //
    // #[test]
    // fn test_ecc_priv_key_fail() {
    //     let mut rng = SecureRng::new().expect("Failed to create RNG");
    //
    //     let priv_key = StaticSecret::random_from_rng(&mut rng);
    //
    //     let pub_key = PublicKey::from(&priv_key);
    //
    //     let i_have_a_dream: &str = "I am happy to join with you today in what will go down in \
    //          history as the greatest demonstration for freedom in the history of our nation. \
    //          Five score years ago, a great American, in whose symbolic shadow we stand today, \
    //          signed the Emancipation Proclamation";
    //     let plaintext: &[u8] = i_have_a_dream.as_bytes();
    //
    //     let mut plaintext_vec = heapless::Vec::<u8, MAX_CONTENTS_SIZE>::new();
    //
    //     plaintext_vec
    //         .extend_from_slice(plaintext)
    //         .expect("Plaintext is too large for MAX_CONTENTS_SIZE");
    //
    //     let encrypted: crypto::AsymmetricEncrypted<MAX_CONTENTS_SIZE> =
    //         crypto::asymmetric_encrypt(&plaintext_vec, &pub_key).expect("Encryption failed");
    //
    //     let mut auth_tag_bytes = [0u8; 16];
    //
    //     for i in 0..16 {
    //         auth_tag_bytes[i] = i as u8;
    //     }
    //
    //     let fail_priv_key: StaticSecret = StaticSecret::random_from_rng(&mut rng);
    //
    //     let decrypted = crypto::asymmetric_decrypt(
    //         &encrypted.ciphertext,
    //         &encrypted.nonce,
    //         &encrypted.cipher_public_key,
    //         &encrypted.auth_tag,
    //         &fail_priv_key,
    //     );
    //
    //     assert!(
    //         matches!(decrypted, Err(crypto::CryptoError::AsymmetricKeyError)),
    //         "Expected AesGcmDecryptError, but got {:?}",
    //         decrypted
    //     );
    // }
    // #[test]
    // fn test_ecc_pub_key_fail() {
    //     let mut rng = SecureRng::new().expect("Failed to create RNG");
    //
    //     let priv_key = StaticSecret::random_from_rng(&mut rng);
    //
    //     let pub_key = PublicKey::from(&priv_key);
    //
    //     let i_have_a_dream: &str = "I am happy to join with you today in what will go down in \
    //          history as the greatest demonstration for freedom in the history of our nation. \
    //          Five score years ago, a great American, in whose symbolic shadow we stand today, \
    //          signed the Emancipation Proclamation";
    //     let plaintext: &[u8] = i_have_a_dream.as_bytes();
    //
    //     let mut plaintext_vec = heapless::Vec::<u8, MAX_CONTENTS_SIZE>::new();
    //
    //     plaintext_vec
    //         .extend_from_slice(plaintext)
    //         .expect("Plaintext is too large for MAX_CONTENTS_SIZE");
    //
    //     let encrypted: crypto::AsymmetricEncrypted<MAX_CONTENTS_SIZE> =
    //         crypto::asymmetric_encrypt(&plaintext_vec, &pub_key).expect("Encryption failed");
    //
    //     let mut auth_tag_bytes = [0u8; 16];
    //
    //     for i in 0..16 {
    //         auth_tag_bytes[i] = i as u8;
    //     }
    //
    //     let fail_priv_key: StaticSecret = StaticSecret::random_from_rng(&mut rng);
    //
    //     let fail_pub_key = PublicKey::from(&fail_priv_key);
    //
    //     let decrypted = crypto::asymmetric_decrypt(
    //         &encrypted.ciphertext,
    //         &encrypted.nonce,
    //         &fail_pub_key,
    //         &encrypted.auth_tag,
    //         &priv_key,
    //     );
    //
    //     assert!(
    //         matches!(decrypted, Err(crypto::CryptoError::AsymmetricKeyError)),
    //         "Expected AesGcmDecryptError, but got {:?}",
    //         decrypted
    //     );
    // }
    // #[test]
    // fn test_ecc_both_key_fail() {
    //     let mut rng = SecureRng::new().expect("Failed to create RNG");
    //
    //     let priv_key = StaticSecret::random_from_rng(&mut rng);
    //
    //     let pub_key = PublicKey::from(&priv_key);
    //
    //     let i_have_a_dream: &str = "I am happy to join with you today in what will go down in \
    //          history as the greatest demonstration for freedom in the history of our nation. \
    //          Five score years ago, a great American, in whose symbolic shadow we stand today, \
    //          signed the Emancipation Proclamation";
    //     let plaintext: &[u8] = i_have_a_dream.as_bytes();
    //
    //     let mut plaintext_vec = heapless::Vec::<u8, MAX_CONTENTS_SIZE>::new();
    //
    //     plaintext_vec
    //         .extend_from_slice(plaintext)
    //         .expect("Plaintext is too large for MAX_CONTENTS_SIZE");
    //
    //     let encrypted: crypto::AsymmetricEncrypted<MAX_CONTENTS_SIZE> =
    //         crypto::asymmetric_encrypt(&plaintext_vec, &pub_key).expect("Encryption failed");
    //
    //     let mut auth_tag_bytes = [0u8; 16];
    //
    //     for i in 0..16 {
    //         auth_tag_bytes[i] = i as u8;
    //     }
    //
    //     let fail_priv_key: StaticSecret = StaticSecret::random_from_rng(&mut rng);
    //
    //     let fail_pub_key = PublicKey::from(&priv_key);
    //
    //     let decrypted = crypto::asymmetric_decrypt(
    //         &encrypted.ciphertext,
    //         &encrypted.nonce,
    //         &fail_pub_key,
    //         &encrypted.auth_tag,
    //         &fail_priv_key,
    //     );
    //
    //     assert!(
    //         matches!(decrypted, Err(crypto::CryptoError::AsymmetricKeyError)),
    //         "Expected AesGcmDecryptError, but got {:?}",
    //         decrypted
    //     );
    // }
    // #[test]
    // fn test_ecc_nonce_fail() {
    //     let mut rng = SecureRng::new().expect("Failed to create RNG");
    //
    //     let priv_key = StaticSecret::random_from_rng(&mut rng);
    //
    //     let pub_key = PublicKey::from(&priv_key);
    //
    //     let i_have_a_dream: &str = "I am happy to join with you today in what will go down in \
    //          history as the greatest demonstration for freedom in the history of our nation. \
    //          Five score years ago, a great American, in whose symbolic shadow we stand today, \
    //          signed the Emancipation Proclamation";
    //     let plaintext: &[u8] = i_have_a_dream.as_bytes();
    //
    //     let mut plaintext_vec = heapless::Vec::<u8, MAX_CONTENTS_SIZE>::new();
    //
    //     plaintext_vec
    //         .extend_from_slice(plaintext)
    //         .expect("Plaintext is too large for MAX_CONTENTS_SIZE");
    //
    //     let encrypted: crypto::AsymmetricEncrypted<MAX_CONTENTS_SIZE> =
    //         crypto::asymmetric_encrypt(&plaintext_vec, &pub_key).expect("Encryption failed");
    //
    //     let mut nonce_bytes = [0u8; 12];
    //
    //     for i in 0..12 {
    //         nonce_bytes[i] = i as u8;
    //     }
    //
    //     let decrypted = crypto::asymmetric_decrypt(
    //         &encrypted.ciphertext,
    //         &nonce_bytes,
    //         &encrypted.cipher_public_key,
    //         &encrypted.auth_tag,
    //         &priv_key,
    //     );
    //
    //     assert!(
    //         matches!(decrypted, Err(crypto::CryptoError::AesGcmDecryptError)),
    //         "Expected AesGcmDecryptError, but got {:?}",
    //         decrypted
    //     );
    // }
    // #[test]
    // fn ecc_test_fail_ciphertext() {
    //     let mut rng = SecureRng::new().expect("Failed to create RNG");
    //
    //     let priv_key = StaticSecret::random_from_rng(&mut rng);
    //
    //     let pub_key = PublicKey::from(&priv_key);
    //
    //     let i_have_a_dream: &str = "I am happy to join with you today in what will go down in \
    //          history as the greatest demonstration for freedom in the history of our nation. \
    //          Five score years ago, a great American, in whose symbolic shadow we stand today, \
    //          signed the Emancipation Proclamation";
    //     let plaintext: &[u8] = i_have_a_dream.as_bytes();
    //     println!("{}", i_have_a_dream);
    //
    //     let mut plaintext_vec = heapless::Vec::<u8, MAX_CONTENTS_SIZE>::new();
    //
    //     plaintext_vec
    //         .extend_from_slice(plaintext)
    //         .expect("Plaintext is too large for MAX_CONTENTS_SIZE");
    //
    //     let encrypted: crypto::AsymmetricEncrypted<MAX_CONTENTS_SIZE> =
    //         crypto::asymmetric_encrypt(&plaintext_vec, &pub_key).expect("Encryption failed");
    //
    //     let decrypted = crypto::asymmetric_decrypt(
    //         &plaintext_vec,
    //         &encrypted.nonce,
    //         &encrypted.cipher_public_key,
    //         &encrypted.auth_tag,
    //         &priv_key,
    //     );
    //
    //     assert!(
    //         matches!(decrypted, Err(crypto::CryptoError::AesGcmDecryptError)),
    //         "Expected AesGcmDecryptError, but got {:?}",
    //         decrypted
    //     );
    // }

    // use core::{assert, matches};
    // use ectf_2026::authentication;
    // use ectf_2026::authentication::SecurityStatus;
    // use hex_literal::hex;

    #[test]
    fn test_ecc_sanity_check() {
        let mut rng = SecureRng::new().expect("Failed to create RNG");
        let priv_key = StaticSecret::random_from_rng(&mut rng);
        let pub_key = PublicKey::from(&priv_key);
        let i_have_a_dream: &str = "I am happy to join with you today in what will go down in \
             history as the greatest demonstration for freedom in the history of our nation. \
             Five score years ago, a great American, in whose symbolic shadow we stand today, \
             signed the Emancipation Proclamation";
         let plaintext: &[u8] = i_have_a_dream.as_bytes();

         let mut plaintext_vec = heapless::Vec::<u8, 256>::new();

         plaintext_vec.extend_from_slice(plaintext)
            .expect("Plaintext is too large for MAX_CONTENTS_SIZE");

         let (nonce, auth_tag, public_key) = crypto::asymmetric_encrypt_in_place::<256>(&mut plaintext_vec, &pub_key)
                .expect("Encryption failed");

         let _decrypted = crypto::asymmetric_decrypt_in_place(& mut plaintext_vec, &nonce, &public_key, &auth_tag, &priv_key).expect("Decryption failed");

         assert_eq!(plaintext_vec, i_have_a_dream.as_bytes());

     }

          #[test]
     fn test_ecc_max_capacity() {
         let mut rng = SecureRng::new().expect("Failed to create RNG");

         let priv_key = StaticSecret::random_from_rng(&mut rng);

         let pub_key = PublicKey::from(&priv_key);
         
         let base_string: &str = "0123456789abcdef0123456789abcdef"; // Exactly 32 bytes
         let base_bytes = base_string.as_bytes();

        let mut plaintext_vec = heapless::Vec::<u8, 8192>::new();

        for _ in 0..256 {
            plaintext_vec.extend_from_slice(base_bytes)
                .expect("Buffer overflow: ensure MAX_CONTENTS_SIZE is at least 8192");
        }

        let (nonce, auth_tag, public_key) = crypto::asymmetric_encrypt_in_place::<8192>(&mut plaintext_vec, &pub_key)
                .expect("Encryption failed");

         let _decrypted = crypto::asymmetric_decrypt_in_place(& mut plaintext_vec, &nonce, &public_key, &auth_tag, &priv_key).expect("Decryption failed");

         assert_eq!(plaintext_vec, base_string.as_bytes());

     }

    #[test]
     fn test_ecc_auth_tag_fail() {
         let mut rng = SecureRng::new().expect("Failed to create RNG");

         let priv_key = StaticSecret::random_from_rng(&mut rng);

         let pub_key = PublicKey::from(&priv_key);
         
         let i_have_a_dream: &str = "I am happy to join with you today in what will go down in \
             history as the greatest demonstration for freedom in the history of our nation. \
             Five score years ago, a great American, in whose symbolic shadow we stand today, \
             signed the Emancipation Proclamation";
         let plaintext: &[u8] = i_have_a_dream.as_bytes();

         let mut plaintext_vec = heapless::Vec::<u8, 256>::new();

         plaintext_vec.extend_from_slice(plaintext)
            .expect("Plaintext is too large for MAX_CONTENTS_SIZE");

         let (nonce, auth_tag, public_key) = crypto::asymmetric_encrypt_in_place::<256>(&mut plaintext_vec, &pub_key)
                .expect("Encryption failed");

         let mut auth_tag_bytes = [0u8; 16];

         for i in 0..16 {
            auth_tag_bytes[i] = i as u8;
        }
        
        let _decrypted = crypto::asymmetric_decrypt_in_place(& mut plaintext_vec, &nonce, &public_key, &auth_tag_bytes, &priv_key).expect("Decryption failed");
         
        assert_ne!(plaintext_vec, i_have_a_dream.as_bytes(), "Expected AesGcmDecryptError, but got {:?}", plaintext_vec);


     }
     
     #[test]
     fn test_ecc_priv_key_fail() {
         let mut rng = SecureRng::new().expect("Failed to create RNG");

         let priv_key = StaticSecret::random_from_rng(&mut rng);

         let pub_key = PublicKey::from(&priv_key);
         
         let i_have_a_dream: &str = "I am happy to join with you today in what will go down in \
             history as the greatest demonstration for freedom in the history of our nation. \
             Five score years ago, a great American, in whose symbolic shadow we stand today, \
             signed the Emancipation Proclamation";
         let plaintext: &[u8] = i_have_a_dream.as_bytes();

         let mut plaintext_vec = heapless::Vec::<u8, 256>::new();

         plaintext_vec.extend_from_slice(plaintext)
            .expect("Plaintext is too large for MAX_CONTENTS_SIZE");

         let (nonce, auth_tag, public_key) = crypto::asymmetric_encrypt_in_place::<256>(&mut plaintext_vec, &pub_key)
                .expect("Encryption failed");

         let mut auth_tag_bytes = [0u8; 16];

         for i in 0..16 {
            auth_tag_bytes[i] = i as u8;
        }

        let fail_priv_key: StaticSecret = StaticSecret::random_from_rng(&mut rng);
        
        let _decrypted = crypto::asymmetric_decrypt(&plaintext_vec, &nonce, &public_key, &auth_tag, &fail_priv_key).expect("Decryption failed");
         
        assert_ne!(plaintext_vec, i_have_a_dream.as_bytes(), "Expected AesGcmDecryptError, but got {:?}", plaintext_vec);


     }
    #[test]
    fn test_ecc_pub_key_fail() {
         let mut rng = SecureRng::new().expect("Failed to create RNG");

         let priv_key = StaticSecret::random_from_rng(&mut rng);

         let pub_key = PublicKey::from(&priv_key);
         
         let i_have_a_dream: &str = "I am happy to join with you today in what will go down in \
             history as the greatest demonstration for freedom in the history of our nation. \
             Five score years ago, a great American, in whose symbolic shadow we stand today, \
             signed the Emancipation Proclamation";
         let plaintext: &[u8] = i_have_a_dream.as_bytes();

         let mut plaintext_vec = heapless::Vec::<u8, 256>::new();

         plaintext_vec.extend_from_slice(plaintext)
            .expect("Plaintext is too large for MAX_CONTENTS_SIZE");

         let (nonce, auth_tag, public_key) = crypto::asymmetric_encrypt_in_place::<256>(&mut plaintext_vec, &pub_key)
                .expect("Encryption failed");

         let mut auth_tag_bytes = [0u8; 16];

         for i in 0..16 {
            auth_tag_bytes[i] = i as u8;
        }

        let fail_priv_key: StaticSecret = StaticSecret::random_from_rng(&mut rng);

        let fail_pub_key = PublicKey::from(&fail_priv_key);

        let _decrypted = crypto::asymmetric_decrypt_in_place(& mut plaintext_vec, &nonce, &fail_pub_key, &auth_tag, &priv_key).expect("Decryption failed");

        assert_ne!(plaintext_vec, i_have_a_dream.as_bytes(), "Expected AesGcmDecryptError, but got {:?}", plaintext_vec);


     }
    #[test]
    fn test_ecc_both_key_fail() {
         let mut rng = SecureRng::new().expect("Failed to create RNG");

         let priv_key = StaticSecret::random_from_rng(&mut rng);

         let pub_key = PublicKey::from(&priv_key);
         
         let i_have_a_dream: &str = "I am happy to join with you today in what will go down in \
             history as the greatest demonstration for freedom in the history of our nation. \
             Five score years ago, a great American, in whose symbolic shadow we stand today, \
             signed the Emancipation Proclamation";
         let plaintext: &[u8] = i_have_a_dream.as_bytes();

         let mut plaintext_vec = heapless::Vec::<u8, 256>::new();

         plaintext_vec.extend_from_slice(plaintext)
            .expect("Plaintext is too large for MAX_CONTENTS_SIZE");

         let (nonce, auth_tag, public_key) = crypto::asymmetric_encrypt_in_place::<256>(&mut plaintext_vec, &pub_key)
                .expect("Encryption failed");

         let mut auth_tag_bytes = [0u8; 16];

         for i in 0..16 {
            auth_tag_bytes[i] = i as u8;
        }

        let fail_priv_key: StaticSecret = StaticSecret::random_from_rng(&mut rng);

        let fail_pub_key = PublicKey::from(&priv_key);

        let _decrypted = crypto::asymmetric_decrypt(&plaintext_vec, &nonce, &fail_pub_key, &auth_tag, &fail_priv_key).expect("Decryption failed");

        assert_ne!(plaintext_vec, i_have_a_dream.as_bytes(), "Expected AesGcmDecryptError, but got {:?}", plaintext_vec);

     }
    #[test]
    fn test_ecc_nonce_fail() {
         let mut rng = SecureRng::new().expect("Failed to create RNG");

         let priv_key = StaticSecret::random_from_rng(&mut rng);

         let pub_key = PublicKey::from(&priv_key);
         
         let i_have_a_dream: &str = "I am happy to join with you today in what will go down in \
             history as the greatest demonstration for freedom in the history of our nation. \
             Five score years ago, a great American, in whose symbolic shadow we stand today, \
             signed the Emancipation Proclamation";
         let plaintext: &[u8] = i_have_a_dream.as_bytes();

         let mut plaintext_vec = heapless::Vec::<u8, 256>::new();

         plaintext_vec.extend_from_slice(plaintext)
            .expect("Plaintext is too large for MAX_CONTENTS_SIZE");

         let (nonce, auth_tag, public_key) = crypto::asymmetric_encrypt_in_place::<256>(&mut plaintext_vec, &pub_key)
                .expect("Encryption failed");

         let mut nonce_bytes = [0u8; 12];

         for i in 0..12 {
            nonce_bytes[i] = i as u8;
        }
        
         let _decrypted = crypto::asymmetric_decrypt(&plaintext_vec, &nonce_bytes, &public_key, &auth_tag, &priv_key).expect("Decryption failed");
         
        assert_ne!(plaintext_vec, i_have_a_dream.as_bytes(), "Expected AesGcmDecryptError, but got {:?}", plaintext_vec);

     }
    #[test]
    fn ecc_test_fail_ciphertext() {
         let mut rng = SecureRng::new().expect("Failed to create RNG");

         let priv_key = StaticSecret::random_from_rng(&mut rng);

         let pub_key = PublicKey::from(&priv_key);
         
         let i_have_a_dream: &str = "I am happy to join with you today in what will go down in \
             history as the greatest demonstration for freedom in the history of our nation. \
             Five score years ago, a great American, in whose symbolic shadow we stand today, \
             signed the Emancipation Proclamation";
         let plaintext: &[u8] = i_have_a_dream.as_bytes();

         let mut plaintext_vec = heapless::Vec::<u8, 256>::new();

         plaintext_vec.extend_from_slice(plaintext)
            .expect("Plaintext is too large for MAX_CONTENTS_SIZE");

         let (nonce, auth_tag, public_key) = crypto::asymmetric_encrypt_in_place::<256>(&mut plaintext_vec, &pub_key)
                .expect("Encryption failed");

        
        let _decrypted = crypto::asymmetric_decrypt(&plaintext_vec, &nonce, &public_key, &auth_tag, &priv_key).expect("Decryption failed");
         
        assert_ne!(plaintext_vec, i_have_a_dream.as_bytes(), "Expected AesGcmDecryptError, but got {:?}", plaintext_vec);

     }






 }
