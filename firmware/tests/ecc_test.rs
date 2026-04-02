#![no_std]
#![no_main]

 #[cfg(test)]
 #[embedded_test::tests]
 mod ecc_test {
use ectf_2026::random::SecureRng;
use ectf_2026::filesystem::MAX_CONTENTS_SIZE;


      use core::module_path;
      use core::{assert_eq};
     use ectf_2026::crypto;
    use x25519_dalek::{PublicKey, StaticSecret};




     #[test]
     fn test_ecc_full_case() {
         let mut rng = SecureRng::new().expect("Failed to create RNG");

         let priv_key = StaticSecret::random_from_rng(&mut rng);

         let pub_key = PublicKey::from(&priv_key);
         
         let i_have_a_dream: &str = "I am happy to join with you today in what will go down in \
             history as the greatest demonstration for freedom in the history of our nation. \
             Five score years ago, a great American, in whose symbolic shadow we stand today, \
             signed the Emancipation Proclamation";
         let plaintext: &[u8] = i_have_a_dream.as_bytes();

         let mut plaintext_vec = heapless::Vec::<u8, MAX_CONTENTS_SIZE>::new();

         plaintext_vec.extend_from_slice(plaintext)
            .expect("Plaintext is too large for MAX_CONTENTS_SIZE");

         let encrypted: crypto::HybridEncrypted = crypto::assymetric_encrypt(&plaintext_vec, &pub_key)
                .expect("Encryption failed");
        
         let decrypted = crypto::assymetric_decrypt(&encrypted.ciphertext, &encrypted.nonce, &encrypted.cipher_public_key, &encrypted.auth_tag, &priv_key).expect("Decryption failed");
         
         assert_eq!(decrypted, i_have_a_dream.as_bytes());

     }

          #[test]
     fn test_ecc_max_capacity() {
         let mut rng = SecureRng::new().expect("Failed to create RNG");

         let priv_key = StaticSecret::random_from_rng(&mut rng);

         let pub_key = PublicKey::from(&priv_key);
         
         let base_string: &str = "0123456789abcdef0123456789abcdef"; // Exactly 32 bytes
         let base_bytes = base_string.as_bytes();

        let mut plaintext_vec = heapless::Vec::<u8, MAX_CONTENTS_SIZE>::new();

        for _ in 0..256 {
            plaintext_vec.extend_from_slice(base_bytes)
                .expect("Buffer overflow: ensure MAX_CONTENTS_SIZE is at least 8192");
        }

         let encrypted: crypto::HybridEncrypted = crypto::assymetric_encrypt(&plaintext_vec, &pub_key)
                .expect("Encryption failed");
        
         let decrypted = crypto::assymetric_decrypt(&encrypted.ciphertext, &encrypted.nonce, &encrypted.cipher_public_key, &encrypted.auth_tag, &priv_key).expect("Decryption failed");
         
         assert_eq!(decrypted, plaintext_vec);

     }

 }
