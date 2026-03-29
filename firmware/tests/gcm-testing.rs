use firmware::crypto;
use aes_gcm::{
    aead::{AeadInPlace, KeyInit, heapless::Vec}, 
    Aes256Gcm, Key, Nonce,
};
use defmt::assert_eq;
use hex;

#[test]
fn test_basic_gcm_encrypt() {
    let i_have_a_dream: &str = "I am happy to join with you today in what will go down in history as \
                the greatest demonstration for freedom in the history of our nation. \
                Five score years ago, a great American, in whose symbolic shadow we \
                stand today, signed the Emancipation Proclamation";

    let plaintext: &[u8] = i_have_a_dream.as_bytes();
    
    let mut key_data: [u8; 32] = [0u8; 32];
    for i in 0..32 {
        key_data[i] = i as u8;
    }
    let key: &[u8; 32] = &key_data;

    let mut iv_data: [u8; 12] = [0u8; 12];
    for i in 0..12 {
        iv_data[i] = i as u8;
    }
    let iv: &[u8; 12] = &iv_data;

    let mut ciphertext_out: Vec<u8> = vec![0u8; plaintext.len()];

    let mut auth_tag_out: [u8; 16] = [0u8; 16];

    crypto::aes_gcm_encrypt(
        plaintext,           // &[u8]
        key,                 // &[u8; 32]
        iv,                  // &[u8; 12]
        &[],                 // aad: empty byte slice
        &mut ciphertext_out, // &mut [u8] (Vec coerces to slice)
        &mut auth_tag_out,   // &mut [u8; 16]
    );
    let expected_ciphertext: &[u8; 256] = b"\x0e\"\xb7v\xe5\x8d\xa3k\xfd8\xb7\xff\xde\xc9\x12\x02\xea\xb8\xa7C\x99\x0f7\\A\x08\x90\xa5i\x06d\xd3x0\xc7\x92\x8f\xb6z\xf9\x00\x84\x08\x84\xe4\xeb\x08_\x81y\x04\xe2-\xb8\x83\xb3Q\xb7Bpk\x97\x9a\x9c\x89\x1c\xa7\t\xf3\xa5N\x04<3\xd8\x0b\x8e\xfbk\x9bL\xaa\xad\x07\x1b\x0c=\x1b\x89\x8f\xff\xb8\x11\x9f\xd7\xad\xad\x97+\xc6\xc23\xad\x7f\xfasS\x92!\x1b\x01\x0b\xd2\x02B\xc3\x8a\xb6Q\xf5?\x86w\xa2\xe4\xc6\x01{\xc9rn\xa7\xc0\xbe\xa4=&\xc1\x0e\xc8K\xbfl\xb1U\x9b\x91P\x15h\xf6+\xfe,\xc8\x16\x9d\xbd\xc5\xce\xf2\xb7\xf9g\x8c\x9e\xb8^\xe6\x0e\xb8\x88\xb6\xe3\xe7\xd5\xb1\xee\xa3L\xab\xdc\x1b\xd3\x16\xba\xe0\xb4\x08\xa8\xd5\x9c\x7f%\xe9\xda~\xb5\xb7\xadX!\xf3\x91\xdfa\xaa\xf0\x80\x10\x9cVIo\xde\x90\x08\xbd\xba\xb4(/\xe1\x9f\'\x03\xa0\xc7\x83\x00FH3)\xdba\xc5p\x088\xc7\xfd\x99%\xef_\xea\xc9v\x06\x06\x07\xe2\xf3,\x81";
    let expected_auth_tag: &str = "2721a971503ea53e5520130d9a0789df";
    assert_eq!(hex::encode(auth_tag_out), expected_auth_tag);
    assert_eq!(ciphertext_out, expected_ciphertext);
}

fn test_basic_gcm_decrypt() {
    let ciphertext: &[u8; 256] = b"\x0e\"\xb7v\xe5\x8d\xa3k\xfd8\xb7\xff\xde\xc9\x12\x02\xea\xb8\xa7C\x99\x0f7\\A\x08\x90\xa5i\x06d\xd3x0\xc7\x92\x8f\xb6z\xf9\x00\x84\x08\x84\xe4\xeb\x08_\x81y\x04\xe2-\xb8\x83\xb3Q\xb7Bpk\x97\x9a\x9c\x89\x1c\xa7\t\xf3\xa5N\x04<3\xd8\x0b\x8e\xfbk\x9bL\xaa\xad\x07\x1b\x0c=\x1b\x89\x8f\xff\xb8\x11\x9f\xd7\xad\xad\x97+\xc6\xc23\xad\x7f\xfasS\x92!\x1b\x01\x0b\xd2\x02B\xc3\x8a\xb6Q\xf5?\x86w\xa2\xe4\xc6\x01{\xc9rn\xa7\xc0\xbe\xa4=&\xc1\x0e\xc8K\xbfl\xb1U\x9b\x91P\x15h\xf6+\xfe,\xc8\x16\x9d\xbd\xc5\xce\xf2\xb7\xf9g\x8c\x9e\xb8^\xe6\x0e\xb8\x88\xb6\xe3\xe7\xd5\xb1\xee\xa3L\xab\xdc\x1b\xd3\x16\xba\xe0\xb4\x08\xa8\xd5\x9c\x7f%\xe9\xda~\xb5\xb7\xadX!\xf3\x91\xdfa\xaa\xf0\x80\x10\x9cVIo\xde\x90\x08\xbd\xba\xb4(/\xe1\x9f\'\x03\xa0\xc7\x83\x00FH3)\xdba\xc5p\x088\xc7\xfd\x99%\xef_\xea\xc9v\x06\x06\x07\xe2\xf3,\x81";
    let auth_tag_hex: &str = "2721a971503ea53e5520130d9a0789df";

    let mut auth_tag_bytes = [0u8; 16];
    hex::decode_to_slice(auth_tag_hex, &mut auth_tag_bytes)
        .expect("Decoding failed: ensure the string is 32 bytes");

    let mut key_data: [u8; 32] = [0u8; 32];
    for i in 0..32 {
        key_data[i] = i as u8;
    }
    let key: &[u8; 32] = &key_data;

    let mut iv_data: [u8; 12] = [0u8; 12];
    for i in 0..12 {
        iv_data[i] = i as u8;
    }
    let iv: &[u8; 12] = &iv_data;

    let mut plaintext_out: std::vec::Vec<u8> = vec![0u8; ciphertext.len()];
    aes_gcm_decrypt(
        ciphertext,          
        key,                  
        iv,                   
        &auth_tag_bytes,      
        &[],                  
        &mut plaintext_out,   
    );

    let expected_text: &str = "I am happy to join with you today in what will go down in history as \
                the greatest demonstration for freedom in the history of our nation. \
                Five score years ago, a great American, in whose symbolic shadow we \
                stand today, signed the Emancipation Proclamation";
    assert_eq!(plaintext_out, expected_text.as_bytes());
    




}

fn test_gcm_encrypt_with_aad() {
    let i_have_a_dream: &str = "I am happy to join with you today in what will go down in history as \
                the greatest demonstration for freedom in the history of our nation. \
                Five score years ago, a great American, in whose symbolic shadow we \
                stand today, signed the Emancipation Proclamation";
    let aad: &str = "1234";

    let plaintext: &[u8] = i_have_a_dream.as_bytes();
    let additional_data: &[u8] = aad.as_bytes();

    let mut key_data: [u8; 32] = [0u8; 32];
    for i in 0..32 {
        key_data[i] = i as u8;
    }
    let key: &[u8; 32] = &key_data;

    let mut iv_data: [u8; 12] = [0u8; 12];
    for i in 0..12 {
        iv_data[i] = i as u8;
    }
    let iv: &[u8; 12] = &iv_data;

    let mut ciphertext_out: Vec<u8> = vec![0u8; plaintext.len()];

    let mut auth_tag_out: [u8; 16] = [0u8; 16];

    crypto::aes_gcm_encrypt(
        plaintext,           // &[u8]
        key,                 // &[u8; 32]
        iv,                  // &[u8; 12]
        additional_data,                 // aad: empty byte slice
        &mut ciphertext_out, // &mut [u8] (Vec coerces to slice)
        &mut auth_tag_out,   // &mut [u8; 16]
    );
    let expected_ciphertext = b"\x0e\"\xb7v\xe5\x8d\xa3k\xfd8\xb7\xff\xde\xc9\x12\x02\xea\xb8\xa7C\x99\x0f7\\A\x08\x90\xa5i\x06d\xd3x0\xc7\x92\x8f\xb6z\xf9\x00\x84\x08\x84\xe4\xeb\x08_\x81y\x04\xe2-\xb8\x83\xb3Q\xb7Bpk\x97\x9a\x9c\x89\x1c\xa7\t\xf3\xa5N\x04<3\xd8\x0b\x8e\xfbk\x9bL\xaa\xad\x07\x1b\x0c=\x1b\x89\x8f\xff\xb8\x11\x9f\xd7\xad\xad\x97+\xc6\xc23\xad\x7f\xfasS\x92!\x1b\x01\x0b\xd2\x02B\xc3\x8a\xb6Q\xf5?\x86w\xa2\xe4\xc6\x01{\xc9rn\xa7\xc0\xbe\xa4=&\xc1\x0e\xc8K\xbfl\xb1U\x9b\x91P\x15h\xf6+\xfe,\xc8\x16\x9d\xbd\xc5\xce\xf2\xb7\xf9g\x8c\x9e\xb8^\xe6\x0e\xb8\x88\xb6\xe3\xe7\xd5\xb1\xee\xa3L\xab\xdc\x1b\xd3\x16\xba\xe0\xb4\x08\xa8\xd5\x9c\x7f%\xe9\xda~\xb5\xb7\xadX!\xf3\x91\xdfa\xaa\xf0\x80\x10\x9cVIo\xde\x90\x08\xbd\xba\xb4(/\xe1\x9f\'\x03\xa0\xc7\x83\x00FH3)\xdba\xc5p\x088\xc7\xfd\x99%\xef_\xea\xc9v\x06\x06\x07\xe2\xf3,\x81";
    let expected_auth_tag: &str = "40d25c63f31f095c20acd47555b8d6a6";
    assert_eq!(hex::encode(auth_tag_out), expected_auth_tag);
    assert_eq!(ciphertext_out, expected_ciphertext);


}

fn test_gcm_decrypt_with_aad() {
    let expected_ciphertext: &[u8; 256] = b"\x0e\"\xb7v\xe5\x8d\xa3k\xfd8\xb7\xff\xde\xc9\x12\x02\xea\xb8\xa7C\x99\x0f7\\A\x08\x90\xa5i\x06d\xd3x0\xc7\x92\x8f\xb6z\xf9\x00\x84\x08\x84\xe4\xeb\x08_\x81y\x04\xe2-\xb8\x83\xb3Q\xb7Bpk\x97\x9a\x9c\x89\x1c\xa7\t\xf3\xa5N\x04<3\xd8\x0b\x8e\xfbk\x9bL\xaa\xad\x07\x1b\x0c=\x1b\x89\x8f\xff\xb8\x11\x9f\xd7\xad\xad\x97+\xc6\xc23\xad\x7f\xfasS\x92!\x1b\x01\x0b\xd2\x02B\xc3\x8a\xb6Q\xf5?\x86w\xa2\xe4\xc6\x01{\xc9rn\xa7\xc0\xbe\xa4=&\xc1\x0e\xc8K\xbfl\xb1U\x9b\x91P\x15h\xf6+\xfe,\xc8\x16\x9d\xbd\xc5\xce\xf2\xb7\xf9g\x8c\x9e\xb8^\xe6\x0e\xb8\x88\xb6\xe3\xe7\xd5\xb1\xee\xa3L\xab\xdc\x1b\xd3\x16\xba\xe0\xb4\x08\xa8\xd5\x9c\x7f%\xe9\xda~\xb5\xb7\xadX!\xf3\x91\xdfa\xaa\xf0\x80\x10\x9cVIo\xde\x90\x08\xbd\xba\xb4(/\xe1\x9f\'\x03\xa0\xc7\x83\x00FH3)\xdba\xc5p\x088\xc7\xfd\x99%\xef_\xea\xc9v\x06\x06\x07\xe2\xf3,\x81";
    let expected_auth_tag: &str = "40d25c63f31f095c20acd47555b8d6a6";
    let mut auth_tag_bytes = [0u8; 16];
    hex::decode_to_slice(auth_tag_hex, &mut auth_tag_bytes)
        .expect("Decoding failed: ensure the string is 32 bytes");

    let mut key_data: [u8; 32] = [0u8; 32];
    for i in 0..32 {
        key_data[i] = i as u8;
    }
    let key: &[u8; 32] = &key_data;

    let mut iv_data: [u8; 12] = [0u8; 12];
    for i in 0..12 {
        iv_data[i] = i as u8;
    }
    let iv: &[u8; 12] = &iv_data;

    let mut plaintext_out: std::vec::Vec<u8> = vec![0u8; ciphertext.len()];
    aes_gcm_decrypt(
        ciphertext,          
        key,                  
        iv,                   
        &auth_tag_bytes,      
        &[],                  
        &mut plaintext_out,   
    );

    let expected_text: &str = "I am happy to join with you today in what will go down in history as \
                the greatest demonstration for freedom in the history of our nation. \
                Five score years ago, a great American, in whose symbolic shadow we \
                stand today, signed the Emancipation Proclamation";
    assert_eq!(plaintext_out, expected_text.as_bytes());




}