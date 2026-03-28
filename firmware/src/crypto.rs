use aes_gcm::{
    aead::{AeadCore, AeadInPlace, KeyInit, OsRng, heapless::Vec},
    Aes256Gcm, Nonce, // 
};

pub fn aes_gcm_encrypt(plaintext: &[u8],             
    key: &[u8; 32],               
    iv: &[u8; 12],                
    aad: &[u8],                   
    ciphertext_out: &mut [u8],    
    auth_tag_out: &mut [u8; 16],) {

    let key = Key::<Aes256Gcm>::from_slice(key);
    let nonce = Nonce::from_slice(iv);
    let cipher = Aes256Gcm::new(key);
    
    let buffer_size: usize = plaintext.len() + 16;
    let mut buffer: Vec<u8, buffer_size> = Vec::new();

    buffer.extend_from_slice(plaintext);


    cipher.encrypt_in_place(nonce, aad, &mut buffer)?;

    let ciphertext_len: usize = buffer_size - 16;

    auth_tag_out.copy_from_slice(&buffer[ciphertext_len..]);
    ciphertext_out.copy_from_slice(&buffer[..ciphertext_len]);

}

pub fn aes_gcm_decrypt(ciphertext: &[u8],           
    key: &[u8; 32],             
    iv: &[u8; 12],            
    auth_tag: &[u8; 16],         
    aad: &[u8],                  
    plaintext_out: &mut [u8],) {
    
    let key = Key::<Aes256Gcm>::from_slice(key);
    let nonce = Nonce::from_slice(iv);
    let cipher = Aes256Gcm::new(key);
    

    let buffer_size: usize = plaintext.len() + 16;
    let mut buffer: Vec<u8, buffer_size> = Vec::new(); 

    buffer.extend_from_slice(ciphertext);
    buffer.extend_from_slice(auth_tag).unwrap();


    cipher.decrypt_in_place(nonce, aad, &mut buffer)?;

    let plaintext_len: usize = buffer_size - 16;

    plaintext_out.copy_from_slice(&buffer[..plaintext_len]);
}