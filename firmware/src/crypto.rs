use aes_gcm::{
    aead::{AeadInPlace, KeyInit, heapless::Vec}, 
    Aes256Gcm, Key, Nonce,
};


pub fn aes_gcm_encrypt(plaintext: &[u8],             
    key: &[u8; 32],               
    iv: &[u8; 12],                
    aad: &[u8],                   
    ciphertext_out: &mut [u8],    
    auth_tag_out: &mut [u8; 16],) -> Result<(), aes_gcm::Error> {

    let key = Key::<Aes256Gcm>::from_slice(key);
    let nonce = Nonce::from_slice(iv);
    let cipher = Aes256Gcm::new(key);
    
    const BUFFER_SIZE: usize = 8192 + 16 + 48;
    let mut buffer: Vec<u8, BUFFER_SIZE> = Vec::new();

    buffer.extend_from_slice(plaintext).map_err(|_| aes_gcm::Error)?;


    cipher.encrypt_in_place(nonce, aad, &mut buffer)?;

    let total_len: usize = buffer.len();

    auth_tag_out.copy_from_slice(&buffer[plaintext.len()..total_len]);
    ciphertext_out.copy_from_slice(&buffer[..plaintext.len()]);

    Ok(())

}

pub fn aes_gcm_decrypt(ciphertext: &[u8],           
    key: &[u8; 32],             
    iv: &[u8; 12],            
    auth_tag: &[u8; 16],         
    aad: &[u8],                  
    plaintext_out: &mut [u8],) -> Result<(), aes_gcm::Error> {
    
    let key = Key::<Aes256Gcm>::from_slice(key);
    let nonce = Nonce::from_slice(iv);
    let cipher = Aes256Gcm::new(key);
    

    const BUFFER_SIZE: usize = 8192 + 16 + 48;
    let mut buffer: Vec<u8, BUFFER_SIZE> = Vec::new(); 

    buffer.extend_from_slice(ciphertext).map_err(|_| aes_gcm::Error)?;
    buffer.extend_from_slice(auth_tag).map_err(|_| aes_gcm::Error)?;


    cipher.decrypt_in_place(nonce, aad, &mut buffer)?;

    plaintext_out.copy_from_slice(&buffer[..ciphertext.len()]);

    Ok(())
}