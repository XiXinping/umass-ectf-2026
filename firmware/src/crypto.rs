use aes_gcm::{
    aead::{AeadInPlace, KeyInit, heapless::Vec}, 
    Aes256Gcm, Key, Nonce,
};

use crate::challenge_response_auth;
use p256::ecdsa::SigningKey;

use p256::ecdsa::{
    Signature, VerifyingKey,
    signature::{Signer, Verifier},
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

pub fn ecc_sign_file_digest(digest: &[u8], private_key_bytes: &[u8; challenge_response_auth::PRIVATE_KEY_SIZE]) -> Result<Signature, challenge_response_auth::AuthError>{
    let signing_key = SigningKey::from_slice(private_key_bytes)
        .map_err(|_| challenge_response_auth::AuthError::KeyImportFailed)?;

    let signature: Signature = signing_key.sign(digest);

    Ok(signature)

}

pub fn ecc_verify_file_digest(
    signature: &Signature,
    digest: &[u8],
    public_key_bytes: &[u8],
) -> Result<(), challenge_response_auth::AuthError> {
    let verifying_key = VerifyingKey::from_sec1_bytes(public_key_bytes)
        .map_err(|_| challenge_response_auth::AuthError::KeyImportFailed)?;

    verifying_key
        .verify(digest, signature)
        .map_err(|_| challenge_response_auth::AuthError::VerificationFailed)
}