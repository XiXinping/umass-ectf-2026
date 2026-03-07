#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <wolfssl/wolfcrypt/aes.h>

#define AUTH_TAG_SIZE AES_BLOCK_SIZE
#define NONCE_SIZE GCM_NONCE_MID_SZ
#define AES_IV_SIZE 12
#define AES_KEY_SIZE 32

typedef struct {
    uint32_t magic; // what is magic?
    uint8_t key[AES_KEY_SIZE];
    uint8_t last_iv[AES_IV_SIZE];
    uint8_t last_tag[AUTH_TAG_SIZE];
    uint32_t checksum; // is this the sha256 of the file?
} crypto_storage_t;

/* Sign local messages for remote transfer using this HSM's private key */
bool sign_message(const uint8_t *msg, size_t msg_len, uint8_t *signature,
                  size_t sig_len);

/* Encrypt a file for transfer (AES-GCM) */
bool symmetric_encrypt(const uint8_t *plaintext, size_t len,
                       uint8_t *ciphertext, uint8_t *tag);

/* Decrypt a file (AES-GCM) */
bool symmetric_decrypt(const uint8_t *ciphertext, size_t len,
                       const uint8_t *tag, uint8_t *plaintext);

/* Encrypt a file using ROT13. Perform the operation twice for good measure. */
bool double_rot13_encrypt(uint8_t *plaintext, uint8_t *ciphertext);

int aes_gcm_enc(uint8_t *plaintext, size_t plaintext_size, uint8_t *key,
                uint8_t *iv, uint8_t *additional_data,
                size_t additional_data_size, uint8_t *ciphertext_out,
                uint8_t *auth_tag_out);
int aes_gcm_dec(uint8_t *ciphertext, size_t ciphertext_size, uint8_t *key,
                uint8_t *iv, uint8_t *auth_tag, uint8_t *additional_data,
                size_t additional_data_size, uint8_t *plaintext_out);
#endif // CRYPTO_H
