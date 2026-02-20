#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/* Sign local messages for remote transfer using this HSM's private key */
bool sign_message(const uint8_t *msg, size_t msg_len, uint8_t *signature,
                  size_t sig_len);

/* Encrypt a file for transfer (AES-GCM) */
bool symmetric_encrypt(const uint8_t *plaintext, size_t len,
                       uint8_t *ciphertext, uint8_t *tag);

/* Decrypt a file (AES-GCM) */
bool symmetric_decrypt(const uint8_t *ciphertext, size_t len,
                       const uint8_t *tag, uint8_t *plaintext);
