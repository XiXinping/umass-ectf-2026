#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define AES_GCM_TAG_SIZE 16
#define AES_GCM_IV_SIZE 12
#define AES_GCM_KEY_SIZE 32

typedef struct {
    uint32_t magic; // what is magic?
    uint8_t key[AES_GCM_KEY_SIZE];
    uint8_t last_iv[AES_GCM_IV_SIZE];
    uint8_t last_tag[AES_GCM_TAG_SIZE];
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
