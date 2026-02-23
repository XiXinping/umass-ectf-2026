#include <stdint.h>
#include <stdlib.h>

int aes_gcm_enc(uint8_t *plaintext, size_t plaintext_size, uint8_t *key,
                uint8_t *iv, uint8_t *additional_data,
                size_t additional_data_size, uint8_t *ciphertext_out,
                uint8_t *auth_tag_out);
int aes_gcm_dec(uint8_t *ciphertext, size_t ciphertext_size, uint8_t *key,
                uint8_t *iv, uint8_t *auth_tag, uint8_t *additional_data,
                size_t additional_data_size, uint8_t *plaintext_out)
