#include <stdint.h>

int aesgcm_enc(uint8_t* input, uint8_t* aad);

uint8_t* aesgcm_dec(uint8_t* ciphertext, uint8_t* aad);
