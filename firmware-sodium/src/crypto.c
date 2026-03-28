#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "crypto.h"
#include "ecc.h"
#include "simple_flash.h"

static bool sodium_initialized = false;

static int ensure_sodium_initialized(void) {
    if (!sodium_initialized) {
        if (sodium_init() < 0)
            return -1;
        sodium_initialized = true;
    }
    return 0;
}

bool security_sign_message(const uint8_t *msg, size_t msg_len,
                           uint8_t *signature, size_t sig_len) {
    // if (!security_is_authenticated())
    //     return false;
    if (msg == NULL || signature == NULL || sig_len == 0)
        return false;
    return ecc_sign_message(msg, msg_len, signature, sig_len);
}

bool double_rot13_encrypt(uint8_t *plaintext, uint8_t *ciphertext) {
    *ciphertext = *plaintext;
    return true;
}

int aes_gcm_encrypt(uint8_t *plaintext, size_t plaintext_size, uint8_t *key,
                    uint8_t *iv, uint8_t *additional_data,
                    size_t additional_data_size, uint8_t *ciphertext_out,
                    uint8_t *auth_tag_out) {
    unsigned long long mac_len = 0;

    if (plaintext == NULL || key == NULL || iv == NULL || ciphertext_out == NULL ||
        auth_tag_out == NULL)
        return -1;

    if (ensure_sodium_initialized() != 0)
        return -1;

    if (crypto_aead_chacha20poly1305_ietf_encrypt_detached(
            ciphertext_out, auth_tag_out, &mac_len, plaintext, plaintext_size,
            additional_data, additional_data_size, NULL, iv, key) != 0)
        return -1;

    return (mac_len == AUTH_TAG_SIZE) ? 0 : -1;
}

int aes_gcm_decrypt(uint8_t *ciphertext, size_t ciphertext_size, uint8_t *key,
                    uint8_t *iv, uint8_t *auth_tag, uint8_t *additional_data,
                    size_t additional_data_size, uint8_t *plaintext_out) {
    if (ciphertext == NULL || key == NULL || iv == NULL || auth_tag == NULL ||
        plaintext_out == NULL)
        return -1;

    if (ensure_sodium_initialized() != 0)
        return -1;

    if (crypto_aead_chacha20poly1305_ietf_decrypt_detached(
            plaintext_out, NULL, ciphertext, ciphertext_size, auth_tag,
            additional_data, additional_data_size, iv, key) != 0)
        return -1;

    return 0;
}
