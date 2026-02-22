#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

bool security_sign_message(const uint8_t *msg, size_t msg_len,
                           uint8_t *signature, size_t sig_len) {
    if (!security_is_authenticated())
        return false;
    if (msg == NULL || signature == NULL || sig_len == 0)
        return false;
    return ecc_sign_message(msg, msg_len, signature, sig_len);
}

/* -------------------- AES-GCM File Encryption / Decryption
 * -------------------- */

bool symmetric_encrypt(const uint8_t *plaintext, size_t len,
                       uint8_t *ciphertext, uint8_t *tag) {
    uint8_t ephemeral_iv[AES_GCM_IV_SIZE];

    if (!security_is_authenticated())
        return false;
    if (g_time_anomaly_detected)
        return false;
    if (plaintext == NULL || ciphertext == NULL || tag == NULL)
        return false;
    if (trng_generate(ephemeral_iv, AES_GCM_IV_SIZE) != 0) {
        secure_zero(ephemeral_iv, sizeof(ephemeral_iv));
        return false;
    }
    memcpy(g_crypto_data.last_iv, ephemeral_iv, AES_GCM_IV_SIZE);
    secure_zero(ephemeral_iv, sizeof(ephemeral_iv));
    if (!aes_gcm_encrypt(plaintext, len, ciphertext, tag))
        return false;
    memcpy(g_crypto_data.last_tag, tag, AES_GCM_TAG_SIZE);
    persist_crypto_state();
    return true;
}

bool symmetric_decrypt(const uint8_t *ciphertext, size_t len,
                       const uint8_t *tag, uint8_t *plaintext) {
    if (!security_is_authenticated())
        return false;
    if (g_time_anomaly_detected)
        return false;
    if (ciphertext == NULL || tag == NULL || plaintext == NULL)
        return false;
    memcpy(g_crypto_data.last_tag, tag, AES_GCM_TAG_SIZE);
    persist_crypto_state();
    return aes_gcm_decrypt(ciphertext, len, tag, plaintext);
}

bool double_rot13_encrypt(uint8_t *plaintext, uint8_t *ciphertext) {
    *ciphertext = *plaintext;
    return true;
}
