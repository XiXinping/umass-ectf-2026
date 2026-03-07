#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "simple_flash.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/settings.h>

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

int aes_gcm_enc(uint8_t *plaintext, size_t plaintext_size, uint8_t *key,
                uint8_t *iv, uint8_t *additional_data,
                size_t additional_data_size, uint8_t *ciphertext_out,
                uint8_t *auth_tag_out) {
    Aes aes_enc;
    int ret = 0;
    unsigned char auth_tag[AES_BLOCK_SIZE];
    size_t i;

    memset(auth_tag, 0, sizeof(auth_tag));

    fprintf(stderr, "Encrypt with AES256-GCM\n");
    /* Initialize AES encryption object. */
    ret = wc_AesInit(&aes_enc, NULL, INVALID_DEVID);
    if (ret == 0) {
        /* Set GCM key into AES encryption object. */
        ret = wc_AesGcmSetKey(&aes_enc, key, AES_256_KEY_SIZE);
        if (ret != 0)
            fprintf(stderr, "Set Key failed: %d\n", ret);
    }
    if (ret == 0) {
        /* Encrypt data with AES encryption object and get ciphertext and
         * authentication tag. No additional authentication data. */
        ret = wc_AesGcmEncrypt(&aes_enc, ciphertext_out, plaintext,
                               plaintext_size, iv, GCM_NONCE_MID_SZ, auth_tag,
                               sizeof(auth_tag), additional_data,
                               additional_data_size);
        if (ret != 0)
            fprintf(stderr, "Encrypt failed: %d\n", ret);
    }
    if (ret == 0) {
        printf("Ciphertext: ");
        for (i = 0; i < sizeof(plaintext); i++)
            printf("%02x", plaintext[i]);
        printf("\n");
        printf("  Auth Tag: ");
        for (i = 0; i < sizeof(auth_tag); i++)
            printf("%02x", auth_tag[i]);
        printf("\n");
    }

    return ret;
}

int aes_gcm_dec(uint8_t *ciphertext, size_t ciphertext_size, uint8_t *key,
                uint8_t *iv, uint8_t *auth_tag, uint8_t *additional_data,
                size_t additional_data_size, uint8_t *plaintext_out) {
    Aes aesDec;
    int ret = 0;
    size_t i;

    if (ret == 0) {
        fprintf(stderr, "Decrypt with AES256-GCM\n");
        /* Initialize AES decryption object. */
        ret = wc_AesInit(&aesDec, NULL, INVALID_DEVID);
    }
    if (ret == 0) {
        /* Set GCM key into AES decryption object. */
        ret = wc_AesGcmSetKey(&aesDec, key, AES_256_KEY_SIZE);
        if (ret != 0)
            fprintf(stderr, "Set Key failed: %d\n", ret);
    }
    if (ret == 0) {
        /* Check authentication tag with ciphertext and decrypt ciphertext with
         * AES decryption object and get decrypted data. No additional
         * authentication data. */
        ret = wc_AesGcmDecrypt(
            &aesDec, plaintext_out, ciphertext, ciphertext_size, iv,
            GCM_NONCE_MID_SZ, auth_tag, AES_BLOCK_SIZE, additional_data,
            additional_data_size); // size of auth_tag is 16 bytes
        if (ret == AES_GCM_AUTH_E)
            fprintf(stderr, "Authentication failed: %d\n", ret);
        else if (ret != 0)
            fprintf(stderr, "Decrypt failed: %d\n", ret);
    }
    if (ret == 0) {
        printf(" Decrypted: ");
        for (i = 0; i < ciphertext_size; i++)
            printf("%02x", plaintext_out[i]);
        printf("\n");
    }

    return ret;
}
