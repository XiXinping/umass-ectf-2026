/* aesgcm-oneshot.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#define WOLFSSL_USER_SETTINGS
#include <wolfssl/wolfcrypt/settings.h>


#include "simple_flash.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/settings.h>

#define HAVE_AESGCM
// TODO: Buffer memsets to 0 after use

int aes_gcm_enc(uint8_t *plaintext, size_t plaintext_size, uint8_t *key,
                uint8_t *iv, uint8_t *additional_data,
                size_t additional_data_size, uint8_t *ciphertext_out,
                uint8_t *auth_tag_out) {
    Aes aes_enc;
    int ret = 0;
    unsigned char auth_tag[AES_BLOCK_SIZE];
    size_t i;

    memset(auth_tag, 0, sizeof(auth_tag));

    printf("Encrypt with AES256-GCM\n");
    /* Initialize AES encryption object. */
    ret = wc_AesInit(&aes_enc, NULL, INVALID_DEVID);
    if (ret == 0) {
        /* Set GCM key into AES encryption object. */
        ret = wc_AesGcmSetKey(&aes_enc, key, AES_256_KEY_SIZE);
        if (ret != 0)
            printf("Set Key failed: %d\n", ret);
    }
    if (ret == 0) {
        /* Encrypt data with AES encryption object and get ciphertext and
         * authentication tag. No additional authentication data. */
        ret = wc_AesGcmEncrypt(&aes_enc, ciphertext_out, plaintext,
                               plaintext_size, iv, GCM_NONCE_MID_SZ, auth_tag,
                               sizeof(auth_tag), additional_data,
                               additional_data_size);
        if (ret != 0)
            printf("Encrypt failed: %d\n", ret);
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
        printf("Decrypt with AES256-GCM\n");
        /* Initialize AES decryption object. */
        ret = wc_AesInit(&aesDec, NULL, INVALID_DEVID);
    }
    if (ret == 0) {
        /* Set GCM key into AES decryption object. */
        ret = wc_AesGcmSetKey(&aesDec, key, AES_256_KEY_SIZE);
        if (ret != 0)
            printf("Set Key failed: %d\n", ret);
    }
    if (ret == 0) {
        /* Check authentication tag with ciphertext and decrypt ciphertext with
         * AES decryption object and get decrypted data. No additional
         * authentication data. */
        ret = wc_AesGcmDecrypt(
            &aesDec, plaintext_out, ciphertext, ciphertext_size, iv, GCM_NONCE_MID_SZ,
            auth_tag, AES_BLOCK_SIZE, additional_data, additional_data_size); // size of auth_tag is 16 bytes
        if (ret == AES_GCM_AUTH_E)
            printf("Authentication failed: %d\n", ret);
        else if (ret != 0)
            printf("Decrypt failed: %d\n", ret);
    }
    if (ret == 0) {
        printf(" Decrypted: ");
        for (i = 0; i < ciphertext_size; i++)
            printf("%02x", plaintext_out[i]);
        printf("\n");
    }

    return ret;
}
