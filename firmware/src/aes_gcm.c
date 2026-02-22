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


#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/aes.h>
#include "simple_flash.h"

// TODO: Buffer memsets to 0 after use

int aesgcm_enc(uint8_t* input, uint8_t* aad)
{
    Aes           aesEnc;
    //Aes           aesDec;
    unsigned char key[AES_256_KEY_SIZE];
    int           ret = 0;
    // unsigned char dec[33];
    unsigned char iv[GCM_NONCE_MID_SZ];
    unsigned char authTag[AES_BLOCK_SIZE];
    size_t        i;

    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv)); 
    memset(authTag, 0, sizeof(authTag)); 

    PRNG_block(key);
    PRNG_block(iv);

    fprintf(stderr, "Encrypt with AES128-GCM\n");
    /* Initialize AES encryption object. */
    ret = wc_AesInit(&aesEnc, NULL, INVALID_DEVID);
    if (ret == 0) {
        /* Set GCM key into AES encryption object. */
        ret = wc_AesGcmSetKey(&aesEnc, key, AES_128_KEY_SIZE);
        if (ret != 0)
            fprintf(stderr, "Set Key failed: %d\n", ret);
    }
    if (ret == 0) {
        /* Encrypt data with AES encryption object and get ciphertext and
         * authentication tag. No additional authentication data. */
        ret = wc_AesGcmEncrypt(&aesEnc, input, input, sizeof(input), iv, sizeof(iv),
                               authTag, sizeof(authTag), aad, 0);  // TODO: encrypt using another buffer
        if (ret != 0)
            fprintf(stderr, "Encrypt failed: %d\n", ret);
    }
    if (ret == 0) {
        printf("Ciphertext: ");
        for (i = 0; i < sizeof(input); i++)
            printf("%02x", input[i]);
        printf("\n");
        printf("  Auth Tag: ");
        for (i = 0; i < sizeof(authTag); i++)
            printf("%02x", authTag[i]);
        printf("\n");
    }
    // asymmetric encryption with loaded in key from flash
    
    flash_simple_write(0, key, sizeof(key));
    flash_simple_write(1, iv, sizeof(iv));
    flash_simple_write(2, authTag, sizeof(authTag));

    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv)); 
    memset(authTag, 0, sizeof(authTag)); 
    return ret;
}

uint8_t* aesgcm_enc_output(uint8_t* input, uint8_t* aad)
{
    Aes           aesEnc;
    //Aes           aesDec;
    unsigned char key[AES_256_KEY_SIZE];
    int           ret = 0;
    // unsigned char dec[33];
    unsigned char iv[GCM_NONCE_MID_SZ];
    unsigned char authTag[AES_BLOCK_SIZE];
    size_t        i;

    uint8_t* output[sizeof(input)];

    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv)); 
    memset(authTag, 0, sizeof(authTag)); 
    memset(output, 0, size(output));

    PRNG_block(key);
    PRNG_block(iv);

    fprintf(stderr, "Encrypt with AES128-GCM\n");
    /* Initialize AES encryption object. */
    ret = wc_AesInit(&aesEnc, NULL, INVALID_DEVID);
    if (ret == 0) {
        /* Set GCM key into AES encryption object. */
        ret = wc_AesGcmSetKey(&aesEnc, key, AES_128_KEY_SIZE);
        if (ret != 0)
            fprintf(stderr, "Set Key failed: %d\n", ret);
    }
    if (ret == 0) {
        /* Encrypt data with AES encryption object and get ciphertext and
         * authentication tag. No additional authentication data. */
        ret = wc_AesGcmEncrypt(&aesEnc, output, input, sizeof(input), iv, sizeof(iv),
                               authTag, sizeof(authTag), aad, 0);  // TODO: encrypt using another buffer
        if (ret != 0)
            fprintf(stderr, "Encrypt failed: %d\n", ret);
    }
    if (ret == 0) {
        printf("Ciphertext: ");
        for (i = 0; i < sizeof(input); i++)
            printf("%02x", input[i]);
        printf("\n");
        printf("  Auth Tag: ");
        for (i = 0; i < sizeof(authTag); i++)
            printf("%02x", authTag[i]);
        printf("\n");
    }

    flash_simple_write(0, key, sizeof(key));
    flash_simple_write(1, iv, sizeof(iv));
    flash_simple_write(2, authTag, sizeof(authTag));

    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv)); 
    memset(authTag, 0, sizeof(authTag)); 
    return ret;
}

uint8_t* aesgcm_dec(uint8_t* ciphertext, uint8_t* aad) // TODO: pass dec buffer to this method 
{
    Aes           aesDec;
    unsigned char key[AES_256_KEY_SIZE];
    int           ret = 0;
    uint8_t dec[sizeof(ciphertext)];
    unsigned char iv[GCM_NONCE_MID_SZ]; 
    unsigned char authTag[AES_BLOCK_SIZE]; 
    size_t        i;
    uint8_t* dec[sizeof(ciphertext)];

    memset(key, 0, sizeof(key)); 
    memset(iv, 0, sizeof(iv)); 
    memset(authTag, 0, sizeof(authTag)); 
    memset(dec, 0, sizeof(dec)); 


    flash_simple_read(0, key, sizeof(key));
    flash_simple_read(1, iv, sizeof(iv));
    flash_simple_read(2, authTag, sizeof(authTag));

    if (ret == 0) {
        fprintf(stderr, "Decrypt with AES128-GCM\n");
        /* Initialize AES decryption object. */
        ret = wc_AesInit(&aesDec, NULL, INVALID_DEVID);
    }
    if (ret == 0) {
        /* Set GCM key into AES decryption object. */
        ret = wc_AesGcmSetKey(&aesDec, key, AES_128_KEY_SIZE);
        if (ret != 0)
            fprintf(stderr, "Set Key failed: %d\n", ret);
    }
    if (ret == 0) {
        /* Check authentication tag with ciphertext and decrypt ciphertext with
         * AES decryption object and get decrypted data. No additional
         * authentication data. */
        ret = wc_AesGcmDecrypt(&aesDec, dec, ciphertext, sizeof(ciphertext), iv, sizeof(iv),
                               authTag, sizeof(authTag), aad, 0); 
        if (ret == AES_GCM_AUTH_E)
            fprintf(stderr, "Authentication failed: %d\n", ret);
        else if (ret != 0)
            fprintf(stderr, "Decrypt failed: %d\n", ret);
    }
    if (ret == 0) {
        printf(" Decrypted: ");
        for (i = 0; i < sizeof(ciphertext); i++)
            printf("%02x", dec[i]);
        printf("\n");
    }

    memset(key, 0, sizeof(key)); 
    memset(iv, 0, sizeof(iv)); 
    memset(authTag, 0, sizeof(authTag)); 

    return dec; 
    //memset(dec, 0, sizeof(dec));


}

uint8_t* aesgcm_dec_output(uint8_t* ciphertext, uint8_t* aad) // TODO: pass dec buffer to this method 
{
    Aes           aesDec;
    unsigned char key[AES_256_KEY_SIZE];
    int           ret = 0;
    uint8_t dec[sizeof(ciphertext)];
    unsigned char iv[GCM_NONCE_MID_SZ]; 
    unsigned char authTag[AES_BLOCK_SIZE]; 
    size_t        i;
    uint8_t* dec[sizeof(ciphertext)];

    memset(key, 0, sizeof(key)); 
    memset(iv, 0, sizeof(iv)); 
    memset(authTag, 0, sizeof(authTag)); 
    memset(dec, 0, sizeof(dec)); 

    flash_simple_read(0, key, sizeof(key));
    flash_simple_read(1, iv, sizeof(iv));
    flash_simple_read(2, authTag, sizeof(authTag));

    if (ret == 0) {
        fprintf(stderr, "Decrypt with AES128-GCM\n");
        /* Initialize AES decryption object. */
        ret = wc_AesInit(&aesDec, NULL, INVALID_DEVID);
    }
    if (ret == 0) {
        /* Set GCM key into AES decryption object. */
        ret = wc_AesGcmSetKey(&aesDec, key, AES_128_KEY_SIZE);
        if (ret != 0)
            fprintf(stderr, "Set Key failed: %d\n", ret);
    }
    if (ret == 0) {
        /* Check authentication tag with ciphertext and decrypt ciphertext with
         * AES decryption object and get decrypted data. No additional
         * authentication data. */
        ret = wc_AesGcmDecrypt(&aesDec, dec, ciphertext, sizeof(ciphertext), iv, sizeof(iv),
                               authTag, sizeof(authTag), aad, 0); 
        if (ret == AES_GCM_AUTH_E)
            fprintf(stderr, "Authentication failed: %d\n", ret);
        else if (ret != 0)
            fprintf(stderr, "Decrypt failed: %d\n", ret);
    }
    if (ret == 0) {
        printf(" Decrypted: ");
        for (i = 0; i < sizeof(ciphertext); i++)
            printf("%02x", dec[i]);
        printf("\n");
    }

    memset(key, 0, sizeof(key)); 
    memset(iv, 0, sizeof(iv)); 
    memset(authTag, 0, sizeof(authTag)); 
    

    return dec; 
    //memset(dec, 0, sizeof(dec));


}