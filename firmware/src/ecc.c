#define WOLFSSL_USER_SETTINGS
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <stdint.h>
#include "aes_gcm.h"
#include "rand_gen.h"
// Need to fix function, reinitializing the rng
int ecc_asymmetric_encrypt(uint8_t *plaintext, size_t plaintext_size,
                           ecc_key *public_key, uint8_t *additional_data,
                           size_t additional_data_size, uint8_t *ciphertext_out,
                           size_t ciphertext_size, uint8_t *iv_out,
                           uint8_t *auth_tag_out,
                           uint8_t *cipher_public_key_out) {
    int ret;

    WC_RNG rng;
    byte ephemeral_priv_bytes[32];
    ecc_key ephemeral_priv_key;

    wc_InitRng(&rng);
    wc_ecc_init(&ephemeral_priv_key);
    if (wc_ecc_make_key(&rng, 32, &ephemeral_priv_key) != 0) {
        printf("Failed to generate ephemeral private key!");
        return -1;
    }

    /*
    if (wc_curve25519_import_private(ephemeral_priv_bytes,
                                     sizeof(ephemeral_priv_bytes),
                                     &ephemeral_priv_key) != 0) {
        printf("Failed to generate ephemeral private key!");
        return -1;
    };
    */

    byte secret_bytes[32];
    word32 secret_size = sizeof(secret_bytes);
    if (wc_ecc_shared_secret(&ephemeral_priv_key, public_key,
                                    secret_bytes,
                                    &secret_size) != 0) {
        printf("Failed to generate shared secret!");
        return -1;
    }

    byte symmetric_key[32];
    if (wc_X963_KDF(WC_HASH_TYPE_SHA256, secret_bytes, sizeof(secret_bytes),
                    NULL, 0, symmetric_key, sizeof(symmetric_key)) != 0) {
        printf("Failed to derive symmetric key!");
        return -1;
    }

    // byte cipher_public_key[32];
    if (wc_ecc_make_pub(&ephemeral_priv_key, NULL) != 0) {
        printf("Failed to create public key!");
        return -1;
    }

    byte cipher_public_key[32];
    word32 cipher_public_key_size = sizeof(cipher_public_key);

    if(wc_ecc_export_x963(&ephemeral_priv_key, cipher_public_key, &cipher_public_key_size) != 0) {
        printf("Failed to export public key!");
        return -1;
    }

    byte iv[GCM_NONCE_MID_SZ];
    gen_rand_block(&rng, iv, GCM_NONCE_MID_SZ); // Replace this call with gen_random_block

    if (aes_gcm_enc(plaintext, plaintext_size, symmetric_key, iv,
                        additional_data, additional_data_size,
                        ciphertext_out, auth_tag_out) != 0) {
        printf("Unable to encrypt with AES!");
        return -1;
    }
    return 0;
}

int ecc_asymmetric_dec(uint8_t *ciphertext, size_t ciphertext_size,
                           ecc_key *private_key, uint8_t *additional_data,
                           size_t additional_data_size, uint8_t *plain_out, uint8_t *iv,
                           uint8_t *auth_tag,
                           uint8_t *cipher_public_key, size_t cipher_public_key_size) {
    byte plain[ciphertext_size];

    ecc_key pub_key;

    if (wc_ecc_import_x963(cipher_public_key,
                                     cipher_public_key_size,
                                     &pub_key) != 0) {
        printf("Failed to generate ephemeral private key!");
        return -1;
    };

    byte secret_bytes[32];
    word32 secret_size = sizeof(secret_bytes);
    if (wc_ecc_shared_secret(private_key, &pub_key,
                                    secret_bytes,
                                    &secret_size) != 0) {
        printf("Failed to generate shared secret!");
        return -1;
    }

    byte symmetric_key[32];
    if (wc_X963_KDF(WC_HASH_TYPE_SHA256, secret_bytes, sizeof(secret_bytes),
                    NULL, 0, symmetric_key, sizeof(symmetric_key)) != 0) {
        printf("Failed to derive symmetric key!");
        return -1;
    }

    if(aes_gcm_dec(ciphertext, ciphertext_size, symmetric_key,
                iv, auth_tag, additional_data,
                additional_data_size, plain) != 0) {
            return -1;
    }

    return 0;




}

int ecc_sign_file_digest(WC_RNG *rng, byte *digest, ecc_key *ephemeral_private_key, ecc_key *cipher_public_key) {
    ecc_key signing_key;
    int ret;
    word32 sigSz;

    byte pub_key_bytes[32];
    word32 pub_size = sizeof(pub_size);
    if (wc_ecc_export_x963(cipher_public_key,
                                     pub_key_bytes,
                                     &pub_size) != 0) {
        printf("Failed to export public ecc key!");
        return -1;
    };  

    byte priv_key_bytes[32];
    word32 priv_size = sizeof(priv_size);
    if (wc_ecc_export_private_only(ephemeral_private_key,
                                     priv_key_bytes,
                                     &priv_size) != 0) {
        printf("Failed to export private ecc key!");
        return -1;
    };


    if (wc_ecc_import_private_key(priv_key_bytes, priv_size, pub_key_bytes, pub_size, &signing_key) != 0) {
        printf("Failed to import ECC key!");
        return -1;
    };


    byte sig[512]; // will hold generated signature
    sigSz = sizeof(sig);
    ret = wc_ecc_sign_hash(digest, sizeof(digest), sig, &sigSz, rng, &signing_key);
    if (ret != 0) {
        // error generating message signature
        printf("Failed to sign file digest!");
    }
    return 0;
}

int ecc_verify_file_digest(byte *sig, word32 sigSize, byte *digest, word32 digestSize, ecc_key *ephemeral_private_key, ecc_key *cipher_public_key) {

    ecc_key signing_key;
    int ret, verified = 0;


    byte pub_key_bytes[32];
    word32 pub_size = sizeof(pub_size);
    if (wc_ecc_export_x963(cipher_public_key,
                                     pub_key_bytes,
                                     &pub_size) != 0) {
        printf("Failed to export public ecc key!");
        return -1;
    };  

    byte priv_key_bytes[32];
    word32 priv_size = sizeof(priv_size);
    if (wc_ecc_export_private_only(ephemeral_private_key,
                                     priv_key_bytes,
                                     &priv_size) != 0) {
        printf("Failed to export private ecc key!");
        return -1;
    };

    if (wc_ecc_import_private_key(priv_key_bytes, priv_size, pub_key_bytes, pub_size, &signing_key) != 0) {
        printf("Failed to import ECC key!");
        return -1;
    };


    ret = wc_ecc_verify_hash(sig, sigSize, digest, digestSize,
                                 &verified, &signing_key);
    if (ret != 0) {
        printf("Failed to verify hash!");
    } else if (verified == 0) {
        printf("Signature is invalid!");
    }
}
