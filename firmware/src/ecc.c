#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/ssl.h>
#include <wolfssl/test.h>

int ecc_asymmetric_encrypt(uint8_t *plaintext, size_t plaintext_size,
                           curve25519_key *public_key, uint8_t additional_data,
                           size_t additional_data_size, uint8_t *ciphertext_out,
                           size_t *ciphertext_size, uint8_t *iv_out,
                           uint8_t *auth_tag_out,
                           uint8_t *cipher_public_key_out) {
    byte out[sizeof(input)];
    word32 outSz = sizeof(out);
    // int public_key_ret;
    int ret;

    WC_RNG rng;
    byte ephemeral_priv_bytes[32];
    curve25519_key ephemeral_priv_key;

    wc_InitRng(&rng);
    if (wc_curve25519_make_priv(&rng, sizeof(ephemeral_priv_bytes),
                                ephemeral_priv_bytes) != 0) {
        printf("Failed to generate ephemeral private key!");
        return -1;
    }

    if (wc_curve25519_import_private(ephemeral_priv_bytes,
                                     sizeof(ephemeral_priv_bytes),
                                     &ephemeral_priv_key) != 0) {
        printf("Failed to generate ephemeral private key!");
        return -1;
    };

    byte secret_bytes[32];

    if (wc_curve25519_shared_secret(&ephemeral_priv_key, public_key,
                                    secret_bytes,
                                    (word32 *)sizeof(secret_bytes)) != 0) {
        printf("Failed to generate shared secret!");
        return -1;
    }

    byte symmetric_key[32];
    if (wc_X963_KDF(WC_HASH_TYPE_SHA256, secret_bytes, sizeof(secret_bytes),
                    NULL, symmetric_key, sizeof(symmetric_key)) != 0) {
        printf("Failed to derive symmetric key!");
        return -1;
    }

    byte cipher_public_key[32];
    if (wc_curve25519_make_pub(sizeof(cipher_public_key), cipher_public_key,
                               sizeof(ephemeral_priv_bytes),
                               ephemeral_priv_bytes) != 0) {
        printf("Ate shit and died");
        return -1;
    }
    byte iv[GCM_NONCE_MID_SZ];
    gen_random(iv, GCM_NONCE_MID_SZ);

    if (aes_gcm_encrypt(plaintext, plaintext_size, symmetric_key, iv,
                        auth_tag_out, additional_data, additional_data_size,
                        ciphertext_out, auth_tag_out) != 0) {
        printf("Unable to encrypt with AES!");
        return -1;
    }
    return 0;
}

uint8_t *ecc_asymmetric_dec(uint8_t *ciphertext, size_t ciphertext_size,
                           curve25519_key *private_key, uint8_t additional_data,
                           size_t additional_data_size, uint8_t *plain_out,
                           size_t *plaintext_size, uint8_t *iv,
                           uint8_t *auth_tag,
                           uint8_t *cipher_public_key, size_t cipher_public_key_size) {
    byte plain[ciphertext_size];

    curve25519_key pub_key;

    if (wc_curve25519_import_public(cipher_public_key,
                                     cipher_public_key_size,
                                     &pub_key) != 0) {
        printf("Failed to generate ephemeral private key!");
        return -1;
    };

    byte secret_bytes[32];

    if (wc_curve25519_shared_secret(private_key, pub_key,
                                    secret_bytes,
                                    (word32 *)sizeof(secret_bytes)) != 0) {
        printf("Failed to generate shared secret!");
        return -1;
    }

    byte symmetric_key[32];
    if (wc_X963_KDF(WC_HASH_TYPE_SHA256, secret_bytes, sizeof(secret_bytes),
                    NULL, symmetric_key, sizeof(symmetric_key)) != 0) {
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

int ecc_sign_file_digest() {
    ecc_key key;
    WC_RNG rng;
    int ret, sigSz;

    byte sig[512]; // will hold generated signature
    sigSz = sizeof(sig);
    byte digest[] = {};              // initialize with message hash };
    wc_InitRng(&rng);                // initialize rng
    wc_ecc_init(&key);               // initialize key
    wc_ecc_make_key(&rng, 32, &key); // make public/private key pair
    ret = wc_ecc_sign_hash(digest, sizeof(digest), sig, &sigSz, &key);
    if (ret != 0) {
        // error generating message signature
    }
}

int ecc_verify_file_digest() {

    ecc_key key;
    int ret, verified = 0;

    byte sig[1024];   // initialize with received signature };
    byte digest[] = { // initialize with message hash };
        // initialize key with received public key
        ret = wc_ecc_verify_hash(sig, sizeof(sig), digest, sizeof(digest),
                                 &verified, &key);
    if (ret != 0) {
        // error performing verification
    } else if (verified == 0) {
        // the signature is invalid
    }
}
