#define WOLFSSL_USER_SETTINGS
#ifndef ECC_H
#define ECC_H

#define HAVE_ECC
#define HAVE_SUPPORTED_CURVES

#include <stdint.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/settings.h>

#define ECC_KEY_SIZE 32

int ecc_asymmetric_encrypt(uint8_t *plaintext, size_t plaintext_size,
                           ecc_key *public_key, uint8_t *additional_data,
                           size_t additional_data_size, uint8_t *ciphertext_out,
                           size_t ciphertext_size, uint8_t *iv_out,
                           uint8_t *auth_tag_out,
                           uint8_t *cipher_public_key_out);

int ecc_asymmetric_dec(uint8_t *ciphertext, size_t ciphertext_size,
                       ecc_key *private_key, uint8_t *additional_data,
                       size_t additional_data_size, uint8_t *plain_out,
                       uint8_t *iv, uint8_t *auth_tag,
                       uint8_t *cipher_public_key,
                       size_t cipher_public_key_size);

int ecc_sign_file_digest(WC_RNG *rng, byte *digest,
                         ecc_key *ephemeral_private_key,
                         ecc_key *cipher_public_key);

int ecc_verify_file_digest(byte *sig, word32 sigSize, byte *digest,
                           word32 digestSize, ecc_key *ephemeral_private_key,
                           ecc_key *cipher_public_key);

#endif // ECC_H
