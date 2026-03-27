 #define WOLFSSL_USER_SETTINGS
#define HAVE_ECC
#define HAVE_SUPPORTED_CURVES
#include <wolfssl/wolfcrypt/settings.h>

#include "crypto.h"
#include "random.h"
#include <stdint.h>
#include <wolfssl/wolfcrypt/aes.h>
// #include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
int main() {
    uint8_t i_have_a_dream[256] =
        "I am happy to join with you today in what will go down in history as "
        "the greatest demonstration for freedom in the history of our nation. "
        "Five score years ago, a great American, in whose symbolic shadow we "
        "stand today, signed the Emancipation Proclamation";

    uint8_t aes_key[32] = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
                           11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                           22, 23, 24, 25, 26, 27, 28, 29, 30, 31};

    uint8_t iv_out*;
    
    
    uint8_t i_have_a_dream_enc[256];
    uint8_t auth_tag[16];
    uint8_t *cipher_public_key_out;

    ecc_asymmetric_encrypt(i_have_a_dream, 256, aes_key, NULL, 0,
                    i_have_a_dream_enc, 256, iv_out, auth_tag, cipher_public_key_out);  

    uint8_t *plain_out;
                    
    ecc_asymmetric_dec(i_have_a_dream_enc, 256,
                       aes_key, NULL,
                       0, plain_out,
                       iv_out, auth_tag,
                       cipher_public_key_out,
                       256);

    
}