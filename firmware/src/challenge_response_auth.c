#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/ssl.h>
#include <wolfssl/test.h>

int send_challenge_nonce(WC_RNG *rng)
{
    byte output[32]; 
    gen_random_block(output, 32);
    

}

int sign_nonce(byte *nonce, ecc_key *ephemeral_private_key, ecc_key *cipher_public_key)
{
    ecc_key signing_key;
    int ret, sigSz;

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

    byte sig[512]; 
    sigSz = sizeof(sig);
    ret = wc_ecc_sign_hash(nonce, sizeof(nonce), sig, &sigSz, &signing_key);
    if (ret != 0) {
        // error generating message signature
        printf("Failed to sign challenge nonce!");
    }
    
}

int verify_nonce_sig(byte *sig, word32 sigSize, byte *nonce, word32 digestSize, ecc_key *ephemeral_private_key, ecc_key *cipher_public_key)
{
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


    ret = wc_ecc_verify_hash(sig, sigSize, nonce, digestSize,
                                 &verified, &signing_key);
    if (ret != 0) {
        printf("Failed to verify nonce!");
    } else if (verified == 0) {
        printf("Nonce signature is invalid!");
    }

    
}