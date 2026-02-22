#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>

#include <wolfssl/ssl.h>
#include <wolfssl/test.h>



int ecc_asymmetric_enc(uint8_t* input, uint8_t* public_key) // Takes in public key of recepient, and encrypts it

{
    byte out[sizeof(input)];
    word32 outSz = sizeof(out);
    // int public_key_ret;
    int ret;
    int curve_ret;

    WC_RNG rng;
    byte priv[1];

    wc_InitRng(&rng);
    int curve_ret = wc_curve25519_make_priv(&rng, sizeof(priv), priv);
    if (curve_ret != 0) {
        // error generating private key
    }


    byte cipherPrivKey[] = {  };
    byte pubKey[] = {  };
    byte secret[1024]; // can hold 1024 byte shared secret key
    word32 secretSz = sizeof(secret);


    int shared_secret = wc_ecc_shared_secret(cipherPrivKey, pubKey, secret, secretSz);
    // ecc_key key;
    //wc_ecc_init(&key);

   // key_ret = wc_ecc_import_private_key(priv, sizeof(priv), pub, sizeof(pub), &key);

    if (private_key_ret != 0) {
        // error importing key
    }

    ecc_key cli, serv;
    
    
    // initialize cli with private key
    // initialize serv with received public key

    ecEncCtx* cliCtx, servCtx;
    // initialize cliCtx and servCtx
    // exchange salts
    ret = wc_ecc_encrypt(&cli, &serv, input, sizeof(input), out, &outSz, cliCtx,
        1);
}

uint8_t* ecc_asymmetric_dec(uint8_t* ciphertext)
{
    byte plain[sizeof(ciphertext)];
    word32 plainSz = sizeof(plain);
    int ret;
    ecc_key cli, serv;
    // initialize cli with private key
    // initialize serv with received public key
    ecEncCtx* cliCtx, servCtx;
    // initialize cliCtx and servCtx
    // exchange salts
    ret = wc_ecc_decrypt(&cli, &serv, ciphertext, sizeof(ciphertext),
    plain, &plainSz, cliCtx);

    if(ret != 0) {
        // error decrypting message
    }
}

int ecc_sign_file_digest() {
    ecc_key key;
    WC_RNG rng;
    int ret, sigSz;

    byte sig[512]; // will hold generated signature
    sigSz = sizeof(sig);
    byte digest[] = { };// initialize with message hash };
    wc_InitRng(&rng); // initialize rng
    wc_ecc_init(&key); // initialize key
    wc_ecc_make_key(&rng, 32, &key); // make public/private key pair
    ret = wc_ecc_sign_hash(digest, sizeof(digest), sig, &sigSz, &key);
    if ( ret != 0 ) {
        // error generating message signature
    }
}

int ecc_verify_file_digest() {

    ecc_key key;
    int ret, verified = 0;

    byte sig[1024]; //initialize with received signature };
    byte digest[] = { // initialize with message hash };
    // initialize key with received public key
    ret = wc_ecc_verify_hash(sig, sizeof(sig), digest, sizeof(digest), &verified, &key);
    if ( ret != 0 ) {
        // error performing verification
    } else if ( verified == 0 ) {
        // the signature is invalid
    }

}