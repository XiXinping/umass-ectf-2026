#ifndef RANDOM_H
#define RANDOM_H

#include <wolfssl/wolfcrypt/random.h>

#include <stdint.h>

int trng_gen_seed(uint8_t *output, int size);

int wc_GenerateSeed(OS_Seed *os, byte *output, word32 sz);

int PRNG_nonce(uint8_t *output);

int PRNG_block(uint8_t *output);

#endif // RANDOM_H
