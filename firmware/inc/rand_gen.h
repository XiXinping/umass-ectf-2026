#include <wolfssl/wolfcrypt/random.h>

#include <stdint.h>

int trng_gen_seed(uint8_t *output, int size);

int wc_GenerateSeed(OS_Seed *os, byte *output, word32 sz);

int init_random(WC_RNG *rng);

int free_random(WC_RNG *rng);

int gen_rand_block(WC_RNG *rng, uint8_t *output, size_t size);