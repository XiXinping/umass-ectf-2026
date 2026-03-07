// Random number gen with TRNG seeding the PRNG with statistical guarantees

#include "ti_msp_dl_config.h"
#include <wolfssl/wolfcrypt/random.h>

#define NO_DEV_RANDOM

// #define NUM_CAPTURES (8)

// volatile uint32_t gTRNGBuffer[NUM_CAPTURES];

#define CUSTOM_RAND_GENERATE_SEED trng_gen_seed

int trng_gen_seed(uint8_t *output, int size) {
    uint32_t i;
    // SYSCFG_DL_init();

    /* Setup and start a capture, then wait for the result */
    for (i = 0; i < size;) {
        DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_NORM_FUNC);
        while (!DL_TRNG_isCaptureReady(TRNG))
            ;
        uint32_t word = DL_TRNG_getCapture(TRNG);

        for (int j = 0; j < 4 && i < size; j++) {
            output[i++] = (uint8_t)(word >> (j * 8));
        }
    }

    /* Power off the peripheral */
    DL_TRNG_disablePower(TRNG);

    /* Set a SW breakpoint. Check gTRNGBuffer is filled with random numbers */
    //__BKPT(0);
    /*
        while (1) {
            __WFI();
        }
        */
}

int wc_GenerateSeed(OS_Seed *os, byte *output, word32 sz) {
    (void)os; /* Suppress unused arg warning */
    return CUSTOM_RAND_GENERATE_SEED(output, sz);
}

int init_random(WC_RNG *rng) {
    int ret = wc_InitRng(rng);
    if (ret != 0) {
        printf("RNG init failed");
        return -1;
    }
    return 0
}

int free_random(WC_RNG *rng) {
    ret = wc_FreeRng(rng);
    if (ret != 0) {
        printf("Failed to free RNG");
        return -1;
    }
    return 0
}

int gen_random_block(WC_RNG *rng, uint8_t *output, size_t size) {
    
    ret = wc_RNG_GenerateBlock(rng, output, size);
    if (ret != 0) {
        printf("Generating block failed");
        return -1;
    }
    return 0;
}

int gen_random_block(WC_RNG *rng, uint8_t *output, size_t size) {
    
    ret = wc_RNG_GenerateBlock(rng, output, size);
    if (ret != 0) {
        printf("Generating block failed");
        return -1;
    }
    return 0;
}

// Generates a specified number of random bytes using WolfCrypt's PRNG seeded
// by the hardware TRNG.
int gen_random(uint8_t *output, size_t size) {
    WC_RNG rng;
    // uint8_t nonce[32];
    // CUSTOM_RAND_GENERATE_SEED(nonce, sizeof(nonce));
    // int ret = wc_InitRngNonce(&rng, nonce, sizeof(nonce));
    int ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("RNG init failed");
        return -1;
    }
    ret = wc_RNG_GenerateBlock(&rng, output, size);
    if (ret != 0) {
        printf("Generating block failed");
        return -2;
    }

    ret = wc_FreeRng(&rng);
    if (ret != 0) {
        printf("Failed to free RNG");
        return -3;
    }

    return 0;
}
