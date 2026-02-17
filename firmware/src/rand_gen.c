// Random number gen with TRNG seeding the PRNG with statistical guarantees

#include "ti_msp_dl_config.h"
#include <wolfssl/wolfcrypt/random.h>

#define NO_DEV_RANDOM

// #define NUM_CAPTURES (8)

//volatile uint32_t gTRNGBuffer[NUM_CAPTURES];

#define CUSTOM_RAND_GENERATE_SEED trng_gen_seed

int trng_gen_seed(uint8_t* output, int size)
{
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

int wc_GenerateSeed(OS_Seed* os, byte* output, word32 sz)
{
        (void)os; /* Suppress unused arg warning */
        return CUSTOM_RAND_GENERATE_SEED(output, sz);
}

int PRNG_nonce(uint8_t* output)
{
    WC_RNG rng;
    byte nonce[12];
    int ret = wc_InitRngNonce(&rng, output, sizeof(output));
    if (ret != 0){
        printf(“RNG init failed”);
        return -1;
    }

    int ret = wc_FreeRng(&rng);
    if (ret != 0) {
        return -1; //free of rng failed!
    }

    return 0;
}

int PRNG_block(uint8_t* output)
{
    RNG  rng;

    int ret = wc_InitRng(&rng);
    if (ret != 0) {
        return -1; //init of rng failed!
    }

    ret = wc_RNG_GenerateBlock(&rng, output, sizeof(output));
    if (ret != 0) {
        return -1; //generating block failed!
    }

    int ret = wc_FreeRng(&rng);
    if (ret != 0) {
        return -1; //free of rng failed!
    }

    return 0;
}

