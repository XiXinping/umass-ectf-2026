// Random number gen with TRNG seeding the PRNG with statistical guarantees

#include "ti_msp_dl_config.h"

#define NUM_CAPTURES (50)

volatile uint32_t gTRNGBuffer[NUM_CAPTURES];

int trng_gen(void)
{
    uint32_t i;
    SYSCFG_DL_init();

    /* Setup and start a capture, then wait for the result */
    for (i = 0; i < NUM_CAPTURES; i++) {
        DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_NORM_FUNC);
        while (!DL_TRNG_isCaptureReady(TRNG))
            ;
        gTRNGBuffer[i] = DL_TRNG_getCapture(TRNG);
    }

    /* Power off the peripheral */
    DL_TRNG_disablePower(TRNG);

    /* Set a SW breakpoint. Check gTRNGBuffer is filled with random numbers */
    __BKPT(0);

    while (1) {
        __WFI();
    }
}
