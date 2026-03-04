#include "system.h"
#include "host_messaging.h"
#include "simple_crypto.h"
#include "simple_flash.h"

#include <stdio.h>
#include <string.h>

/* -------------------- Internal State -------------------- */

static pin_storage_t g_pin_data;
static bool g_authenticated = false;
static uint64_t g_session_expiration_ms = 0;
static uint64_t g_last_time_ms = 0;
static timestamp_storage_t g_time_data;
static crypto_storage_t g_crypto_data;

static bool g_time_anomaly_detected = false;

/* Platform hooks */
extern uint64_t platform_get_time_ms(void);
extern int trng_generate(uint8_t *buf, size_t len);

/* Flash addresses */
