/**
 * @file security.c
 * @author Samuel Meyers
 * @brief Stub file to hold security checks
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF
 * (eCTF). This code is being provided only for educational purposes for the
 * 2026 MITRE eCTF competition, and may not meet MITRE standards for quality.
 * Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#define WOLFSSL_USER_SETTINGS
#include "authentication.h"
#include "crypto.h"
#include "host_messaging.h"
#include "permission.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

bool check_pin(unsigned char *pin) {
    print_debug("Checking PIN\n");

    // TODO: the reference design doesn't implement *ANY* security.
    // This function currently does nothing. Your team should add the
    // appropriate security checks here to implement the security
    // requirements.
    return true;
}
extern pin_storage_t g_pin_data;
extern bool g_authenticated;
extern uint64_t g_session_expiration_ms;
extern uint64_t g_last_time_ms;
extern timestamp_storage_t g_time_data;
extern crypto_storage_t g_crypto_data;
extern bool g_time_anomaly_detected;

// void security_init(void) {
//     uint64_t now;
//     uint64_t tolerated_now;
//
//     load_pin();
//     // load_permissions();
//     load_timestamp_state();
//     load_crypto_state();
//
//     now = platform_get_time_ms();
//     g_last_time_ms = now;
//
//     if (!SECURITY_LOCK_CLOCK_CONFIG() || !SECURITY_IS_CLOCK_CONFIG_LOCKED())
//     {
//         g_time_anomaly_detected = true;
//         g_authenticated = false;
//     }
//
//     if (!pin_storage_valid(&g_pin_data)) {
//         memset(&g_pin_data, 0, sizeof(g_pin_data));
//         g_pin_data.magic = PIN_STORAGE_MAGIC;
//         persist_pin();
//     }
//
//     if (!timestamp_storage_valid(&g_time_data)) {
//         g_time_data.magic = TIMESTAMP_STORAGE_MAGIC;
//         g_time_data.first_timestamp_ms = now;
//         g_time_data.max_observed_timestamp_ms = now;
//         persist_timestamp_state();
//     } else {
//         if (!checked_add_u64(now, TIMESTAMP_DRIFT_TOLERANCE_MS,
//                              &tolerated_now)) {
//             tolerated_now = UINT64_MAX;
//         }
//         if (tolerated_now < g_time_data.first_timestamp_ms ||
//             tolerated_now < g_time_data.max_observed_timestamp_ms) {
//             g_time_anomaly_detected = true;
//             g_authenticated = false;
//         } else if (now > g_time_data.max_observed_timestamp_ms) {
//             g_time_data.max_observed_timestamp_ms = now;
//             persist_timestamp_state();
//         }
//     }
//
//     if (!crypto_storage_valid(&g_crypto_data)) {
//         memset(&g_crypto_data, 0, sizeof(g_crypto_data));
//         if (trng_generate(g_crypto_data.key, AES_KEY_SIZE) != 0) {
//             g_time_anomaly_detected = true;
//         }
//         if (trng_generate(g_crypto_data.last_iv, AES_IV_SIZE) != 0) {
//             g_time_anomaly_detected = true;
//         }
//         memset(g_crypto_data.last_tag, 0, AUTH_TAG_SIZE);
//         persist_crypto_state();
//     }
//
//     if (g_time_anomaly_detected) {
//         g_authenticated = false;
//         g_pin_data.session_active = false;
//         g_pin_data.session_expiration_ms = 0;
//         persist_pin();
//     } else if (g_pin_data.session_active) {
//         g_authenticated = true;
//         g_session_expiration_ms = g_pin_data.session_expiration_ms;
//         if (!security_is_authenticated()) {
//             g_pin_data.session_active = false;
//             g_pin_data.session_expiration_ms = 0;
//             persist_pin();
//         }
//     } else {
//         g_authenticated = false;
//         g_session_expiration_ms = 0;
//     }
// }
