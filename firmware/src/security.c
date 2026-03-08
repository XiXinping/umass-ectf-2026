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
#include "security.h"
#include "host_messaging.h"
#include "permission.h"

/*
bool check_pin(unsigned char *pin) {
    print_debug("Checking PIN\n");

    // TODO: the reference design doesn't implement *ANY* security.
    // This function currently does nothing. Your team should add the
    // appropriate security checks here to implement the security
    // requirements.
    return true;
}

static const group_permission_t *permission_entry(uint16_t group_id) {
    if (group_id >= MAX_PERMS)
        return NULL;

    const group_permission_t *entry = &g_permissions[group_id];
    if (entry->group_id == group_id)
        return entry;

    for (int i = 0; i < MAX_PERMS; i++) {
        if (g_permissions[i].group_id == group_id)
            return &g_permissions[i];
    }
    return NULL;
}

static bool permission_allowed(uint16_t group_id, permission_t perm) {
    const group_permission_t *entry = permission_entry(group_id);
    if (entry == NULL)
        return false;

    switch (perm) {
    case PERM_READ:
        return entry->read_perm;
    case PERM_WRITE:
        return entry->write_perm;
    case PERM_RECEIVE:
        return entry->receive_perm;
    default:
        return false;
    }
}

void security_init(void) {
    uint64_t now;
    uint64_t tolerated_now;

    load_pin();
    load_permissions();
    load_timestamp_state();
    load_crypto_state();

    now = platform_get_time_ms();
    g_last_time_ms = now;

    if (!SECURITY_LOCK_CLOCK_CONFIG() || !SECURITY_IS_CLOCK_CONFIG_LOCKED()) {
        g_time_anomaly_detected = true;
        g_authenticated = false;
    }

    if (!pin_storage_valid(&g_pin_data)) {
        memset(&g_pin_data, 0, sizeof(g_pin_data));
        g_pin_data.magic = PIN_STORAGE_MAGIC;
        persist_pin();
    }

    if (!timestamp_storage_valid(&g_time_data)) {
        g_time_data.magic = TIMESTAMP_STORAGE_MAGIC;
        g_time_data.first_timestamp_ms = now;
        g_time_data.max_observed_timestamp_ms = now;
        persist_timestamp_state();
    } else {
        if (!checked_add_u64(now, TIMESTAMP_DRIFT_TOLERANCE_MS,
                             &tolerated_now)) {
            tolerated_now = UINT64_MAX;
        }
        if (tolerated_now < g_time_data.first_timestamp_ms ||
            tolerated_now < g_time_data.max_observed_timestamp_ms) {
            g_time_anomaly_detected = true;
            g_authenticated = false;
        } else if (now > g_time_data.max_observed_timestamp_ms) {
            g_time_data.max_observed_timestamp_ms = now;
            persist_timestamp_state();
        }
    }

    if (!crypto_storage_valid(&g_crypto_data)) {
        memset(&g_crypto_data, 0, sizeof(g_crypto_data));
        if (trng_generate(g_crypto_data.key, AES_GCM_KEY_SIZE) != 0) {
            g_time_anomaly_detected = true;
        }
        if (trng_generate(g_crypto_data.last_iv, AES_GCM_IV_SIZE) != 0) {
            g_time_anomaly_detected = true;
        }
        memset(g_crypto_data.last_tag, 0, AES_GCM_TAG_SIZE);
        persist_crypto_state();
    }

    if (g_time_anomaly_detected) {
        g_authenticated = false;
        g_pin_data.session_active = false;
        g_pin_data.session_expiration_ms = 0;
        persist_pin();
    } else if (g_pin_data.session_active) {
        g_authenticated = true;
        g_session_expiration_ms = g_pin_data.session_expiration_ms;
        if (!security_is_authenticated()) {
            g_pin_data.session_active = false;
            g_pin_data.session_expiration_ms = 0;
            persist_pin();
        }
    } else {
        g_authenticated = false;
        g_session_expiration_ms = 0;
    }
}
*/