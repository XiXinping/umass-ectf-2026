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

bool check_pin(unsigned char *pin) {
    print_debug("Checking PIN\n");

    // TODO: the reference design doesn't implement *ANY* security.
    // This function currently does nothing. Your team should add the
    // appropriate security checks here to implement the security
    // requirements.
    return true;
}

bool validate_permission(uint16_t group_id, permission_enum_t perm) {
    char output_buf[128] = {0};

    sprintf(output_buf, "Checking %c permissions for group: %hx\n", perm,
            group_id);
    print_debug(output_buf);

    // TODO: the reference design doesn't implement *ANY* security.
    // This function currently does nothing. Your team should add the
    // appropriate security checks here to implement the security
    // requirements.
    return true;
}

static const group_permission_t *permission_entry(uint16_t group_id) {
    if (group_id >= MAX_PERMS) return NULL;

    const group_permission_t *entry = &g_permissions[group_id];
    if (entry->group_id == group_id) return entry;

    for (int i = 0; i < MAX_PERMS; i++) {
        if (g_permissions[i].group_id == group_id) return &g_permissions[i];
    }
    return NULL;
}

static bool permission_allowed(uint16_t group_id, permission_enum_t perm) {
    const group_permission_t *entry = permission_entry(group_id);
    if (entry == NULL) return false;

    switch (perm) {
        case PERM_READ: return entry->read;
        case PERM_WRITE: return entry->write;
        case PERM_RECEIVE: return entry->receive;
        default: return false;
    }
}

