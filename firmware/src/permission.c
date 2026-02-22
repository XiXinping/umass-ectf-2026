#include "permission.h"
#include "secrets.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

// Return of permission entry with the given group ID
static const group_permission_t *permission_entry(uint16_t group_id) {
    const group_permission_t *entry = &permissions[group_id];
    if (entry->group_id == group_id)
        return entry;

    // Linear search through the global permission list
    for (int i = 0; i < NUM_PERMS; i++) {
        if (permissions[i].group_id == group_id)
            return &permissions[i];
    }
    return NULL;
}
static const uint8_t *get_private_key(int group_id,
                                      permission_t permission_type) {
    const group_permission_t *entry = permission_entry(group_id);
    if (entry == NULL) {
        return NULL;
    }
    switch (permission_type) {
    case PERM_READ:
        // The HSM only has the private key if it has the given permission
        if (!entry->read_perm) {
            return NULL;
        }
        return entry->keys.read_keys.private_key;
    case PERM_WRITE:
        if (!entry->write_perm) {
            return NULL;
        }
        return entry->keys.write_keys.private_key;
    case PERM_RECEIVE:
        if (!entry->receive_perm) {
            return NULL;
        }
        return entry->keys.receive_keys.private_key;
    default:
        return NULL;
    };
}
static const uint8_t *get_public_key(int group_id,
                                     permission_t permission_type) {
    const group_permission_t *entry = permission_entry(group_id);
    if (entry == NULL) {
        return NULL;
    }
    switch (permission_type) {
    case PERM_READ:
        return entry->keys.read_keys.public_key;
    case PERM_WRITE:
        if (!entry->write_perm) {
            return NULL;
        }
        return entry->keys.write_keys.public_key;
    case PERM_RECEIVE:
        if (!entry->receive_perm) {
            return NULL;
        }
        return entry->keys.receive_keys.public_key;
    default:
        return false;
    };
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
static bool validate_permission(uint16_t group_id, permission_t perm) {
    if (!security_is_authenticated())
        return false;

    return permission_allowed(group_id, perm);
}

static bool verify_sender_identity(const uint8_t *msg, size_t msg_len,
                                   const uint8_t *signature, size_t sig_len) {
    if (msg == NULL || signature == NULL || sig_len == 0)
        return false;
    return ecc_verify_signature(msg, msg_len, signature, sig_len);
}

static bool verify_sender_permission(uint16_t sender_group,
                                     permission_enum_t action) {
    return permission_allowed(sender_group, action);
}

static bool verify_file_integrity(const uint8_t *file, size_t file_len,
                                  const uint8_t *tag) {
    if (file == NULL || tag == NULL)
        return false;
    return aes_gcm_verify(file, file_len, tag);
}

bool verify_remote_hsm(const uint8_t *msg, size_t msg_len,
                       const uint8_t *signature, size_t sig_len,
                       const uint8_t *file, size_t file_len, const uint8_t *tag,
                       uint16_t sender_group, permission_enum_t action) {
    if (!verify_sender_identity(msg, msg_len, signature, sig_len))
        return false;
    if (!verify_sender_permission(sender_group, action))
        return false;
    if (!verify_file_integrity(file, file_len, tag))
        return false;
    return true;
}
