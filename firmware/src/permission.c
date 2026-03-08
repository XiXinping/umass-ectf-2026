#define WOLFSSL_USER_SETTINGS

#include "permission.h"
#include "secrets.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include <wolfssl/wolfcrypt/ecc.h>
/*
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
int get_private_key(int group_id, permission_t permission_type,
                    ecc_key *private_key_out) {
    const group_permission_t *entry = permission_entry(group_id);
    if (entry == NULL) {
        return NULL;
    }
    uint8_t private_key_raw[32];
    uint8_t public_key_raw[32];
    switch (permission_type) {
    case PERM_READ:
        // The HSM only has the private key if it has the given permission
        if (!entry->read_perm) {
            return -1;
        }
        private_key_raw = entry->keys.read_keys.private_key;
        public_key_raw = entry->keys.read_keys.public_key;
    case PERM_WRITE:
        if (!entry->write_perm) {
            return -1;
        }
        private_key_raw = entry->keys.write_keys.private_key;
        public_key_raw = entry->keys.read_keys.public_key;

    case PERM_RECEIVE:
        if (!entry->receive_perm) {
            return -1;
        }
        private_key_raw = entry->keys.receive_keys.private_key;
        public_key_raw = entry->keys.read_keys.public_key;

    default:
        return NULL;
    };
    wc_ecc_init(private_key_out);
    if (wc_ecc_import_private_key(private_key_raw, sizeof(private_key_raw),
                                  public_key_raw, sizeof(public_key_raw),
                                  private_key_out) != 0) {
        printf("Failed to import private key!");
        return -1;
    }
    return 0;
}

static const int get_public_key(int group_id, permission_t permission_type,
                                ecc_key *public_key_out) {
    const group_permission_t *entry = permission_entry(group_id);
    if (entry == NULL) {
        return -1;
    }
    uint8_t public_key_raw[32];
    switch (permission_type) {
    case PERM_READ:
        public_key_raw = entry->keys.read_keys.public_key;
    case PERM_WRITE:
        if (!entry->write_perm) {
            return -1;
        }
        public_key_raw = entry->keys.write_keys.public_key;
    case PERM_RECEIVE:
        public_key_raw = entry->keys.receive_keys.public_key;
    default:
        return -1;
    };
    wc_ecc_init(public_key_out);
    if (wc_ecc_import_x963(public_key_raw, sizeof(public_key_raw),
                           public_key_out) != 0) {
        printf("Failed to import public key!");
        return -1;
    }
    return 0;
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
*/