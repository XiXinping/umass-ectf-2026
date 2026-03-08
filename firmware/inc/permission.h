#ifndef PERMISSION_H
#define PERMISSION_H

#include "ecc.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

// A struct representing a public-private key pair.
typedef struct {
    // All HSMs have access to the public key for every permission
    uint8_t public_key[ECC_KEY_SIZE];
    // This field will be NULL if an HSM does not have a particular permission
    uint8_t private_key[ECC_KEY_SIZE];
} key_pair_t;

// The public-private key pairs corresponding to each permission in a group.
typedef struct {
    key_pair_t read_keys;
    key_pair_t write_keys;
    key_pair_t receive_keys;
} group_keys_t;

typedef struct {
    // Unique identifier for the permission group.
    int group_id;
    // Indicates read permission.
    bool read_perm;
    // Indicates write permission.
    bool write_perm;
    // Indicates receive permission.
    bool receive_perm;
    // The public-private key pairs for each permission.
    group_keys_t keys;
} group_permission_t;

typedef enum {
    // Allows reading files.
    PERM_READ,
    // Allows writing files.
    PERM_WRITE,
    // Allows receiving files from another HSM.
    PERM_RECEIVE,
} permission_t;

/**
 * @brief Get the private key corresponding to a permission for a group.
 *
 * @param group_id The group ID
 * @param permisison_type The kind of permission (read, write, or receive)
 * @return Returns the raw bytes of the private key if the HSM has permission.
 * Returns NULL otherwise.
 */
int get_private_key(uint16_t group_id, permission_t permission_type,
                    ecc_key *private_key_out);
/**
 * @brief Get the public key corresponding to a permission for a group.
 *
 * @param group_id The group ID
 * @param permisison_type The kind of permission (read, write, or receive)
 * @return Returns the raw bytes of the public key.
 */
int get_public_key(uint16_t group_id, permission_t permission_type,
                   ecc_key *public_key_out);

static bool permission_allowed(uint16_t group_id, permission_t perm);
/** @brief Ensure the HSM has the requested permission
 *
 *  @param group_id Group ID.
 *  @param perm Permission type.
 *
 *  @return True if the HSM has the correct permission. False if not.
 */
bool validate_permission(uint16_t group_id, permission_t perm);
/* Verify that a remote HSM message is valid:
   - sender identity via ECC signature
   - permission group of sender
   - file integrity via AES-GCM tag */
bool verify_remote_hsm(const uint8_t *msg, size_t msg_len,
                       const uint8_t *signature, size_t sig_len,
                       const uint8_t *file, size_t file_len, const uint8_t *tag,
                       uint16_t sender_group, permission_t action);
#endif // PERMISSION_H
