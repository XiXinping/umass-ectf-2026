#include "aes_gcm.h"
#include "filesystem.h"
#include "permission.h"
#include "simple_flash.h"
#include <stdint.h>
#include <string.h>
//
// Read a protected file from persistent storage. Does not perform any
// decryption or verification.
int load_protected_file(slot_t, protected_file_t *dest) {
    file_t file;
    if (read_file(slot, file) < 0) {
        print_error("Failed to read file!");
        return -1;
    }
    uint8_t nonce[NONCE_SIZE];
    uint8_t auth_tag[AUTH_TAG_SIZE];
    uint8_t shared_secret[SHARED_SECRET_SIZE];
    uint8_t encrypted_contents[MAX_ENC_SIZE];
    uint8_t signature[SIGNATURE_SIZE];

    uint8_t file_contents[MAX_CONTENTS_SIZE] = file.contents;
    uint32_t offset = 0;
    memmove((uint8_t *)nonce, (const uint8_t *)file_contents + offset,
            NONCE_SIZE);
    offset += NONCE_SIZE;
    memmove((uint8_t *)auth_tag, (const uint8_t *)file_contents + offset,
            NONCE_SIZE);
    offset += AUTH_TAG_SIZE;
    memmove((uint8_t *)shared_secret, (const uint8_t *)file_contents + offset,
            SHARED_SECRET_SIZE);
    offset += SHARED_SECRET_SIZE;
    memmove((uint8_t *)encrypted_contents,
            (const uint8_t *)file_contents + offset, MAX_ENC_SIZE);
    offset += MAX_ENC_SIZE;
    memmove((uint8_t *)signature, (const uint8_t *)file_contents + offset,
            SIGNATURE_SIZE);

    *dest = {
        .in_use = false,
        .group_id = file.group_id,
        .name = file.name,
        .contents_len = file.contents_len,
        .nonce = nonce,
        .auth_tag = auth_tag,
        .shared_secret = shared_secret,
        .encrypted_contents = encrypted_contents,
        .signature = signature,

    }
}

/** @brief Read and decrypt a protected file from persistent storage into
 *  memory if the HSM has appropriate permissions.
 *
 *  Secure read will do the following:
 *  1. Check if the HSM has the valid permission to read the file.
 *  2. Verify that the file was written with proper permissions.
 *  3. Access the read permission key.
 *  4. Decrypt the file contents and output them to the buffer.
 *
 *  @param slot The slot to read
 *  @param dest The destination address to store the file
 *
 * @return 0 upon success. A negative value otherwise.
 */

/*
int secure_read(slot_t slot, file_t *dest) {
    file_t file;
    if (read_file(slot, file) < 0) {
        print_error("Failed to read file!");
        return -1;
    }

    uint16_t group_id = file.group_id;
    if (!permission_allowed(group_id, PERM_READ)) {
        return -1;
    }
    uint8_t read_private_key[ECC_KEY_SIZE] =
        get_private_key(group_id, PERM_READ);
    uint16_t write_pub_key[ECC_KEY_SIZE] = get_public_key(group_id, PERM_WRITE);
}

/** @brief Securely encrypt, sign, and write a file into persistent storage.
 *
 *  Secure read will do the following:
 *  1. Check if the HSM has the valid permission to write the file.
 *  2. Encrypt the contents of the file with the public key of the read
 *  permission.
 *  3. Create a signed file digest and attach this at the end.
 *  4. Write the file to the desired slot.
 *
 *  @param slot The slot to read
 *  @param dest The destination address to store the file
 *
 * @return 0 upon success. A negative value otherwise.
 */
