#define WOLFSSL_USER_SETTINGS

#include "secure_filesystem.h"
#include "crypto.h"
#include "filesystem.h"
#include "permission.h"
#include "simple_flash.h"
#include <stdint.h>
#include <string.h>
#include "file_chunker.h"
//
// Read a protected file from persistent storage. Does not perform any
// decryption or verification.
int load_protected_file(slot_t slot, protected_file_t *dest) {
    file_t file;
    if (read_file(slot, &file) < 0) {
        // print_error("Failed to read file!");
        return -1;
    }
    uint8_t nonce[NONCE_SIZE];
    uint8_t auth_tag[AUTH_TAG_SIZE];
    uint8_t shared_secret[SHARED_SECRET_SIZE];
    uint8_t encrypted_contents[MAX_ENC_SIZE];
    uint8_t signature[SIGNATURE_SIZE];

    uint8_t *file_contents = file.contents;
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

    // *dest = {
    //     .in_use = false,
    //     .group_id = file.group_id,
    //     .name = file.name,
    //     .contents_len = file.contents_len,
    //     .nonce = nonce,
    //     .auth_tag = auth_tag,
    //     .shared_secret = shared_secret,
    //     .encrypted_contents = encrypted_contents,
    //     .signature = signature,
    // };
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

int secure_read(slot_t slot, file_t *dest, uint8_t *tag, uint8_t *iv, uint8_t *sig, word32 sig_size) {
    file_t file;
    if (read_file(slot, &file) < 0) {
        // print_error("Failed to read file!");
        return -1;
    }
    filesystem_entry_t *metadata = get_file_metadata(slot);
    uint16_t group_id = file.group_id;
    if (!permission_allowed(group_id, PERM_READ)) {
        return -1;
    }
    ecc_key *read_private_key;
    ecc_key *write_pub_key;
    get_private_key(group_id, PERM_READ, read_private_key);
    get_public_key(group_id, PERM_WRITE, write_pub_key);

    ecc_verify_file_digest(sig, sig_size, read_private_key, write_pub_key);


    uint8_t *plain_out;
    size_t metadata_size = FILE_NAME_SIZE + FILE_UUID_SIZE + sizeof(group_id_t);
    ecc_asymmetric_dec(file->contents, read_private_key, metadata, metadata_size, plain_out, iv, tag, write_pub_key, )
}

/** @brief Securely encrypt, sign, and write a file into persistent storage.
 *
 *  Secure write will do the following:
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



int secure_write(slot_t slot, file_t *src, uint8_t *ciphertext_out, uint8_t *iv_out, uint8_t *auth_tag_out, uint8_t *cipher_public_key_out, WC_RNG *rng) {
    // file_t file;
    /** 
    if (read_file(slot, &file) < 0) {
        // print_error("Failed to read file!");
        return -1;
    }
        */
    

    uint16_t group_id = src.group_id;
    if (!permission_allowed(group_id, PERM_WRITE)) {
        return -1;
    }
    ecc_key *read_private_key;
    ecc_key *write_pub_key;
    get_private_key(group_id, PERM_WRITE, read_private_key);
    get_public_key(group_id, PERM_READ, write_pub_key);

    size_t file_contents_size = file->contents_len + (16 - (file->contents_len % 16));
    uint8_t file_buffer[file_contents_size];

    size_t metadata_size = FILE_NAME_SIZE + FILE_UUID_SIZE + sizeof(group_id_t);
    uint8_t* metadata_buffer[metadata_size];

    buffer_store_newfile(src, src->uuid, file_buffer, file_contents_size, metadata_buffer, metadata_size);

    ecc_asymmetric_encrypt(file_buffer, file_contents_size, write_pub_key, metadata_buffer, metadata_size, ciphertext_out, file_contents_size, iv_out, auth_tag_out, cipher_public_key_out);
    
    
    size_t combined_size = file_contents_size + metadata_size;
    uint8_t* file_combined_buffer[combined_size];
    buffer_store_oldfile_combined(slot, file_combined_buffer, combined_size);
    ecc_sign_file_digest(rng, file_combined_buffer, read_private_key, write_pub_key);


    memset(metadata_buffer, 0, metadata_size);
    memset(file_buffer, 0, file_contents_size);
    memset(file_combined_buffer, 0, combined_size);

    write_file(slot, ciphertext_out, src->uuid);
    
}