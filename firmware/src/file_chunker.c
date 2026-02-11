// TODO: File chunking API for GCM/transfer
#include "filesystem.h"
// Maintain buffer of file bytes per slot

/**  
 ASSUMPTION: File is already stored in the slot
 Zero out buffer before input
 Perform file read into buffer 
 Perform file metadata read into buffer
 Iterate through buffer and input into AES-GCM and perform uart transfer (write byte function)
 Zero out buffer once completed
*/

uint8_t* buffer_store_oldfile_info(slot_t slot) {
    // TODO: Buffer overflow/null checks, null checks for fields

    file_t* file;
    filesystem_entry_t* metadata; 
    read_file(slot, &file);
    metadata = get_file_metadata(slot);

    __attribute__((aligned(4))) 
    uint8_t buffer[file->contents_len + sizeof(group_id_t) + UUID_SIZE + MAX_NAME_SIZE];
    memset(buffer, 0, sizeof(buffer));
    
    int offset = 0;
    
    memcpy(buffer, file->contents, file->contents_len);
    offset += file->contents_len;

    memcpy(buffer, &file->group_id, sizeof(group_id_t));
    offset += sizeof(group_id_t);

    memcpy(buffer + offset, metadata->uuid, UUID_SIZE);
    offset += UUID_SIZE;

    memcpy(buffer + offset, file->name, MAX_NAME_SIZE);
    offset += MAX_NAME_SIZE;

    /*
    memcpy(buffer + offset, metadata->flash_addr, sizeof(metadata->flash_addr));
    offset += sizeof(metadata->flash_addr);

    memcpy(buffer + offset, metadata->length, sizeof(metadata->length));
    offset += sizeof(metadata->length);

    memcpy(buffer + offset, metadata->padding, sizeof(metadata->padding));

    */
    // add offset potentially

    return buffer;
}



/**  
 ASSUMPTION: File is in transsit
 Zero out buffer 
 Accept each byte from uart into buffer
 Iterate through buffer and input into AES-GCM  and store the encrypted data into slot pages
 Zero out buffer once completed
*/

uint8_t* buffer_store_newfile_info(file_t* file, uint8_t* UUID, slot_t slot, uint16_t length) {
    // TODO: Buffer overflow/null checks, null checks for fields
    
    int offset = 0;

    __attribute__((aligned(4))) 
    uint8_t buffer[file->contents_len + sizeof(group_id_t) + UUID_SIZE + MAX_NAME_SIZE];
    memset(buffer, 0, sizeof(buffer));

    memcpy(buffer, file->contents, file->contents_len);
    offset += file->contents_len;

    memcpy(buffer, &file->group_id, sizeof(group_id_t));
    offset += sizeof(group_id_t);

    memcpy(buffer + offset, UUID, UUID_SIZE);
    offset += UUID_SIZE;

    memcpy(buffer + offset, file->name, MAX_NAME_SIZE);
    offset += MAX_NAME_SIZE;

    

    /*
    memcpy(buffer + offset, &flash_addr, sizeof(flash_addr));
    offset += sizeof(flash_addr);

    memcpy(buffer + offset, &length, sizeof(length));
    // add offset potentially
    */
    return buffer;
}

