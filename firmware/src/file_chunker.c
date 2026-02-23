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

uint8_t* buffer_store_oldfile_contents(slot_t slot) {
    // TODO: Buffer overflow/null checks, null checks for fields

    file_t* file;
    filesystem_entry_t* metadata; 

    if(is_slot_in_use(slot)) {
        return NULL; // add graceful return logic 
    }
    read_file(slot, &file);
    metadata = get_file_metadata(slot);

    __attribute__((aligned(16))) 
    uint8_t buffer[file->contents_len + (16 - (file->contents_len % 16))];
    memset(buffer, 0, sizeof(buffer));
    
    int offset = 0;
    
    memcpy(buffer, file->contents, file->contents_len);
    offset += file->contents_len;

    return buffer;
}

uint8_t* buffer_store_oldfile_metadata(slot_t slot) {
    // TODO: Buffer overflow/null checks, null checks for fields
    filesystem_entry_t* metadata; 

    if(is_slot_in_use(slot)) {
        return NULL; // add graceful return logic 
    }
    metadata = get_file_metadata(slot);

   //__attribute__((aligned(4))) 
    uint8_t buffer[sizeof(group_id_t) + UUID_SIZE + MAX_NAME_SIZE];
    memset(buffer, 0, sizeof(buffer));
    
    int offset = 0;
    
    memcpy(buffer, &file->group_id, sizeof(group_id_t));
    offset += sizeof(group_id_t);

    memcpy(buffer + offset, metadata->uuid, UUID_SIZE);
    offset += UUID_SIZE;

    memcpy(buffer + offset, file->name, MAX_NAME_SIZE);
    offset += MAX_NAME_SIZE;

    return buffer;
}



/**  
 ASSUMPTION: File is in transsit
 Zero out buffer 
 Accept each byte from uart into buffer
 Iterate through buffer and input into AES-GCM  and store the encrypted data into slot pages
 Zero out buffer once completed
*/

uint8_t* buffer_store_newfile_contents(file_t* file, uint8_t* UUID) {
    // TODO: Buffer overflow/null checks, null checks for fields
    
    int offset = 0;

    __attribute__((aligned(16))) 
    uint8_t buffer[file->contents_len + (16 - (file->contents_len % 16))];
    memset(buffer, 0, sizeof(buffer));

    memcpy(buffer, file->contents, file->contents_len);
    offset += file->contents_len;

    return buffer;
}

uint8_t* buffer_store_newfile_metadata(file_t* file, uint8_t* UUID) {
    // TODO: Buffer overflow/null checks, null checks for fields
    
    int offset = 0;

    //__attribute__((aligned(4))) 
    uint8_t buffer[sizeof(group_id_t) + UUID_SIZE + MAX_NAME_SIZE];
    memset(buffer, 0, sizeof(buffer));

    memcpy(buffer, &file->group_id, sizeof(group_id_t));
    offset += sizeof(group_id_t);

    memcpy(buffer + offset, UUID, UUID_SIZE);
    offset += UUID_SIZE;

    memcpy(buffer + offset, file->name, MAX_NAME_SIZE);
    offset += MAX_NAME_SIZE;

    return buffer;
}