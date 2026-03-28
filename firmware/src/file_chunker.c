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

int buffer_store_oldfile(slot_t slot, uint8_t* file_buffer, size_t file_size, uint8_t* metadata_buffer, size_t metadata_size) {
    // TODO: Buffer overflow/null checks, null checks for fields

    file_t* file;
    const filesystem_entry_t *metadata; 

    if(is_slot_in_use(slot)) {
        return -1;  
    }
    read_file(slot, file);
    metadata = get_file_metadata(slot);

    // Fills file_buffer with file contents
    //__attribute__((aligned(16))) 
    //uint8_t buffer[file->contents_len + (16 - (file->contents_len % 16))]; USE SIZE IN COMMANDS.C instead
    memset(file_buffer, 0, file_size);
    
    int offset = 0;
    
    memcpy(file_buffer, file->contents, file->contents_len);
    //offset += file->contents_len;
    
    // Fills metadata_buffer 
    memset(metadata_buffer, 0, metadata_size);
    offset = 0;
    
    memcpy(metadata_buffer, &file->group_id, sizeof(group_id_t));
    offset += sizeof(group_id_t);

    memcpy(metadata_buffer + offset, metadata->uuid, UUID_SIZE);
    offset += UUID_SIZE;

    memcpy(metadata_buffer + offset, file->name, MAX_NAME_SIZE);
    offset += MAX_NAME_SIZE;

    return 0;
}

int buffer_store_oldfile_combined(slot_t slot, uint8_t* buffer, size_t size) {
    // TODO: Buffer overflow/null checks, null checks for fields

    file_t* file;
    const filesystem_entry_t *metadata; 

    if(is_slot_in_use(slot)) {
        return -1;  
    }
    read_file(slot, file);
    metadata = get_file_metadata(slot);

    int offset = 0;

    // Fills file_buffer with file contents
    //__attribute__((aligned(16))) 
    //uint8_t buffer[file->contents_len + (16 - (file->contents_len % 16))]; USE SIZE IN COMMANDS.C instead
    memset(buffer, 0, size);
    
    
    memcpy(buffer, file->contents, file->contents_len);
    offset += file->contents_len;
        
    memcpy(buffer, &file->group_id, sizeof(group_id_t));
    offset += sizeof(group_id_t);

    memcpy(buffer + offset, metadata->uuid, UUID_SIZE);
    offset += UUID_SIZE;

    memcpy(buffer + offset, file->name, MAX_NAME_SIZE);
    offset += MAX_NAME_SIZE;

    return 0;
}

/**  
 ASSUMPTION: File is in transsit
 Zero out buffer 
 Accept each byte from uart into buffer
 Iterate through buffer and input into AES-GCM  and store the encrypted data into slot pages
 Zero out buffer once completed
*/

int buffer_store_newfile(file_t* file, uint8_t* UUID, uint8_t* file_buffer, size_t file_size, uint8_t* metadata_buffer, size_t metadata_size) {
    // TODO: Buffer overflow/null checks, null checks for fields
    
    int offset = 0;

    //__attribute__((aligned(16))) 
    // uint8_t buffer[file->contents_len + (16 - (file->contents_len % 16))];
    memset(file_buffer, 0, file_size);

    memcpy(file_buffer, file->contents, file_size);
    //offset += file->contents_len;


    offset = 0;
    memset(metadata_buffer, 0, metadata_size);

    memcpy(metadata_buffer, &file->group_id, sizeof(group_id_t));
    offset += sizeof(group_id_t);

    memcpy(metadata_buffer + offset, UUID, UUID_SIZE);
    offset += UUID_SIZE;

    memcpy(metadata_buffer + offset, file->name, MAX_NAME_SIZE);
    offset += MAX_NAME_SIZE;

    return 0;
}


int buffer_store_newfile_combined(slot_t slot, uint8_t* buffer, size_t size) {
    // TODO: Buffer overflow/null checks, null checks for fields

    int offset = 0;

    file_t* file;
    const filesystem_entry_t *metadata; 

    // Fills file_buffer with file contents
    //__attribute__((aligned(16))) 
    //uint8_t buffer[file->contents_len + (16 - (file->contents_len % 16))]; USE SIZE IN COMMANDS.C instead
    memset(buffer, 0, size);
    
    
    memcpy(buffer, file->contents, file->contents_len);
    offset += file->contents_len;
        
    memcpy(buffer, &file->group_id, sizeof(group_id_t));
    offset += sizeof(group_id_t);

    memcpy(buffer + offset, metadata->uuid, UUID_SIZE);
    offset += UUID_SIZE;

    memcpy(buffer + offset, file->name, MAX_NAME_SIZE);
    offset += MAX_NAME_SIZE;

    return 0;
}


    //__attribute__((aligned(4))) 
    // 
