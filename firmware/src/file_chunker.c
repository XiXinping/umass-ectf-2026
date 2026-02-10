// TODO: File chunking API for GCM/transfer

// Maintain buffer of file bytes per slot

/**  
 ASSUMPTION: File is already stored in the slot
 Zero out buffer before input
 Perform file read into buffer 
 Perform file metadata read into buffer
 Iterate through buffer and input into AES-GCM and perform uart transfer (write byte function)
 Zero out buffer once completed
*/

/**  
 ASSUMPTION: File is in transsit
 Zero out buffer 
 Accept each byte from uart into buffer
 Iterate through buffer and input into AES-GCM  and store the encrypted data into slot pages
 Zero out buffer once completed
*/