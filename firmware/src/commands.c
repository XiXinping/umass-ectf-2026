/**
 * @file commands.c
 * @author Samuel Meyers
 * @brief eCTF command handlers
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF
 * (eCTF). This code is being provided only for educational purposes for the
 * 2026 MITRE eCTF competition, and may not meet MITRE standards for quality.
 * Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include "commands.h"
#include "authentication.h"
#include "filesystem.h"
#include "host_messaging.h"

/* Host message command lengths */
#define HOST_LIST_CMD_LEN PIN_LENGTH
#define HOST_READ_CMD_LEN (PIN_LENGTH + 1U)
#define HOST_WRITE_MIN_CMD_LEN                                                 \
    (PIN_LENGTH + 1U + 2U + FILE_NAME_SIZE + FILE_UUID_SIZE + 2U)
#define HOST_INTERROGATE_CMD_LEN PIN_LENGTH
#define HOST_RECEIVE_CMD_LEN (PIN_LENGTH + 1U + 1U)

/* IMPORTANT COMPONENTS FROM HSM.c */
// extern file_t hsm_status[MAX_FILE_COUNT];
static file_t current_file;

/**********************************************************
 ******************** HELPER FUNCTIONS ********************
 **********************************************************/

/** @brief List out the files on the system.
 *      To be utilized by list and interrogate
 *
 *  @param file_list A pointer to the list_response_t variable in
 *      which to store the results
 */
void generate_list_files(list_response_t *file_list) {
    file_list->n_files = 0;
    file_t temp_file;

    // Loop through all files on the system
    for (uint8_t i = 0; i < MAX_FILE_COUNT; i++) {
        // Check if the file is in use
        if (is_slot_in_use(i)) {
            read_file(i, &temp_file);

            file_list->metadata[file_list->n_files].slot = i;
            file_list->metadata[file_list->n_files].group_id =
                temp_file.group_id;
            strcpy(file_list->metadata[file_list->n_files].name,
                   (char *)&temp_file.name);
            file_list->n_files++;
        }
    }
}

/**********************************************************
 ******************** COMMAND HANDLERS ********************
 **********************************************************/

/** @brief Perform the list operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
 */
int list(uint16_t pkt_len, uint8_t *buf) {
    list_command_t *command = (list_command_t *)buf;
    list_response_t file_list;

    memset(&file_list, 0, sizeof(file_list));

    // copy relevant fields into the final struct
    generate_list_files(&file_list);

    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    // write success packet with list
    pkt_len_t length = LIST_PKT_LEN(file_list.n_files);
    write_packet(CONTROL_INTERFACE, LIST_MSG, &file_list, length);
    return 0;
}

/** @brief Perform the read operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
 */
int read(uint16_t pkt_len, uint8_t *buf) {
    read_command_t *command = (read_command_t *)buf;
    read_response_t file_info;
    file_t curr_file;

    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    // zeroizing memory is a pretty good practice
    memset(&file_info, 0, sizeof(read_response_t));

    if (read_file(command->slot, &curr_file) < 0) {
        print_error("Failed to read file");
        return -1;
    }

    // copy structure of the persistent file
    memcpy(file_info.name, &curr_file.name, strlen(curr_file.name));
    // memcpy(
    //     file_info.contents, original_content,
    //     curr_file.contents_len); // changed from curr file to decrypted
    //     buffer

    if (!validate_permission(curr_file.group_id, PERM_READ)) {
        print_error("Invalid permission");
        return -1;
    }

    // write a success message with the file information
    pkt_len_t length = FILE_NAME_SIZE + curr_file.contents_len;
    write_packet(CONTROL_INTERFACE, READ_MSG, &file_info, length);
    return 0;
}

/** @brief Perform the write operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
 */
int write(uint16_t pkt_len, uint8_t *buf) {
    write_command_t *command = (write_command_t *)buf;
    int ret;
    file_t curr_file;

    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    if (!validate_permission(command->group_id, PERM_WRITE)) {
        print_error("Invalid permission");
        return -1;
    }

    create_file(&curr_file, command->group_id, command->name,
                command->contents_len, command->contents);

    memset(curr_file.contents, 0, curr_file.contents_len);
    // curr_file.contents = aes_buffer;

    // Store the file persistently
    if (write_file(command->slot, &curr_file, command->uuid) < 0) {
        print_error("Error storing file");
        return -1;
    }

    // Success message with an empty body
    write_packet(CONTROL_INTERFACE, WRITE_MSG, NULL, 0);
    return 0;
}

/** @brief Perform the receive operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
 */
int receive(uint16_t pkt_len, uint8_t *buf) {
    receive_command_t *command = (receive_command_t *)buf;
    receive_request_t request;
    receive_response_t recv_resp;
    msg_type_t cmd;
    uint16_t len_recv_msg;
    int ret;

    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    // zeroize the buffers we will use
    memset(&recv_resp, 0, sizeof(recv_resp));
    memset(&request, 0, sizeof(request));

    // prep request to neighbor
    request.slot = command->read_slot;
    // memcpy(&request.permissions, &global_permissions,
    //        sizeof(group_permission_t) * MAX_PERMS);

    // request the file from the neighboring device
    write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, (void *)&request,
                 sizeof(receive_request_t));

    // set essentially no limit to the receive message size
    len_recv_msg = 0xffff;

    // recieve the response message
    read_packet(TRANSFER_INTERFACE, &cmd, &recv_resp, &len_recv_msg);
    if (cmd != RECEIVE_MSG) {
        print_error("Opcode mismatch");
        return -1;
    }

    // write that file into the file system
    if (write_file(command->write_slot, &recv_resp.file, recv_resp.uuid) < 0) {
        print_error("Writing received file failed");
        return -1;
    }
    // empty success message
    write_packet(CONTROL_INTERFACE, RECEIVE_MSG, NULL, 0);
    return 0;
}

/** @brief Perform the interrogate operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer to the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
 */
int interrogate(uint16_t pkt_len, uint8_t *buf) {
    interrogate_command_t *command = (interrogate_command_t *)buf;
    msg_type_t cmd;
    list_response_t final_list_buf;
    uint16_t len_recv_msg;

    // pin check
    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    // request the file list from the neighboring device
    write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, NULL, 0);

    // set essentially no limit to the receive message size
    len_recv_msg = 0xffff;

    // recieve the response message
    read_packet(TRANSFER_INTERFACE, &cmd, &final_list_buf, &len_recv_msg);
    if (cmd != INTERROGATE_MSG) {
        print_error("Opcode mismatch");
        return -1;
    }

    // return the final list to the user
    write_packet(CONTROL_INTERFACE, INTERROGATE_MSG, &final_list_buf,
                 len_recv_msg);
    return 0;
}

/** @brief Perform the listen operation
 *
 * @return 0 upon success. A negative value on error.
 */
int listen(uint16_t pkt_len, uint8_t *buf) {
    uint8_t uart_buf[sizeof(receive_request_t)];
    msg_type_t cmd;
    pkt_len_t write_length, read_length;
    list_response_t file_list;
    receive_request_t *command;
    receive_response_t recv_resp;
    const filesystem_entry_t *metadata;

    read_length = sizeof(uart_buf);

    // Receive a packet from a neighboring hsm
    memset(uart_buf, 0, sizeof(uart_buf));
    read_packet(TRANSFER_INTERFACE, &cmd, uart_buf, &read_length);

    switch (cmd) {
    case INTERROGATE_MSG:
        // zeroize the buffers we will use
        memset(&file_list, 0, sizeof(file_list));

        // generate a list of files for the other device
        generate_list_files(&file_list);

        // TODO: the reference design does not implement *ANY* security
        // you will want to add something here to comply with SR1

        // send the list of files on this device
        write_length = LIST_PKT_LEN(file_list.n_files);
        write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, &file_list,
                     write_length);
        break;
    case RECEIVE_MSG:
        // get the request
        command = (receive_request_t *)uart_buf;

        // TODO: the reference design does not implement *ANY* security
        // you will want to add something here to comply with SR1

        // if this read fails, the other device will not receive a response and
        // may need to be reset before further testing can occur
        if (read_file(command->slot, &recv_resp.file) < 0) {
            print_error("Failed to read file");
            return -1;
        }

        metadata = get_file_metadata(command->slot);
        if (metadata == NULL) {
            print_error("Getting metadata failed");
            return -1;
        }

        memcpy(&recv_resp.uuid, &metadata->uuid, FILE_UUID_SIZE);

        // send the file to the neighbor hsm
        write_length = sizeof(receive_response_t);
        write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, &recv_resp, write_length);
        break;
    default:
        print_error("Bad message type");
        return -1;
    }

    // blank success message
    write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
    return 0;
}
bool security_process_host_command(hsm_opcode_t opcode, const uint8_t *body,
                                   uint16_t body_len, const hsm_file_ops_t *ops,
                                   uint8_t *response_opcode,
                                   uint8_t *response_body,
                                   uint16_t response_capacity,
                                   uint16_t *response_len) {
    bool ok = false;
    uint8_t err = 0xFF;
    uint16_t out_len = 0;
    uint16_t empty_len = 0;

    if (response_opcode == NULL || response_body == NULL ||
        response_len == NULL)
        return false;
    if (body_len > 0U && body == NULL)
        return false;
    if (g_time_anomaly_detected) {
        if (response_capacity < 1U)
            return false;
        *response_opcode = HSM_OPCODE_ERROR;
        response_body[0] = (uint8_t)SECURITY_ERR_TIME_ANOMALY;
        *response_len = 1U;
        return true;
    }

    switch (opcode) {
    case HSM_OPCODE_LIST:
        ok = handle_list_cmd(body, body_len, ops, response_body,
                             response_capacity, &out_len, &err);
        break;

    case HSM_OPCODE_READ:
        ok = handle_read_cmd(body, body_len, ops, response_body,
                             response_capacity, &out_len, &err);
        break;

    case HSM_OPCODE_WRITE:
        ok = handle_write_cmd(body, body_len, ops, &empty_len, &err);
        out_len = empty_len;
        break;

    case HSM_OPCODE_LISTEN:
        ok = handle_listen_cmd(body, body_len, ops, &empty_len, &err);
        out_len = empty_len;
        break;

    case HSM_OPCODE_INTERROGATE:
        ok = handle_interrogate_cmd(body, body_len, ops, response_body,
                                    response_capacity, &out_len, &err);
        break;

    case HSM_OPCODE_RECEIVE:
        ok = handle_receive_cmd(body, body_len, ops, &empty_len, &err);
        out_len = empty_len;
        break;

    default:
        ok = false;
        err = 0xFE;
        break;
    }

    if (!ok) {
        *response_opcode = HSM_OPCODE_ERROR;
        if (response_capacity < 1U)
            return false;
        response_body[0] = err;
        *response_len = 1U;
#if SECURITY_REQUIRE_PIN_EACH_COMMAND
        security_logout();
#endif
        return true;
    }

    *response_opcode = opcode;
    *response_len = out_len;
#if SECURITY_REQUIRE_PIN_EACH_COMMAND
    security_logout();
#endif
    return true;
}

static bool serialize_file_list(const file_metadata_t *files, uint32_t count,
                                uint8_t *out, uint16_t out_cap,
                                uint16_t *out_len) {
    uint32_t i;
    uint32_t per_entry = (uint32_t)(1U + 2U + FILE_NAME_SIZE);
    uint32_t payload = 0U;
    uint32_t needed = 0U;

    if (files == NULL || out == NULL || out_len == NULL)
        return false;
    if (count > MAX_FILE_COUNT)
        return false;
    if (count != 0U && per_entry > (UINT32_MAX / count))
        return false;
    if (!checked_add_u32(0U, count * per_entry, &payload))
        return false;
    if (!checked_add_u32(4U, payload, &needed))
        return false;
    if (needed > out_cap || needed > UINT16_MAX)
        return false;

    write_le32(out, count);

    for (i = 0; i < count; i++) {
        uint32_t base = 4U + i * (1U + 2U + FILE_NAME_SIZE);
        out[base] = files[i].slot;
        write_le16(&out[base + 1U], files[i].group_id);
        memcpy(&out[base + 3U], files[i].name, FILE_NAME_SIZE);
    }

    *out_len = (uint16_t)needed;
    return true;
}

static bool handle_list_cmd(const uint8_t *body, uint16_t body_len,
                            const hsm_file_ops_t *ops, uint8_t *response_body,
                            uint16_t response_capacity, uint16_t *response_len,
                            uint8_t *err) {
    file_metadata_t files[MAX_FILE_COUNT];
    uint32_t count = MAX_FILE_COUNT;

    if (response_body == NULL || response_len == NULL || err == NULL) {
        return false;
    }
    if (body_len != HOST_LIST_CMD_LEN) {
        *err = (uint8_t)SECURITY_ERR_INVALID_LENGTH;
        return false;
    }
    if (!authenticate_request_pin(body, body_len, err))
        return false;
    if (ops == NULL || ops->list_local_files == NULL) {
        *err = 0x70;
        return false;
    }

    if (!ops->list_local_files(files, &count)) {
        *err = 0x71;
        return false;
    }
    if (count > MAX_FILE_COUNT) {
        *err = 0x72;
        return false;
    }

    if (!serialize_file_list(files, count, response_body, response_capacity,
                             response_len)) {
        *err = 0x73;
        return false;
    }

    return true;
}

static bool handle_read_cmd(const uint8_t *body, uint16_t body_len,
                            const hsm_file_ops_t *ops, uint8_t *response_body,
                            uint16_t response_capacity, uint16_t *response_len,
                            uint8_t *err) {
    uint8_t slot;
    file_t file;
    uint32_t needed;

    if (response_body == NULL || response_len == NULL || err == NULL) {
        return false;
    }
    if (body_len != HOST_READ_CMD_LEN) {
        *err = (uint8_t)SECURITY_ERR_INVALID_LENGTH;
        return false;
    }
    if (!authenticate_request_pin(body, body_len, err))
        return false;
    if (ops == NULL || ops->read_local_file == NULL) {
        *err = 0x74;
        return false;
    }

    slot = body[PIN_LENGTH];
    if (slot >= MAX_FILE_COUNT) {
        *err = 0x85;
        return false;
    }
    if (!ops->read_local_file(slot, &file)) {
        *err = 0x75;
        return false;
    }

    if (!validate_permission(file.group_id, PERM_READ)) {
        *err = 0x76;
        return false;
    }

    needed = (uint32_t)FILE_NAME_SIZE + file.contents_len;
    if (needed > response_capacity) {
        *err = 0x77;
        return false;
    }

    memcpy(response_body, file.name, FILE_NAME_SIZE);
    if (file.contents_len > 0 && file.contents != NULL) {
        memcpy(response_body + FILE_NAME_SIZE, file.contents,
               file.contents_len);
    }
    *response_len = (uint16_t)needed;
    return true;
}

static bool parse_write_cmd(const uint8_t *body, uint16_t body_len,
                            file_t *file, uint8_t *err) {
    uint32_t fixed_len = (uint32_t)HOST_WRITE_MIN_CMD_LEN;
    uint32_t expected_len;
    uint16_t contents_len;

    if (body == NULL || file == NULL || err == NULL) {
        return false;
    }

    if (body_len < HOST_WRITE_MIN_CMD_LEN) {
        *err = (uint8_t)SECURITY_ERR_INVALID_LENGTH;
        return false;
    }

    file->slot = body[PIN_LENGTH];
    if (file->slot >= MAX_FILE_COUNT) {
        *err = (uint8_t)SECURITY_ERR_INVALID_LENGTH;
        return false;
    }
    file->group_id = read_le16(&body[PIN_LENGTH + 1U]);
    memcpy(file->name, &body[PIN_LENGTH + 3U], FILE_NAME_SIZE);
    memcpy(file->uuid, &body[PIN_LENGTH + 3U + FILE_NAME_SIZE], FILE_UUID_SIZE);

    contents_len =
        read_le16(&body[PIN_LENGTH + 3U + FILE_NAME_SIZE + FILE_UUID_SIZE]);
    if (!checked_add_u32(fixed_len, (uint32_t)contents_len, &expected_len)) {
        *err = (uint8_t)SECURITY_ERR_BUFFER;
        return false;
    }
    if (expected_len > UINT16_MAX || body_len != (uint16_t)expected_len) {
        *err = (uint8_t)SECURITY_ERR_INVALID_LENGTH;
        return false;
    }

    file->contents_len = contents_len;
    file->contents = &body[HOST_WRITE_MIN_CMD_LEN];
    return true;
}

static bool handle_write_cmd(const uint8_t *body, uint16_t body_len,
                             const hsm_file_ops_t *ops, uint16_t *response_len,
                             uint8_t *err) {
    file_t file;

    if (response_len == NULL || err == NULL)
        return false;
    if (!authenticate_request_pin(body, body_len, err))
        return false;
    if (ops == NULL || ops->write_local_file == NULL) {
        *err = 0x78;
        return false;
    }
    if (!parse_write_cmd(body, body_len, &file, err))
        return false;

    if (!validate_permission(file.group_id, PERM_WRITE)) {
        *err = 0x79;
        return false;
    }

    if (!ops->write_local_file(&file)) {
        *err = 0x7A;
        return false;
    }

    *response_len = 0;
    return true;
}

static bool handle_listen_cmd(const uint8_t *body, uint16_t body_len,
                              const hsm_file_ops_t *ops, uint16_t *response_len,
                              uint8_t *err) {
    (void)body;

    if (response_len == NULL || err == NULL)
        return false;
    if (body_len != 0) {
        *err = (uint8_t)SECURITY_ERR_INVALID_LENGTH;
        return false;
    }
    if (ops == NULL || ops->listen_for_neighbor == NULL) {
        *err = 0x7B;
        return false;
    }

    if (!ops->listen_for_neighbor()) {
        *err = 0x7C;
        return false;
    }

    *response_len = 0;
    return true;
}

static bool handle_interrogate_cmd(const uint8_t *body, uint16_t body_len,
                                   const hsm_file_ops_t *ops,
                                   uint8_t *response_body,
                                   uint16_t response_capacity,
                                   uint16_t *response_len, uint8_t *err) {
    file_metadata_t all_files[MAX_FILE_COUNT];
    file_metadata_t filtered_files[MAX_FILE_COUNT];
    uint32_t total = MAX_FILE_COUNT;
    uint32_t filtered = 0;
    uint32_t i;

    if (response_body == NULL || response_len == NULL || err == NULL) {
        return false;
    }
    if (body_len != HOST_INTERROGATE_CMD_LEN) {
        *err = (uint8_t)SECURITY_ERR_INVALID_LENGTH;
        return false;
    }
    if (!authenticate_request_pin(body, body_len, err))
        return false;
    if (ops == NULL || ops->interrogate_neighbor == NULL) {
        *err = 0x7D;
        return false;
    }

    if (!ops->interrogate_neighbor(all_files, &total)) {
        *err = 0x7E;
        return false;
    }
    if (total > MAX_FILE_COUNT) {
        *err = 0x7F;
        return false;
    }

    for (i = 0; i < total; i++) {
        if (validate_permission(all_files[i].group_id, PERM_RECEIVE)) {
            filtered_files[filtered++] = all_files[i];
        }
    }

    if (!serialize_file_list(filtered_files, filtered, response_body,
                             response_capacity, response_len)) {
        *err = 0x80;
        return false;
    }

    return true;
}

static bool handle_receive_cmd(const uint8_t *body, uint16_t body_len,
                               const hsm_file_ops_t *ops,
                               uint16_t *response_len, uint8_t *err) {
    uint8_t read_slot;
    uint8_t write_slot;
    file_t file;

    if (response_len == NULL || err == NULL)
        return false;
    if (body_len != HOST_RECEIVE_CMD_LEN) {
        *err = (uint8_t)SECURITY_ERR_INVALID_LENGTH;
        return false;
    }
    if (!authenticate_request_pin(body, body_len, err))
        return false;

    if (ops == NULL || ops->receive_neighbor_file == NULL ||
        ops->write_local_file == NULL) {
        *err = 0x81;
        return false;
    }

    read_slot = body[PIN_LENGTH];
    write_slot = body[PIN_LENGTH + 1U];
    if (read_slot >= MAX_FILE_COUNT || write_slot >= MAX_FILE_COUNT) {
        *err = (uint8_t)SECURITY_ERR_INVALID_LENGTH;
        return false;
    }

    if (!ops->receive_neighbor_file(read_slot, &file)) {
        *err = 0x82;
        return false;
    }

    if (!validate_permission(file.group_id, PERM_RECEIVE)) {
        *err = 0x83;
        return false;
    }

    file.slot = write_slot;
    if (!ops->write_local_file(&file)) {
        *err = 0x84;
        return false;
    }

    *response_len = 0;
    return true;
}
