#include <permission.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

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
    return permission_allowed(group_id, perm);
}
