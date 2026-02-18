#include <stdbool.h>
#include <stdint.h>

// A struct representing a public-private key pair.
typedef struct {
    // All HSMs have access to the public key for every permission
    uint8_t public_key[32];
    // This field will be NULL if an HSM does not have a particular permission
    uint8_t private_key[32];
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
    // The public-private key pairs for each permission. If the HSM has a
    // particular permission, the private_key field will be populated with a
    // key, otherwise it will be NULL.
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

// static const int groups[NUM_GROUPS] = {1, 2, 3};

static uint8_t *get_private_key(int group_id, permission_t permission_type);
static uint8_t *get_public_key(int group_id, permission_t permission_type);

static bool permission_allowed(uint16_t group_id, permission_t perm);
static bool validate_permission(uint16_t group_id, permission_t perm);
