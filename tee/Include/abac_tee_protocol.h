#ifndef ABAC_TEE_PROTOCOL_H
#define ABAC_TEE_PROTOCOL_H

#include <stdint.h>

#define ABAC_TEE_MAX_ATTRIBUTES 16
#define ABAC_TEE_NAME_SIZE      64
#define ABAC_TEE_VALUE_SIZE     128

enum abac_tee_attribute_type {
        ABAC_TEE_USER_ATTRIBUTE = 1,
        ABAC_TEE_OBJECT_ATTRIBUTE = 2,
        ABAC_TEE_ENV_ATTRIBUTE = 3
};

enum abac_tee_status {
        ABAC_TEE_SUCCESS = 0,
        ABAC_TEE_INVALID_REQUEST = -1,
        ABAC_TEE_RULE_NOT_FOUND = -2,
        ABAC_TEE_RULE_LIMIT_REACHED = -3
};

typedef struct {
        uint32_t type;
        char name[ABAC_TEE_NAME_SIZE];
        char value[ABAC_TEE_VALUE_SIZE];
} abac_tee_attribute_t;

/*
 Expected attributes are loaded as a rule. Actual attributes for one access
 use the same structure and rule_id. All attributes are evaluated together.
 */
typedef struct {
        uint32_t rule_id;
        uint32_t attribute_count;
        abac_tee_attribute_t attributes[ABAC_TEE_MAX_ATTRIBUTES];
} abac_tee_rule_data_t;

#endif
