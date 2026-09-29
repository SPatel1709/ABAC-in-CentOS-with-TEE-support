#ifndef ABAC_TEE_PROTOCOL_H
#define ABAC_TEE_PROTOCOL_H

#ifdef __KERNEL__
#include <linux/types.h>
typedef __u32 abac_tee_u32;
typedef __u64 abac_tee_u64;
typedef __s32 abac_tee_s32;
#else
#include <stdint.h>
typedef uint32_t abac_tee_u32;
typedef uint64_t abac_tee_u64;
typedef int32_t abac_tee_s32;
#endif

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
        ABAC_TEE_RULE_LIMIT_REACHED = -3,
        ABAC_TEE_SERVICE_UNAVAILABLE = -4
};

typedef struct {
        abac_tee_u32 type;
        char name[ABAC_TEE_NAME_SIZE];
        char value[ABAC_TEE_VALUE_SIZE];
} abac_tee_attribute_t;

typedef struct {
        abac_tee_u32 rule_id;
        abac_tee_u32 attribute_count;
        abac_tee_attribute_t attributes[ABAC_TEE_MAX_ATTRIBUTES];
} abac_tee_rule_data_t;

typedef struct {
        abac_tee_u64 request_id;
        abac_tee_rule_data_t rule;
} abac_tee_ipc_request_t;

typedef struct {
        abac_tee_u64 request_id;
        abac_tee_s32 status;
        abac_tee_s32 matched;
} abac_tee_ipc_response_t;

#endif
