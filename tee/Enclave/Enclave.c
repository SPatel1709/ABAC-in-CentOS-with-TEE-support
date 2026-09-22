#include "Enclave_t.h"
#include "abac_tee_protocol.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define ABAC_TEE_MAX_RULES 64

static abac_tee_rule_data_t trusted_rules[ABAC_TEE_MAX_RULES];
static uint8_t trusted_rule_used[ABAC_TEE_MAX_RULES];

static int has_terminator(const char *value, size_t size)
{
        return memchr(value, '\0', size) != NULL;
}

static int valid_rule_data(const abac_tee_rule_data_t *rule)
{
        uint32_t i;

        if (!rule || rule->attribute_count == 0 ||
            rule->attribute_count > ABAC_TEE_MAX_ATTRIBUTES)
                return 0;

        for (i = 0; i < rule->attribute_count; i++) {
                const abac_tee_attribute_t *attribute = &rule->attributes[i];

                if (attribute->type < ABAC_TEE_USER_ATTRIBUTE ||
                    attribute->type > ABAC_TEE_ENV_ATTRIBUTE)
                        return 0;
                if (!has_terminator(attribute->name, ABAC_TEE_NAME_SIZE) ||
                    !has_terminator(attribute->value, ABAC_TEE_VALUE_SIZE))
                        return 0;
        }

        return 1;
}

static int find_rule(uint32_t rule_id)
{
        int i;

        for (i = 0; i < ABAC_TEE_MAX_RULES; i++) {
                if (trusted_rule_used[i] &&
                    trusted_rules[i].rule_id == rule_id)
                        return i;
        }

        return -1;
}

static int attributes_equal(const abac_tee_attribute_t *expected,
                            const abac_tee_attribute_t *actual)
{
        return expected->type == actual->type &&
               strncmp(expected->name, actual->name,
                       ABAC_TEE_NAME_SIZE) == 0 &&
               strncmp(expected->value, actual->value,
                       ABAC_TEE_VALUE_SIZE) == 0;
}

int ecall_load_rule(const uint8_t *rule_data, size_t rule_size)
{
        const abac_tee_rule_data_t *rule;
        int slot;
        int i;

        if (!rule_data || rule_size != sizeof(abac_tee_rule_data_t))
                return ABAC_TEE_INVALID_REQUEST;

        rule = (const abac_tee_rule_data_t *)rule_data;
        if (!valid_rule_data(rule))
                return ABAC_TEE_INVALID_REQUEST;

        slot = find_rule(rule->rule_id);
        if (slot < 0) {
                for (i = 0; i < ABAC_TEE_MAX_RULES; i++) {
                        if (!trusted_rule_used[i]) {
                                slot = i;
                                break;
                        }
                }
        }

        if (slot < 0)
                return ABAC_TEE_RULE_LIMIT_REACHED;

        memcpy(&trusted_rules[slot], rule, sizeof(*rule));
        trusted_rule_used[slot] = 1;
        return ABAC_TEE_SUCCESS;
}

int ecall_evaluate_rule(const uint8_t *request_data, size_t request_size,
                        int *matched)
{
        const abac_tee_rule_data_t *request;
        const abac_tee_rule_data_t *expected;
        uint32_t i;
        uint32_t j;
        int slot;
        int found;

        if (!matched)
                return ABAC_TEE_INVALID_REQUEST;
        *matched = 0;

        if (!request_data || request_size != sizeof(abac_tee_rule_data_t))
                return ABAC_TEE_INVALID_REQUEST;

        request = (const abac_tee_rule_data_t *)request_data;
        if (!valid_rule_data(request))
                return ABAC_TEE_INVALID_REQUEST;

        slot = find_rule(request->rule_id);
        if (slot < 0)
                return ABAC_TEE_RULE_NOT_FOUND;
        expected = &trusted_rules[slot];

        for (i = 0; i < expected->attribute_count; i++) {
                found = 0;
                for (j = 0; j < request->attribute_count; j++) {
                        if (attributes_equal(&expected->attributes[i],
                                             &request->attributes[j])) {
                                found = 1;
                                break;
                        }
                }
                if (!found)
                        return ABAC_TEE_SUCCESS;
        }

        *matched = 1;
        return ABAC_TEE_SUCCESS;
}

int ecall_clear_rules(void)
{
        memset(trusted_rules, 0, sizeof(trusted_rules));
        memset(trusted_rule_used, 0, sizeof(trusted_rule_used));
        return ABAC_TEE_SUCCESS;
}
