#include "Enclave_u.h"
#include "abac_tee_protocol.h"

#include <sgx_urts.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define ENCLAVE_FILE "Enclave/enclave.signed.so"

static void set_attribute(abac_tee_rule_data_t *data, uint32_t index,
                          uint32_t type, const char *name, const char *value)
{
        abac_tee_attribute_t *attribute = &data->attributes[index];

        attribute->type = type;
        strncpy(attribute->name, name, ABAC_TEE_NAME_SIZE - 1);
        strncpy(attribute->value, value, ABAC_TEE_VALUE_SIZE - 1);
}

static bool load_rule(sgx_enclave_id_t enclave_id,
                      const abac_tee_rule_data_t *rule)
{
        int enclave_status = ABAC_TEE_INVALID_REQUEST;
        sgx_status_t status;

        status = ecall_load_rule(enclave_id, &enclave_status,
                                 (const uint8_t *)rule, sizeof(*rule));
        if (status != SGX_SUCCESS || enclave_status != ABAC_TEE_SUCCESS) {
                fprintf(stderr,
                        "ecall_load_rule failed: SGX=0x%x enclave=%d\n",
                        status, enclave_status);
                return false;
        }

        return true;
}

static bool evaluate_rule(sgx_enclave_id_t enclave_id,
                          const abac_tee_rule_data_t *request,
                          int expected_match)
{
        int enclave_status = ABAC_TEE_INVALID_REQUEST;
        int matched = 0;
        sgx_status_t status;

        status = ecall_evaluate_rule(enclave_id, &enclave_status,
                                     (const uint8_t *)request,
                                     sizeof(*request), &matched);
        if (status != SGX_SUCCESS || enclave_status != ABAC_TEE_SUCCESS) {
                fprintf(stderr,
                        "ecall_evaluate_rule failed: SGX=0x%x enclave=%d\n",
                        status, enclave_status);
                return false;
        }

        printf("rule=%u expected=%s result=%s\n", request->rule_id,
               expected_match ? "ALLOW" : "DENY",
               matched ? "ALLOW" : "DENY");
        return matched == expected_match;
}

int main(void)
{
        sgx_launch_token_t launch_token = { 0 };
        sgx_misc_attribute_t misc_attributes = { 0 };
        sgx_enclave_id_t enclave_id = 0;
        int launch_token_updated = 0;
        sgx_status_t status;
        abac_tee_rule_data_t rule = { 0 };
        abac_tee_rule_data_t request = { 0 };
        bool success;

        status = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG,
                                    &launch_token, &launch_token_updated,
                                    &enclave_id, &misc_attributes);
        if (status != SGX_SUCCESS) {
                fprintf(stderr, "sgx_create_enclave failed: 0x%x\n", status);
                return 1;
        }

        rule.rule_id = 1001;
        rule.attribute_count = 2;
        set_attribute(&rule, 0, ABAC_TEE_USER_ATTRIBUTE,
                      "clearance", "high");
        set_attribute(&rule, 1, ABAC_TEE_OBJECT_ATTRIBUTE,
                      "classification", "secret");

        if (!load_rule(enclave_id, &rule)) {
                sgx_destroy_enclave(enclave_id);
                return 1;
        }

        request.rule_id = 1001;
        request.attribute_count = 2;
        set_attribute(&request, 0, ABAC_TEE_USER_ATTRIBUTE,
                      "clearance", "high");
        set_attribute(&request, 1, ABAC_TEE_OBJECT_ATTRIBUTE,
                      "classification", "secret");

        success = evaluate_rule(enclave_id, &request, 1);

        memset(request.attributes[1].value, 0,
               sizeof(request.attributes[1].value));
        strncpy(request.attributes[1].value, "public",
                ABAC_TEE_VALUE_SIZE - 1);
        success = evaluate_rule(enclave_id, &request, 0) && success;

        sgx_destroy_enclave(enclave_id);
        if (!success) {
                fprintf(stderr, "ABAC TEE self-test failed\n");
                return 1;
        }

        printf("ABAC TEE multi-attribute self-test passed\n");
        return 0;
}
