#define _POSIX_C_SOURCE 200809L
#include "Enclave_u.h"
#include "abac_tee_protocol.h"

#include <sgx_urts.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define ENCLAVE_FILE "Enclave/enclave.signed.so"
#define TEE_REQUEST_FILE "/sys/kernel/security/abac/tee_request"
#define TEE_RESPONSE_FILE "/sys/kernel/security/abac/tee_response"
#define TEE_RULES_FILE "/etc/abac/tee_rules.conf"
#define TEE_ENV_FILE "/etc/abac/tee_env.conf"

static void set_attribute(abac_tee_rule_data_t *rule, uint32_t index,
                          uint32_t type, const char *name, const char *value)
{
        abac_tee_attribute_t *attribute = &rule->attributes[index];

        attribute->type = type;
        strncpy(attribute->name, name, ABAC_TEE_NAME_SIZE - 1);
        strncpy(attribute->value, value, ABAC_TEE_VALUE_SIZE - 1);
}

static int attribute_type(const char *text)
{
        if (strcmp(text, "user") == 0)
                return ABAC_TEE_USER_ATTRIBUTE;
        if (strcmp(text, "object") == 0)
                return ABAC_TEE_OBJECT_ATTRIBUTE;
        if (strcmp(text, "env") == 0)
                return ABAC_TEE_ENV_ATTRIBUTE;
        return 0;
}

static int load_environment_config(sgx_enclave_id_t enclave_id,
                                   const char *path)
{
        abac_tee_env_config_t config = { 0 };
        unsigned int value;
        int have_mask = 0;
        int have_start = 0;
        int have_end = 0;
        int enclave_status = ABAC_TEE_INVALID_REQUEST;
        sgx_status_t status;
        char line[128];
        FILE *file;

        file = fopen(path, "r");
        if (!file) {
                perror("open TEE environment file");
                return -1;
        }

        while (fgets(line, sizeof(line), file)) {
                if (sscanf(line, "workday_mask=%u", &value) == 1) {
                        config.workday_mask = value;
                        have_mask = 1;
                } else if (sscanf(line, "work_start_minute=%u",
                                  &value) == 1) {
                        config.work_start_minute = value;
                        have_start = 1;
                } else if (sscanf(line, "work_end_minute=%u",
                                  &value) == 1) {
                        config.work_end_minute = value;
                        have_end = 1;
                }
        }

        fclose(file);

        if (!have_mask || !have_start || !have_end) {
                fprintf(stderr, "Incomplete TEE environment configuration\n");
                return -1;
        }

        status = ecall_set_env_config(
                enclave_id, &enclave_status,
                (const uint8_t *)&config, sizeof(config));

        if (status != SGX_SUCCESS ||
            enclave_status != ABAC_TEE_SUCCESS) {
                fprintf(stderr,
                        "Failed to configure TEE environment: "
                        "SGX=0x%x enclave=%d\n",
                        status, enclave_status);
                return -1;
        }

        printf("TEE environment configured: mask=%u window=%u-%u\n",
               config.workday_mask,
               config.work_start_minute,
               config.work_end_minute);

        return 0;
}

static int get_current_environment(abac_tee_env_context_t *environment)
{
        struct tm local_time;
        time_t now;

        if (!environment)
                return -1;

        now = time(NULL);
        if (now == (time_t)-1 ||
            localtime_r(&now, &local_time) == NULL)
                return -1;

        environment->day_of_week = (uint32_t)local_time.tm_wday;
        environment->minute_of_day =
                (uint32_t)(local_time.tm_hour * 60 +
                           local_time.tm_min);

        return 0;
}

static int load_rule(sgx_enclave_id_t enclave_id,
                     const abac_tee_rule_data_t *rule)
{
        int enclave_status = ABAC_TEE_INVALID_REQUEST;
        sgx_status_t status;

        status = ecall_load_rule(enclave_id, &enclave_status,
                                 (const uint8_t *)rule, sizeof(*rule));
        if (status != SGX_SUCCESS ||
            enclave_status != ABAC_TEE_SUCCESS) {
                fprintf(stderr,
                        "Failed to load rule %u: SGX=0x%x enclave=%d\n",
                        rule->rule_id, status, enclave_status);
                return -1;
        }

        return 0;
}

static int load_rules_from_file(sgx_enclave_id_t enclave_id,
                                const char *path)
{
        char line[4096];
        unsigned int line_number = 0;
        int loaded = 0;
        FILE *file;

        file = fopen(path, "r");
        if (!file) {
                perror("open TEE rules file");
                return -1;
        }

        while (fgets(line, sizeof(line), file)) {
                abac_tee_rule_data_t rule = { 0 };
                char *attributes;
                char *saveptr = NULL;
                char *token;
                char *endptr;
                unsigned long rule_id;

                line_number++;
                attributes = strchr(line, '|');
                if (!attributes) {
                        fprintf(stderr, "Invalid TEE rule at line %u\n",
                                line_number);
                        fclose(file);
                        return -1;
                }

                *attributes++ = '\0';
                errno = 0;
                rule_id = strtoul(line, &endptr, 10);
                if (errno || *endptr != '\0' || rule_id == 0 ||
                    rule_id > UINT32_MAX) {
                        fprintf(stderr, "Invalid rule ID at line %u\n",
                                line_number);
                        fclose(file);
                        return -1;
                }
                rule.rule_id = (uint32_t)rule_id;

                token = strtok_r(attributes, ",\r\n", &saveptr);
                while (token) {
                        char *type_text;
                        char *name;
                        char *value;
                        char *colon;
                        char *equals;
                        int type;

                        if (rule.attribute_count >=
                            ABAC_TEE_MAX_ATTRIBUTES) {
                                fprintf(stderr,
                                        "Too many TEE attributes in rule %u\n",
                                        rule.rule_id);
                                fclose(file);
                                return -1;
                        }

                        type_text = token;
                        colon = strchr(token, ':');
                        equals = colon ? strchr(colon + 1, '=') : NULL;
                        if (!colon || !equals) {
                                fprintf(stderr,
                                        "Invalid attribute at line %u\n",
                                        line_number);
                                fclose(file);
                                return -1;
                        }

                        *colon = '\0';
                        *equals = '\0';
                        name = colon + 1;
                        value = equals + 1;
                        type = attribute_type(type_text);

                        if (!type || !*name || !*value ||
                            strlen(name) >= ABAC_TEE_NAME_SIZE ||
                            strlen(value) >= ABAC_TEE_VALUE_SIZE) {
                                fprintf(stderr,
                                        "Invalid attribute at line %u\n",
                                        line_number);
                                fclose(file);
                                return -1;
                        }

                        set_attribute(&rule, rule.attribute_count,
                                      (uint32_t)type, name, value);
                        rule.attribute_count++;
                        token = strtok_r(NULL, ",\r\n", &saveptr);
                }

                if (rule.attribute_count == 0 ||
                    load_rule(enclave_id, &rule) != 0) {
                        fclose(file);
                        return -1;
                }

                loaded++;
        }

        if (ferror(file)) {
                perror("read TEE rules file");
                fclose(file);
                return -1;
        }

        fclose(file);
        return loaded;
}

int main(void)
{
        sgx_launch_token_t launch_token = { 0 };
        sgx_misc_attribute_t misc_attributes = { 0 };
        sgx_enclave_id_t enclave_id = 0;
        int launch_token_updated = 0;
        int request_fd;
        int response_fd;
        int loaded_rules;
        sgx_status_t status;

        status = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG,
                                    &launch_token, &launch_token_updated,
                                    &enclave_id, &misc_attributes);
        if (status != SGX_SUCCESS) {
                fprintf(stderr, "sgx_create_enclave failed: 0x%x\n", status);
                return 1;
        }

        if (load_environment_config(enclave_id, TEE_ENV_FILE) != 0) {
                sgx_destroy_enclave(enclave_id);
                return 1;
        }

        loaded_rules = load_rules_from_file(enclave_id, TEE_RULES_FILE);
        if (loaded_rules < 0) {
                sgx_destroy_enclave(enclave_id);
                return 1;
        }

        request_fd = open(TEE_REQUEST_FILE, O_RDONLY);
        if (request_fd < 0) {
                perror("open tee_request");
                sgx_destroy_enclave(enclave_id);
                return 1;
        }

        response_fd = open(TEE_RESPONSE_FILE, O_WRONLY);
        if (response_fd < 0) {
                perror("open tee_response");
                close(request_fd);
                sgx_destroy_enclave(enclave_id);
                return 1;
        }

        printf("ABAC TEE daemon ready; %d rule(s) loaded\n",
               loaded_rules);
        fflush(stdout);

        for (;;) {
                abac_tee_ipc_request_t request;
                abac_tee_ipc_response_t response = { 0 };
                abac_tee_eval_data_t evaluation = { 0 };
                int enclave_status = ABAC_TEE_INVALID_REQUEST;
                int matched = 0;
                ssize_t bytes;

                bytes = read(request_fd, &request, sizeof(request));
                if (bytes < 0) {
                        if (errno == EINTR)
                                continue;
                        perror("read tee_request");
                        break;
                }
                if ((size_t)bytes != sizeof(request)) {
                        fprintf(stderr, "Invalid TEE request size: %zd\n",
                                bytes);
                        continue;
                }

                response.request_id = request.request_id;
                evaluation.rule = request.rule;

                if (get_current_environment(
                            &evaluation.environment) != 0) {
                        response.status =
                                ABAC_TEE_SERVICE_UNAVAILABLE;
                        response.matched = 0;
                } else {
                        status = ecall_evaluate_rule(
                                enclave_id, &enclave_status,
                                (const uint8_t *)&evaluation,
                                sizeof(evaluation), &matched);

                        if (status != SGX_SUCCESS) {
                                response.status =
                                        ABAC_TEE_SERVICE_UNAVAILABLE;
                                response.matched = 0;
                        } else {
                                response.status = enclave_status;
                                response.matched = matched;
                        }
                }

                bytes = write(response_fd, &response, sizeof(response));
                if ((size_t)bytes != sizeof(response)) {
                        if (bytes < 0)
                                perror("write tee_response");
                        else
                                fprintf(stderr,
                                        "Invalid TEE response write: %zd\n",
                                        bytes);
                        break;
                }

                printf("request=%llu rule=%u attributes=%u result=%s\n",
                       (unsigned long long)request.request_id,
                       request.rule.rule_id,
                       request.rule.attribute_count,
                       response.matched ? "MATCH" : "NO MATCH");
                fflush(stdout);
        }

        close(response_fd);
        close(request_fd);
        sgx_destroy_enclave(enclave_id);
        return 1;
}
