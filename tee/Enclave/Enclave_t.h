#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int ecall_load_rule(const uint8_t* rule_data, size_t rule_size);
int ecall_evaluate_rule(const uint8_t* request_data, size_t request_size, int* matched);
int ecall_clear_rules(void);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
