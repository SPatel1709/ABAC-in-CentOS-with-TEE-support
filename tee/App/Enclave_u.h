#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t ecall_load_rule(sgx_enclave_id_t eid, int* retval, const uint8_t* rule_data, size_t rule_size);
sgx_status_t ecall_evaluate_rule(sgx_enclave_id_t eid, int* retval, const uint8_t* request_data, size_t request_size, int* matched);
sgx_status_t ecall_clear_rules(sgx_enclave_id_t eid, int* retval);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
