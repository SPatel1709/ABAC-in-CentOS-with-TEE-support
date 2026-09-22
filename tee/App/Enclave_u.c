#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_load_rule_t {
	int ms_retval;
	const uint8_t* ms_rule_data;
	size_t ms_rule_size;
} ms_ecall_load_rule_t;

typedef struct ms_ecall_evaluate_rule_t {
	int ms_retval;
	const uint8_t* ms_request_data;
	size_t ms_request_size;
	int* ms_matched;
} ms_ecall_evaluate_rule_t;

typedef struct ms_ecall_clear_rules_t {
	int ms_retval;
} ms_ecall_clear_rules_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	0,
	{ NULL },
};
sgx_status_t ecall_load_rule(sgx_enclave_id_t eid, int* retval, const uint8_t* rule_data, size_t rule_size)
{
	sgx_status_t status;
	ms_ecall_load_rule_t ms;
	ms.ms_rule_data = rule_data;
	ms.ms_rule_size = rule_size;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_evaluate_rule(sgx_enclave_id_t eid, int* retval, const uint8_t* request_data, size_t request_size, int* matched)
{
	sgx_status_t status;
	ms_ecall_evaluate_rule_t ms;
	ms.ms_request_data = request_data;
	ms.ms_request_size = request_size;
	ms.ms_matched = matched;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_clear_rules(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_clear_rules_t ms;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

