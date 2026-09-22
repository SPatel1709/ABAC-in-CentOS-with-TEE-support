#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_ecall_load_rule(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_load_rule_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_load_rule_t* ms = SGX_CAST(ms_ecall_load_rule_t*, pms);
	ms_ecall_load_rule_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_load_rule_t), ms, sizeof(ms_ecall_load_rule_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_rule_data = __in_ms.ms_rule_data;
	size_t _tmp_rule_size = __in_ms.ms_rule_size;
	size_t _len_rule_data = _tmp_rule_size;
	uint8_t* _in_rule_data = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_rule_data, _len_rule_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_rule_data != NULL && _len_rule_data != 0) {
		if ( _len_rule_data % sizeof(*_tmp_rule_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_rule_data = (uint8_t*)malloc(_len_rule_data);
		if (_in_rule_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_rule_data, _len_rule_data, _tmp_rule_data, _len_rule_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	_in_retval = ecall_load_rule((const uint8_t*)_in_rule_data, _tmp_rule_size);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_rule_data) free(_in_rule_data);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_evaluate_rule(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_evaluate_rule_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_evaluate_rule_t* ms = SGX_CAST(ms_ecall_evaluate_rule_t*, pms);
	ms_ecall_evaluate_rule_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_evaluate_rule_t), ms, sizeof(ms_ecall_evaluate_rule_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_request_data = __in_ms.ms_request_data;
	size_t _tmp_request_size = __in_ms.ms_request_size;
	size_t _len_request_data = _tmp_request_size;
	uint8_t* _in_request_data = NULL;
	int* _tmp_matched = __in_ms.ms_matched;
	size_t _len_matched = sizeof(int);
	int* _in_matched = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_request_data, _len_request_data);
	CHECK_UNIQUE_POINTER(_tmp_matched, _len_matched);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_request_data != NULL && _len_request_data != 0) {
		if ( _len_request_data % sizeof(*_tmp_request_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_request_data = (uint8_t*)malloc(_len_request_data);
		if (_in_request_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_request_data, _len_request_data, _tmp_request_data, _len_request_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_matched != NULL && _len_matched != 0) {
		if ( _len_matched % sizeof(*_tmp_matched) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_matched = (int*)malloc(_len_matched)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_matched, 0, _len_matched);
	}
	_in_retval = ecall_evaluate_rule((const uint8_t*)_in_request_data, _tmp_request_size, _in_matched);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_matched) {
		if (memcpy_verw_s(_tmp_matched, _len_matched, _in_matched, _len_matched)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_request_data) free(_in_request_data);
	if (_in_matched) free(_in_matched);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_clear_rules(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_clear_rules_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_clear_rules_t* ms = SGX_CAST(ms_ecall_clear_rules_t*, pms);
	ms_ecall_clear_rules_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_clear_rules_t), ms, sizeof(ms_ecall_clear_rules_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	int _in_retval;


	_in_retval = ecall_clear_rules();
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[3];
} g_ecall_table = {
	3,
	{
		{(void*)(uintptr_t)sgx_ecall_load_rule, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_evaluate_rule, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_clear_rules, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


