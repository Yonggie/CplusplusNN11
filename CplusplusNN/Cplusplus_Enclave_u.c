#include "Cplusplus_Enclave_u.h"
#include <errno.h>

typedef struct ms_SGXBayesTrain_t {
	void* ms_m;
	int ms_start;
	int ms_end;
} ms_SGXBayesTrain_t;

typedef struct ms_SGXGetData_t {
	double* ms_data;
} ms_SGXGetData_t;

typedef struct ms_SGXSVMTrain_t {
	void* ms_m;
	void* ms_p;
	void* ms_problem;
	int ms_start;
	int ms_end;
} ms_SGXSVMTrain_t;

typedef struct ms_SGXEncrypt_t {
	sgx_aes_ctr_128bit_key_t* ms_key;
	uint8_t* ms_text;
	uint32_t ms_length;
	uint8_t* ms_counter;
	uint32_t ms_bit;
	uint8_t* ms_result;
} ms_SGXEncrypt_t;

typedef struct ms_SGXDecrypt_t {
	sgx_aes_ctr_128bit_key_t* ms_key;
	uint8_t* ms_text;
	uint32_t ms_length;
	uint8_t* ms_counter;
	uint32_t ms_bit;
	uint8_t* ms_result;
} ms_SGXDecrypt_t;

typedef struct ms_time_t {
	long long ms_retval;
	long long* ms__time;
} ms_time_t;

typedef struct ms_srand_t {
	unsigned int ms_seed;
} ms_srand_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

typedef struct ms_rand_t {
	int ms_retval;
} ms_rand_t;

static sgx_status_t SGX_CDECL Cplusplus_Enclave_time(void* pms)
{
	ms_time_t* ms = SGX_CAST(ms_time_t*, pms);
	ms->ms_retval = time(ms->ms__time);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Cplusplus_Enclave_srand(void* pms)
{
	ms_srand_t* ms = SGX_CAST(ms_srand_t*, pms);
	srand(ms->ms_seed);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Cplusplus_Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Cplusplus_Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Cplusplus_Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Cplusplus_Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Cplusplus_Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Cplusplus_Enclave_rand(void* pms)
{
	ms_rand_t* ms = SGX_CAST(ms_rand_t*, pms);
	ms->ms_retval = rand();

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[8];
} ocall_table_Cplusplus_Enclave = {
	8,
	{
		(void*)(uintptr_t)Cplusplus_Enclave_time,
		(void*)(uintptr_t)Cplusplus_Enclave_srand,
		(void*)(uintptr_t)Cplusplus_Enclave_sgx_oc_cpuidex,
		(void*)(uintptr_t)Cplusplus_Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)(uintptr_t)Cplusplus_Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)(uintptr_t)Cplusplus_Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)(uintptr_t)Cplusplus_Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
		(void*)(uintptr_t)Cplusplus_Enclave_rand,
	}
};

sgx_status_t SGXBayesTrain(sgx_enclave_id_t eid, void* m, int start, int end)
{
	sgx_status_t status;
	ms_SGXBayesTrain_t ms;
	ms.ms_m = m;
	ms.ms_start = start;
	ms.ms_end = end;
	status = sgx_ecall(eid, 0, &ocall_table_Cplusplus_Enclave, &ms);
	return status;
}

sgx_status_t SGXGetData(sgx_enclave_id_t eid, double data[3200][15])
{
	sgx_status_t status;
	ms_SGXGetData_t ms;
	ms.ms_data = (double*)data;
	status = sgx_ecall(eid, 1, &ocall_table_Cplusplus_Enclave, &ms);
	return status;
}

sgx_status_t SGXSVMTrain(sgx_enclave_id_t eid, void* m, void* p, void* problem, int start, int end)
{
	sgx_status_t status;
	ms_SGXSVMTrain_t ms;
	ms.ms_m = m;
	ms.ms_p = p;
	ms.ms_problem = problem;
	ms.ms_start = start;
	ms.ms_end = end;
	status = sgx_ecall(eid, 2, &ocall_table_Cplusplus_Enclave, &ms);
	return status;
}

sgx_status_t SGXEncrypt(sgx_enclave_id_t eid, sgx_aes_ctr_128bit_key_t* key, uint8_t* text, uint32_t length, uint8_t* counter, uint32_t bit, uint8_t* result)
{
	sgx_status_t status;
	ms_SGXEncrypt_t ms;
	ms.ms_key = key;
	ms.ms_text = text;
	ms.ms_length = length;
	ms.ms_counter = counter;
	ms.ms_bit = bit;
	ms.ms_result = result;
	status = sgx_ecall(eid, 3, &ocall_table_Cplusplus_Enclave, &ms);
	return status;
}

sgx_status_t SGXDecrypt(sgx_enclave_id_t eid, sgx_aes_ctr_128bit_key_t* key, uint8_t* text, uint32_t length, uint8_t* counter, uint32_t bit, uint8_t* result)
{
	sgx_status_t status;
	ms_SGXDecrypt_t ms;
	ms.ms_key = key;
	ms.ms_text = text;
	ms.ms_length = length;
	ms.ms_counter = counter;
	ms.ms_bit = bit;
	ms.ms_result = result;
	status = sgx_ecall(eid, 4, &ocall_table_Cplusplus_Enclave, &ms);
	return status;
}

