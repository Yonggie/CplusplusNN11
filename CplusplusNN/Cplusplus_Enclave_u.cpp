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
	int* ms_res;
} ms_SGXSVMTrain_t;

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

static const struct {
	size_t nr_ocall;
	void * func_addr[5];
} ocall_table_Cplusplus_Enclave = {
	5,
	{
		(void*)(uintptr_t)Cplusplus_Enclave_sgx_oc_cpuidex,
		(void*)(uintptr_t)Cplusplus_Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)(uintptr_t)Cplusplus_Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)(uintptr_t)Cplusplus_Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)(uintptr_t)Cplusplus_Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
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

sgx_status_t SGXSVMTrain(sgx_enclave_id_t eid, void* m, void* p, void* problem, int start, int end, int* res)
{
	sgx_status_t status;
	ms_SGXSVMTrain_t ms;
	ms.ms_m = m;
	ms.ms_p = p;
	ms.ms_problem = problem;
	ms.ms_start = start;
	ms.ms_end = end;
	ms.ms_res = res;
	status = sgx_ecall(eid, 2, &ocall_table_Cplusplus_Enclave, &ms);
	return status;
}

