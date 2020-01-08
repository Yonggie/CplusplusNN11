#include "Cplusplus_Enclave_t.h"

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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#endif

static sgx_status_t SGX_CDECL sgx_SGXBayesTrain(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_SGXBayesTrain_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_SGXBayesTrain_t* ms = SGX_CAST(ms_SGXBayesTrain_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_m = ms->ms_m;
	size_t _len_m = 1024;
	void* _in_m = NULL;

	CHECK_UNIQUE_POINTER(_tmp_m, _len_m);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_m != NULL && _len_m != 0) {
		_in_m = (void*)malloc(_len_m);
		if (_in_m == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_m, _len_m, _tmp_m, _len_m)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	SGXBayesTrain(_in_m, ms->ms_start, ms->ms_end);

err:
	if (_in_m) free(_in_m);
	return status;
}

static sgx_status_t SGX_CDECL sgx_SGXGetData(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_SGXGetData_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_SGXGetData_t* ms = SGX_CAST(ms_SGXGetData_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	double* _tmp_data = ms->ms_data;
	size_t _len_data = 48000 * sizeof(double);
	double* _in_data = NULL;

	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_data != NULL && _len_data != 0) {
		if ( _len_data % sizeof(*_tmp_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_data = (double*)malloc(_len_data);
		if (_in_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_data, _len_data, _tmp_data, _len_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	SGXGetData((double (*)[15])_in_data);

err:
	if (_in_data) free(_in_data);
	return status;
}

static sgx_status_t SGX_CDECL sgx_SGXSVMTrain(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_SGXSVMTrain_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_SGXSVMTrain_t* ms = SGX_CAST(ms_SGXSVMTrain_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_m = ms->ms_m;
	void* _tmp_p = ms->ms_p;
	void* _tmp_problem = ms->ms_problem;



	SGXSVMTrain(_tmp_m, _tmp_p, _tmp_problem, ms->ms_start, ms->ms_end);


	return status;
}

static sgx_status_t SGX_CDECL sgx_SGXEncrypt(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_SGXEncrypt_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_SGXEncrypt_t* ms = SGX_CAST(ms_SGXEncrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_aes_ctr_128bit_key_t* _tmp_key = ms->ms_key;
	uint8_t* _tmp_text = ms->ms_text;
	uint8_t* _tmp_counter = ms->ms_counter;
	uint8_t* _tmp_result = ms->ms_result;



	SGXEncrypt(_tmp_key, _tmp_text, ms->ms_length, _tmp_counter, ms->ms_bit, _tmp_result);


	return status;
}

static sgx_status_t SGX_CDECL sgx_SGXDecrypt(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_SGXDecrypt_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_SGXDecrypt_t* ms = SGX_CAST(ms_SGXDecrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_aes_ctr_128bit_key_t* _tmp_key = ms->ms_key;
	uint8_t* _tmp_text = ms->ms_text;
	uint8_t* _tmp_counter = ms->ms_counter;
	uint8_t* _tmp_result = ms->ms_result;



	SGXDecrypt(_tmp_key, _tmp_text, ms->ms_length, _tmp_counter, ms->ms_bit, _tmp_result);


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv;} ecall_table[5];
} g_ecall_table = {
	5,
	{
		{(void*)(uintptr_t)sgx_SGXBayesTrain, 0},
		{(void*)(uintptr_t)sgx_SGXGetData, 0},
		{(void*)(uintptr_t)sgx_SGXSVMTrain, 0},
		{(void*)(uintptr_t)sgx_SGXEncrypt, 0},
		{(void*)(uintptr_t)sgx_SGXDecrypt, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[8][5];
} g_dyn_entry_table = {
	8,
	{
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL time(long long* retval, long long* _time)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_time_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_time_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_time_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_time_t));
	ocalloc_size -= sizeof(ms_time_t);

	ms->ms__time = _time;
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL srand(unsigned int seed)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_srand_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_srand_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_srand_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_srand_t));
	ocalloc_size -= sizeof(ms_srand_t);

	ms->ms_seed = seed;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	ms->ms_self = self;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	ms->ms_waiter = waiter;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	ms->ms_waiter = waiter;
	ms->ms_self = self;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		ms->ms_waiters = (const void**)__tmp;
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL rand(int* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_rand_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_rand_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_rand_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_rand_t));
	ocalloc_size -= sizeof(ms_rand_t);

	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
