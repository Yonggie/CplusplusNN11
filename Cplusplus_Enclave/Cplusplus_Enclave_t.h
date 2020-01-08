#ifndef CPLUSPLUS_ENCLAVE_T_H__
#define CPLUSPLUS_ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_tcrypto.h"
#include "svm.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGXBayesTrain(void* m, int start, int end);
void SGXGetData(double data[3200][15]);
void SGXSVMTrain(void* m, void* p, void* problem, int start, int end);
void SGXEncrypt(sgx_aes_ctr_128bit_key_t* key, uint8_t* text, uint32_t length, uint8_t* counter, uint32_t bit, uint8_t* result);
void SGXDecrypt(sgx_aes_ctr_128bit_key_t* key, uint8_t* text, uint32_t length, uint8_t* counter, uint32_t bit, uint8_t* result);

sgx_status_t SGX_CDECL time(long long* retval, long long* _time);
sgx_status_t SGX_CDECL srand(unsigned int seed);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);
sgx_status_t SGX_CDECL rand(int* retval);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
