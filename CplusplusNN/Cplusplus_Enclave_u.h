#ifndef CPLUSPLUS_ENCLAVE_U_H__
#define CPLUSPLUS_ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "sgx_tcrypto.h"
#include "svm.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef TIME_DEFINED__
#define TIME_DEFINED__
long long SGX_UBRIDGE(SGX_NOCONVENTION, time, (long long* _time));
#endif
#ifndef SRAND_DEFINED__
#define SRAND_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, srand, (unsigned int seed));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif
#ifndef RAND_DEFINED__
#define RAND_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, rand, (void));
#endif

sgx_status_t SGXBayesTrain(sgx_enclave_id_t eid, void* m, int start, int end);
sgx_status_t SGXGetData(sgx_enclave_id_t eid, double data[3200][15]);
sgx_status_t SGXSVMTrain(sgx_enclave_id_t eid, void* m, void* p, void* problem, int start, int end);
sgx_status_t SGXEncrypt(sgx_enclave_id_t eid, sgx_aes_ctr_128bit_key_t* key, uint8_t* text, uint32_t length, uint8_t* counter, uint32_t bit, uint8_t* result);
sgx_status_t SGXDecrypt(sgx_enclave_id_t eid, sgx_aes_ctr_128bit_key_t* key, uint8_t* text, uint32_t length, uint8_t* counter, uint32_t bit, uint8_t* result);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
