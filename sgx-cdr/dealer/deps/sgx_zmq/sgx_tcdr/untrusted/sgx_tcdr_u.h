#ifndef SGX_TCDR_U_H__
#define SGX_TCDR_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void* SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxcdr_connect_cdr_mq, (const char* host, uint16_t port, uint8_t pattern));
int32_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxcdr_get_cdr_message, (void* handle, uint8_t* buffer, uint32_t buffer_size));
int32_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxcdr_send_cdr_message, (void* handle, uint8_t* buffer, uint32_t buffer_size));
int32_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxcdr_close_cdr_mq, (void* handle));
void* SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxcdr_connect_to_zmq_router, (const char* host, uint16_t port, uint8_t mode, const char* identity, int8_t* err, void* context));
int32_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxcdr_send_zmq_router_socket, (void* handle, uint8_t* buffer, uint32_t buffer_size));
void SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxcdr_zmq_router_read_poll, (void* handle, uint32_t msec, int8_t* result, uint8_t* buffer, uint32_t buffer_size));
void SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxcdr_recv_zmq_router_socket, (void* handle, uint8_t* buffer, uint32_t buffer_size, int32_t* actual_read));
int32_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxcdr_close_zmq_router, (void* handle, void* context));
void* SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_exclusive_file_open, (const char* filename, uint8_t read_only, int64_t* file_size, int32_t* error_code));
uint8_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_check_if_file_exists, (const char* filename));
int32_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_fread_node, (void* f, uint64_t node_number, uint8_t* buffer, uint32_t node_size));
int32_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_fwrite_node, (void* f, uint64_t node_number, uint8_t* buffer, uint32_t node_size));
int32_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_fclose, (void* f));
uint8_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_fflush, (void* f));
int32_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_remove, (const char* filename));
void* SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_recovery_file_open, (const char* filename));
uint8_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_fwrite_recovery_node, (void* f, uint8_t* data, uint32_t data_length));
int32_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_do_file_recovery, (const char* filename, const char* recovery_filename, uint32_t node_size));

sgx_status_t ecall_sgx_tcdr(sgx_enclave_id_t eid, int* retval);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
