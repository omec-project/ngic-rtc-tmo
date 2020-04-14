#include "sgx_tcdr_u.h"
#include <errno.h>

typedef struct ms_ecall_sgx_tcdr_t {
	int ms_retval;
} ms_ecall_sgx_tcdr_t;

typedef struct ms_u_sgxcdr_connect_cdr_mq_t {
	void* ms_retval;
	char* ms_host;
	uint16_t ms_port;
	uint8_t ms_pattern;
} ms_u_sgxcdr_connect_cdr_mq_t;

typedef struct ms_u_sgxcdr_get_cdr_message_t {
	int32_t ms_retval;
	void* ms_handle;
	uint8_t* ms_buffer;
	uint32_t ms_buffer_size;
} ms_u_sgxcdr_get_cdr_message_t;

typedef struct ms_u_sgxcdr_send_cdr_message_t {
	int32_t ms_retval;
	void* ms_handle;
	uint8_t* ms_buffer;
	uint32_t ms_buffer_size;
} ms_u_sgxcdr_send_cdr_message_t;

typedef struct ms_u_sgxcdr_close_cdr_mq_t {
	int32_t ms_retval;
	void* ms_handle;
} ms_u_sgxcdr_close_cdr_mq_t;

typedef struct ms_u_sgxcdr_connect_to_zmq_router_t {
	void* ms_retval;
	char* ms_host;
	uint16_t ms_port;
	uint8_t ms_mode;
	char* ms_identity;
	int8_t* ms_err;
	void* ms_context;
} ms_u_sgxcdr_connect_to_zmq_router_t;

typedef struct ms_u_sgxcdr_send_zmq_router_socket_t {
	int32_t ms_retval;
	void* ms_handle;
	uint8_t* ms_buffer;
	uint32_t ms_buffer_size;
} ms_u_sgxcdr_send_zmq_router_socket_t;

typedef struct ms_u_sgxcdr_zmq_router_read_poll_t {
	void* ms_handle;
	uint32_t ms_msec;
	int8_t* ms_result;
	uint8_t* ms_buffer;
	uint32_t ms_buffer_size;
} ms_u_sgxcdr_zmq_router_read_poll_t;

typedef struct ms_u_sgxcdr_recv_zmq_router_socket_t {
	void* ms_handle;
	uint8_t* ms_buffer;
	uint32_t ms_buffer_size;
	int32_t* ms_actual_read;
} ms_u_sgxcdr_recv_zmq_router_socket_t;

typedef struct ms_u_sgxcdr_close_zmq_router_t {
	int32_t ms_retval;
	void* ms_handle;
	void* ms_context;
} ms_u_sgxcdr_close_zmq_router_t;

typedef struct ms_u_sgxprotectedfs_exclusive_file_open_t {
	void* ms_retval;
	char* ms_filename;
	uint8_t ms_read_only;
	int64_t* ms_file_size;
	int32_t* ms_error_code;
} ms_u_sgxprotectedfs_exclusive_file_open_t;

typedef struct ms_u_sgxprotectedfs_check_if_file_exists_t {
	uint8_t ms_retval;
	char* ms_filename;
} ms_u_sgxprotectedfs_check_if_file_exists_t;

typedef struct ms_u_sgxprotectedfs_fread_node_t {
	int32_t ms_retval;
	void* ms_f;
	uint64_t ms_node_number;
	uint8_t* ms_buffer;
	uint32_t ms_node_size;
} ms_u_sgxprotectedfs_fread_node_t;

typedef struct ms_u_sgxprotectedfs_fwrite_node_t {
	int32_t ms_retval;
	void* ms_f;
	uint64_t ms_node_number;
	uint8_t* ms_buffer;
	uint32_t ms_node_size;
} ms_u_sgxprotectedfs_fwrite_node_t;

typedef struct ms_u_sgxprotectedfs_fclose_t {
	int32_t ms_retval;
	void* ms_f;
} ms_u_sgxprotectedfs_fclose_t;

typedef struct ms_u_sgxprotectedfs_fflush_t {
	uint8_t ms_retval;
	void* ms_f;
} ms_u_sgxprotectedfs_fflush_t;

typedef struct ms_u_sgxprotectedfs_remove_t {
	int32_t ms_retval;
	char* ms_filename;
} ms_u_sgxprotectedfs_remove_t;

typedef struct ms_u_sgxprotectedfs_recovery_file_open_t {
	void* ms_retval;
	char* ms_filename;
} ms_u_sgxprotectedfs_recovery_file_open_t;

typedef struct ms_u_sgxprotectedfs_fwrite_recovery_node_t {
	uint8_t ms_retval;
	void* ms_f;
	uint8_t* ms_data;
	uint32_t ms_data_length;
} ms_u_sgxprotectedfs_fwrite_recovery_node_t;

typedef struct ms_u_sgxprotectedfs_do_file_recovery_t {
	int32_t ms_retval;
	char* ms_filename;
	char* ms_recovery_filename;
	uint32_t ms_node_size;
} ms_u_sgxprotectedfs_do_file_recovery_t;

static sgx_status_t SGX_CDECL sgx_tcdr_u_sgxcdr_connect_cdr_mq(void* pms)
{
	ms_u_sgxcdr_connect_cdr_mq_t* ms = SGX_CAST(ms_u_sgxcdr_connect_cdr_mq_t*, pms);
	ms->ms_retval = u_sgxcdr_connect_cdr_mq((const char*)ms->ms_host, ms->ms_port, ms->ms_pattern);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL sgx_tcdr_u_sgxcdr_get_cdr_message(void* pms)
{
	ms_u_sgxcdr_get_cdr_message_t* ms = SGX_CAST(ms_u_sgxcdr_get_cdr_message_t*, pms);
	ms->ms_retval = u_sgxcdr_get_cdr_message(ms->ms_handle, ms->ms_buffer, ms->ms_buffer_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL sgx_tcdr_u_sgxcdr_send_cdr_message(void* pms)
{
	ms_u_sgxcdr_send_cdr_message_t* ms = SGX_CAST(ms_u_sgxcdr_send_cdr_message_t*, pms);
	ms->ms_retval = u_sgxcdr_send_cdr_message(ms->ms_handle, ms->ms_buffer, ms->ms_buffer_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL sgx_tcdr_u_sgxcdr_close_cdr_mq(void* pms)
{
	ms_u_sgxcdr_close_cdr_mq_t* ms = SGX_CAST(ms_u_sgxcdr_close_cdr_mq_t*, pms);
	ms->ms_retval = u_sgxcdr_close_cdr_mq(ms->ms_handle);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL sgx_tcdr_u_sgxcdr_connect_to_zmq_router(void* pms)
{
	ms_u_sgxcdr_connect_to_zmq_router_t* ms = SGX_CAST(ms_u_sgxcdr_connect_to_zmq_router_t*, pms);
	ms->ms_retval = u_sgxcdr_connect_to_zmq_router((const char*)ms->ms_host, ms->ms_port, ms->ms_mode, (const char*)ms->ms_identity, ms->ms_err, ms->ms_context);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL sgx_tcdr_u_sgxcdr_send_zmq_router_socket(void* pms)
{
	ms_u_sgxcdr_send_zmq_router_socket_t* ms = SGX_CAST(ms_u_sgxcdr_send_zmq_router_socket_t*, pms);
	ms->ms_retval = u_sgxcdr_send_zmq_router_socket(ms->ms_handle, ms->ms_buffer, ms->ms_buffer_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL sgx_tcdr_u_sgxcdr_zmq_router_read_poll(void* pms)
{
	ms_u_sgxcdr_zmq_router_read_poll_t* ms = SGX_CAST(ms_u_sgxcdr_zmq_router_read_poll_t*, pms);
	u_sgxcdr_zmq_router_read_poll(ms->ms_handle, ms->ms_msec, ms->ms_result, ms->ms_buffer, ms->ms_buffer_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL sgx_tcdr_u_sgxcdr_recv_zmq_router_socket(void* pms)
{
	ms_u_sgxcdr_recv_zmq_router_socket_t* ms = SGX_CAST(ms_u_sgxcdr_recv_zmq_router_socket_t*, pms);
	u_sgxcdr_recv_zmq_router_socket(ms->ms_handle, ms->ms_buffer, ms->ms_buffer_size, ms->ms_actual_read);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL sgx_tcdr_u_sgxcdr_close_zmq_router(void* pms)
{
	ms_u_sgxcdr_close_zmq_router_t* ms = SGX_CAST(ms_u_sgxcdr_close_zmq_router_t*, pms);
	ms->ms_retval = u_sgxcdr_close_zmq_router(ms->ms_handle, ms->ms_context);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL sgx_tcdr_u_sgxprotectedfs_exclusive_file_open(void* pms)
{
	ms_u_sgxprotectedfs_exclusive_file_open_t* ms = SGX_CAST(ms_u_sgxprotectedfs_exclusive_file_open_t*, pms);
	ms->ms_retval = u_sgxprotectedfs_exclusive_file_open((const char*)ms->ms_filename, ms->ms_read_only, ms->ms_file_size, ms->ms_error_code);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL sgx_tcdr_u_sgxprotectedfs_check_if_file_exists(void* pms)
{
	ms_u_sgxprotectedfs_check_if_file_exists_t* ms = SGX_CAST(ms_u_sgxprotectedfs_check_if_file_exists_t*, pms);
	ms->ms_retval = u_sgxprotectedfs_check_if_file_exists((const char*)ms->ms_filename);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL sgx_tcdr_u_sgxprotectedfs_fread_node(void* pms)
{
	ms_u_sgxprotectedfs_fread_node_t* ms = SGX_CAST(ms_u_sgxprotectedfs_fread_node_t*, pms);
	ms->ms_retval = u_sgxprotectedfs_fread_node(ms->ms_f, ms->ms_node_number, ms->ms_buffer, ms->ms_node_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL sgx_tcdr_u_sgxprotectedfs_fwrite_node(void* pms)
{
	ms_u_sgxprotectedfs_fwrite_node_t* ms = SGX_CAST(ms_u_sgxprotectedfs_fwrite_node_t*, pms);
	ms->ms_retval = u_sgxprotectedfs_fwrite_node(ms->ms_f, ms->ms_node_number, ms->ms_buffer, ms->ms_node_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL sgx_tcdr_u_sgxprotectedfs_fclose(void* pms)
{
	ms_u_sgxprotectedfs_fclose_t* ms = SGX_CAST(ms_u_sgxprotectedfs_fclose_t*, pms);
	ms->ms_retval = u_sgxprotectedfs_fclose(ms->ms_f);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL sgx_tcdr_u_sgxprotectedfs_fflush(void* pms)
{
	ms_u_sgxprotectedfs_fflush_t* ms = SGX_CAST(ms_u_sgxprotectedfs_fflush_t*, pms);
	ms->ms_retval = u_sgxprotectedfs_fflush(ms->ms_f);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL sgx_tcdr_u_sgxprotectedfs_remove(void* pms)
{
	ms_u_sgxprotectedfs_remove_t* ms = SGX_CAST(ms_u_sgxprotectedfs_remove_t*, pms);
	ms->ms_retval = u_sgxprotectedfs_remove((const char*)ms->ms_filename);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL sgx_tcdr_u_sgxprotectedfs_recovery_file_open(void* pms)
{
	ms_u_sgxprotectedfs_recovery_file_open_t* ms = SGX_CAST(ms_u_sgxprotectedfs_recovery_file_open_t*, pms);
	ms->ms_retval = u_sgxprotectedfs_recovery_file_open((const char*)ms->ms_filename);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL sgx_tcdr_u_sgxprotectedfs_fwrite_recovery_node(void* pms)
{
	ms_u_sgxprotectedfs_fwrite_recovery_node_t* ms = SGX_CAST(ms_u_sgxprotectedfs_fwrite_recovery_node_t*, pms);
	ms->ms_retval = u_sgxprotectedfs_fwrite_recovery_node(ms->ms_f, ms->ms_data, ms->ms_data_length);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL sgx_tcdr_u_sgxprotectedfs_do_file_recovery(void* pms)
{
	ms_u_sgxprotectedfs_do_file_recovery_t* ms = SGX_CAST(ms_u_sgxprotectedfs_do_file_recovery_t*, pms);
	ms->ms_retval = u_sgxprotectedfs_do_file_recovery((const char*)ms->ms_filename, (const char*)ms->ms_recovery_filename, ms->ms_node_size);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[19];
} ocall_table_sgx_tcdr = {
	19,
	{
		(void*)sgx_tcdr_u_sgxcdr_connect_cdr_mq,
		(void*)sgx_tcdr_u_sgxcdr_get_cdr_message,
		(void*)sgx_tcdr_u_sgxcdr_send_cdr_message,
		(void*)sgx_tcdr_u_sgxcdr_close_cdr_mq,
		(void*)sgx_tcdr_u_sgxcdr_connect_to_zmq_router,
		(void*)sgx_tcdr_u_sgxcdr_send_zmq_router_socket,
		(void*)sgx_tcdr_u_sgxcdr_zmq_router_read_poll,
		(void*)sgx_tcdr_u_sgxcdr_recv_zmq_router_socket,
		(void*)sgx_tcdr_u_sgxcdr_close_zmq_router,
		(void*)sgx_tcdr_u_sgxprotectedfs_exclusive_file_open,
		(void*)sgx_tcdr_u_sgxprotectedfs_check_if_file_exists,
		(void*)sgx_tcdr_u_sgxprotectedfs_fread_node,
		(void*)sgx_tcdr_u_sgxprotectedfs_fwrite_node,
		(void*)sgx_tcdr_u_sgxprotectedfs_fclose,
		(void*)sgx_tcdr_u_sgxprotectedfs_fflush,
		(void*)sgx_tcdr_u_sgxprotectedfs_remove,
		(void*)sgx_tcdr_u_sgxprotectedfs_recovery_file_open,
		(void*)sgx_tcdr_u_sgxprotectedfs_fwrite_recovery_node,
		(void*)sgx_tcdr_u_sgxprotectedfs_do_file_recovery,
	}
};
sgx_status_t ecall_sgx_tcdr(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_sgx_tcdr_t ms;
	status = sgx_ecall(eid, 0, &ocall_table_sgx_tcdr, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

