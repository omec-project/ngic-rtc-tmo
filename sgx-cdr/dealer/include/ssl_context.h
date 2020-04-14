//
// Created by fanz on 4/7/17.
//

#ifndef MBEDTLS_SGX_SSL_CONTEXT_H
#define MBEDTLS_SGX_SSL_CONTEXT_H

#include "mbedtls/ssl.h"
#include "mbedtls/net.h"

typedef struct {
  char cdr_file_path[256];
//  char ftp_root_path[256];
  void *output_buffer; 
  int request; 
  unsigned int ftp_pasv_port; 
  unsigned int ftp_server_ip; 
} ftp_params_t;


typedef struct {
  mbedtls_net_context client_fd;
  ftp_params_t ftp_params;
  int thread_complete;
  const mbedtls_ssl_config *config;
  unsigned char client_ip[16];
  size_t ip_len;
  char cdr_router_host[16];
  size_t cdr_router_port;
} thread_info_t;

typedef struct {
	char kmsserver[16];
	char kmsport[6];
	char keynamespace[33];
	char cdrpath[4096];
	char cdrarchpath[4096];
	unsigned long cdrfilesize;
}enclave_params_t;

#endif //MBEDTLS_SGX_SSL_CONTEXT_H
