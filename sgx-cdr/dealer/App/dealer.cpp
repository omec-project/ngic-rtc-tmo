/*
 *  SSL server demonstration program using pthread for handling multiple
 *  clients.
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */


#include <stdio.h>
#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf
#define mbedtls_snprintf   snprintf

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <iostream>
#include <atomic>
#include <csignal>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string>

#include <getopt.h>
#include <assert.h>
#include "options.h"

#include <mbedtls/ssl.h>
#include <mbedtls/net.h>
#include <mbedtls/error.h>
#include "Enclave_u.h"
#include "Utils.h"

#include <sgx_urts.h>
#include <thread>

using std::cerr;
using std::endl;
using std::exit;

typedef struct {
  int active;
  thread_info_t data;
  pthread_t thread;
} pthread_info_t;

int MAX_NUM_THREADS=100;
static pthread_info_t* threads=NULL;
sgx_enclave_id_t eid;

mbedtls_net_context ftp_server_fd;

extern "C" {
void mbedtls_net_free( mbedtls_net_context *ctx );
int mbedtls_net_bind( mbedtls_net_context *ctx, const char *bind_ip, const char *port, int proto );
int mbedtls_net_set_nonblock( mbedtls_net_context *ctx );
int mbedtls_net_accept( mbedtls_net_context *bind_ctx,
                        mbedtls_net_context *client_ctx,
                        void *client_ip, size_t buf_size, size_t *ip_len );
}

void ocall_rename_file(const char *oldname, const char *newname)
{
	rename(oldname, newname);
}

void ocall_date_time(char *date_time)
{
    time_t cur_time;
    struct tm *ptm;
    time(&cur_time);
    ptm = localtime(&cur_time);
    strftime(date_time, 15, "%Y%m%d%H%M%S", ptm);
}

// thread function
void *ecall_handle_ssl_connection(void *data) {
  long int thread_id = pthread_self();
  thread_info_t *thread_info = (thread_info_t *) data;
  ssl_conn_handle(eid, thread_id, thread_info);

  cerr << "thread exiting for thread " << thread_id << endl;
  mbedtls_net_free(&thread_info->client_fd);
  return (NULL);
}


pthread_t* thread_create(ftp_params_t *ftp_params, mbedtls_net_context *client_fd,
  unsigned char client_ip[16], size_t *ip_len, char *cdr_router_host,
  size_t cdr_router_port) {
  int i;

#ifdef SGX_FTPS
  struct sockaddr_in svr_addr;
  unsigned int svr_addr_len = sizeof(svr_addr);

  getsockname(client_fd->fd, (struct sockaddr*)&svr_addr, &svr_addr_len);
  uint32_t svr_host_addr = ntohl(svr_addr.sin_addr.s_addr);
#endif

  for (i = 0; i < MAX_NUM_THREADS; i++) {
    if (threads[i].active == 0)
      break;

    if (threads[i].data.thread_complete == 1) {
      mbedtls_printf("  [ main ]  Cleaning up thread %d\n", i);
      threads[i].active = 0 ;
      pthread_join(threads[i].thread, NULL);
      memset(&threads[i], 0, sizeof(pthread_info_t));
      break;
    }
  }

  if (i == MAX_NUM_THREADS)
    return (NULL);

  threads[i].active = 1;
  threads[i].data.config = NULL;
  threads[i].data.thread_complete = 0;
  memcpy(&threads[i].data.client_fd, client_fd, sizeof(mbedtls_net_context));

#ifdef SGX_FTPS
  if (ftp_params) {
      memcpy(&threads[i].data.ftp_params, ftp_params, sizeof(ftp_params_t));
  } else {
      memset(&threads[i].data.ftp_params, 0, sizeof(ftp_params_t));
  }
  threads[i].data.ftp_params.ftp_pasv_port = std::stoi(Options::dealerPort())-1;  
  threads[i].data.ftp_params.ftp_server_ip = svr_host_addr;  
#endif

//  memcpy(threads[i].data.ftp_params.ftp_root_path,Options::cdrPath().c_str(),sizeof(ftp_params.ftp_root_path));  
  memset(threads[i].data.client_ip, 0, 16);
  memcpy(threads[i].data.client_ip, client_ip, *ip_len);
  threads[i].data.ip_len = *ip_len;

  if (cdr_router_host && cdr_router_port) {
      memset(threads[i].data.cdr_router_host, 0, 16);
      memcpy(threads[i].data.cdr_router_host, cdr_router_host, 16);
      threads[i].data.cdr_router_port = cdr_router_port;
  }

  if (pthread_create(&threads[i].thread, NULL, ecall_handle_ssl_connection, &threads[i].data) != 0) {
    return (NULL);
  }

  return (&threads[i].thread);
}

#define FILE_LISTING 5
#define FILE_TRANSFER 6
#define _2MB (2*1024*1024)
#define CMD_BUF_SZ 1024

void ocall_handle_ftp_data(int request, const char *filename, int *ftp_status) {

   int ret,i;
   mbedtls_net_context client_fd;
   unsigned char client_ip[16] = {0};
   size_t ip_len;
   ftp_params_t ftp_params;
	pthread_t *thread;

   mbedtls_printf("Waiting for passive connection from FTP Client\n");
   ret = mbedtls_net_accept(&ftp_server_fd, &client_fd, client_ip, sizeof(client_ip), &ip_len);
    if ((ret != 0) && (ret != MBEDTLS_ERR_SSL_WANT_READ)) {
      mbedtls_printf("  [ ocall_handle_ftp_data ] failed: mbedtls_net_accept returned -0x%04x\n", ret);
      *ftp_status = -1;
      return;
    }

   if (request == FILE_LISTING) { //File Listing
       FILE *popen_file;
       char cmd_buffer[CMD_BUF_SZ];  
       char output_buffer[_2MB]; //Max 2MB of listing output supported 
       snprintf(cmd_buffer, CMD_BUF_SZ, "ls -al %s/%s", Options::cdrArchPath().c_str(),filename);
       mbedtls_printf("%s\n",cmd_buffer);
       popen_file = popen(cmd_buffer, "r");
       assert(popen_file);
       for (i = 0; (i < _2MB) && (!feof(popen_file)); i++) {
            output_buffer[i] = fgetc(popen_file);   
       }
       output_buffer[--i] = '\0';
       fclose(popen_file);
       ftp_params.output_buffer = output_buffer;
       ftp_params.request = request; //File Listing 
   } else if (request == FILE_TRANSFER) { // File Transfer
       ftp_params.request = request; //File Listing 
       snprintf(ftp_params.cdr_file_path, sizeof(ftp_params.cdr_file_path), "%s/%s", Options::cdrArchPath().c_str(),filename);
   } else { // Unsupported request
       mbedtls_printf("Unsupported FTP handling request");
       *ftp_status = -2;
       return;
   }
       
   
   mbedtls_printf("creating FTP data thread\n");
    if ((thread = thread_create(&ftp_params, &client_fd, client_ip, &ip_len, NULL, 0)) == NULL) {
      mbedtls_printf("  [ main ]  failed: thread_create returned %d\n", ret);
      mbedtls_net_free(&client_fd);
      *ftp_status = -3;
      return;
    }

   mbedtls_printf("created FTP data thread...waiting to join\n");
   pthread_join(*thread, NULL);
   mbedtls_printf("FTP data thread joined...exiting ocall\n");
   *ftp_status = 0; 
   return;
}
 
void ocall_handle_ftp_data_dele(const char *filename, int *ftp_status) {
   char cmd_buffer[CMD_BUF_SZ];
   snprintf(cmd_buffer, CMD_BUF_SZ, "%s%s", Options::cdrArchPath().c_str(),filename);
   mbedtls_printf("%s\n",cmd_buffer);
   remove(cmd_buffer);
   *ftp_status = 0;
   return;
}

void *offline_processing(void *data)
{

	thread_info_t *thread_info = (thread_info_t *) data;

	while (1) {
		printf("cdr host %s and port %zu \n", thread_info->cdr_router_host, thread_info->cdr_router_port);
		offline_handle(eid, thread_info);
		sleep(5);
	}
	return NULL;
}

#ifndef SGX_FTPS
static int offlinemode_thread(char *cdr_router_host, size_t cdr_router_port)
{
	int ret;

	pthread_info_t *thread = new pthread_info_t();

	thread->data.config = NULL;
	thread->data.thread_complete = 0;
	memset(thread->data.cdr_router_host, 0, 16);
	memcpy(thread->data.cdr_router_host, cdr_router_host, 16);
	thread->data.cdr_router_port = cdr_router_port;

	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	if ((ret = pthread_create(&thread->thread, &attr, offline_processing, &thread->data)) != 0)
	{
		return (ret);
	}

	return (0);
}
#endif

std::atomic<bool> quit(false);
void exitGraceful(int) { quit.store(true); }



int main(int argc, char *argv[]) {
  int ret;
  int run_mode = 0;
  char cdr_router_host[16] = {0};
  size_t cdr_router_port;
  enclave_params_t params;

  std::signal(SIGINT, exitGraceful);

  if ( !Options::parse( argc, argv ) )
  {
    std::cout << "Options::parse() failed" << std::endl;
    return 1;
  }

  // print provided options
  std::cout << "Options::jsonConfig            : " << Options::jsonConfig() << std::endl;
  std::cout << "Options::runMode               : " << Options::runMode() << std::endl;
  std::cout << "Options::port         	       : " << Options::dealerPort() << std::endl;
  std::cout << "Options::cdrRouterHost         : " << Options::cdrRouterHost() << std::endl;
  std::cout << "Options::cdrRouterPort         : " << Options::cdrRouterPort() << std::endl;
  std::cout << "Options::maxConnections        : " << Options::maxConnections() << std::endl;
  std::cout << "Options::kmsServer	       : " << Options::kmsServer() << std::endl;
  std::cout << "Options::kmsPort 	       : " << Options::kmsPort() << std::endl;
  std::cout << "Options::keyNamespace	       : " << Options::keyNamespace() << std::endl;
  std::cout << "Options::cdrPath     	       : " << Options::cdrPath() << std::endl;
  std::cout << "Options::cdrArchPath	       : " << Options::cdrArchPath() << std::endl;
  std::cout << "Options::cdrfilesize	       : " << Options::cdrFileSize() << std::endl;

  // set run mode
  if( Options::runMode() == std::string("IN"))
  {
	run_mode = 1;
  }
  else if( Options::runMode() == std::string("OUT"))
  {
	run_mode = 2;
  }
  else
  {
	run_mode = -1;
	std::cout << "Invalid run mode " << run_mode << ". It must be IN|OUT" << std::endl;
	exit(-1);
  }

  // KMS options
  memset(params.kmsserver, 0, 16);
  strncpy(params.kmsserver, Options::kmsServer().c_str(), 16);
  memset(params.kmsport, 0 ,6);
  strncpy(params.kmsport, Options::kmsPort().c_str(), 6);
  memset(params.keynamespace, 0, 33);
  strncpy(params.keynamespace, Options::keyNamespace().c_str(), 33);
  memset(params.cdrpath, 0, 4096);
  strncpy(params.cdrpath, Options::cdrPath().c_str(), Options::cdrPath().size());
  memset(params.cdrarchpath, 0, 4096);
  strncpy(params.cdrarchpath, Options::cdrArchPath().c_str(), Options::cdrArchPath().size());
  params.cdrfilesize =  Options::cdrFileSize();

  // set CDR router options
  strncpy(cdr_router_host, Options::cdrRouterHost().c_str(), 16);
  cdr_router_port = Options::cdrRouterPort();

  // set max thread
  MAX_NUM_THREADS = Options::maxConnections();
  threads = new pthread_info_t[MAX_NUM_THREADS];
  if(threads == NULL)
  {
     std::cout << "Failed to create a thread pool for pool size " << MAX_NUM_THREADS << std::endl;
     return -1;
  }
  else
  {
     std::cout << "Setting max number of threads to " << MAX_NUM_THREADS << std::endl;
  }
  // clear memory
  memset(threads, 0, sizeof(pthread_info_t)*MAX_NUM_THREADS);

  if (0 != initialize_enclave(&eid)) {
    cerr << "failed to init enclave" << endl;
    exit(-1);
  }

  mbedtls_net_context listen_fd, client_fd;

  sgx_status_t res;
  ssl_conn_init(eid, run_mode, &params, &res);

  if (res != SGX_SUCCESS)
    std::exit(-1);
	
  //TODO: check retrun value and exit
  memset(threads, 0, sizeof(pthread_info_t)*MAX_NUM_THREADS);

#ifndef SGX_FTPS
  if (run_mode == 2)
    offlinemode_thread(cdr_router_host, cdr_router_port);
#endif

  mbedtls_printf("Bind on https://localhost:%s\n", Options::dealerPort().c_str());
  fflush(stdout);

  if ((ret = mbedtls_net_bind(&listen_fd, NULL, Options::dealerPort().c_str(), MBEDTLS_NET_PROTO_TCP)) != 0) {
    mbedtls_printf(" failed\n  ! mbedtls_net_bind returned %d\n\n", ret);
    std::exit(-1);
  }

#ifdef SGX_FTPS
  mbedtls_printf("Bind on https://localhost:%s\n", std::to_string(std::stoi(Options::dealerPort())-1).c_str());
  fflush(stdout);

  if ((ret = mbedtls_net_bind(&ftp_server_fd, NULL, std::to_string(std::stoi(Options::dealerPort())-1).c_str(), MBEDTLS_NET_PROTO_TCP)) != 0) {
    mbedtls_printf(" failed\n  ! mbedtls_net_bind returned %d\n\n", ret);
    std::exit(-1);
  }
#endif

  if (run_mode == 1)
    mbedtls_printf("Waiting for remote connection from CP\n");
  else
    mbedtls_printf("Waiting for remote connection from trusted CTF\n");

  while (true) {
    std::this_thread::sleep_for (std::chrono::seconds(1));
    if (quit.load()) {
      cerr << "Ctrl-C pressed. Quiting..." << endl;
      break;
    }

    /*
     * 3. Wait until a client connects
     */

    if (0 != mbedtls_net_set_nonblock(&listen_fd)) {
      cerr << "can't set nonblock for the listen socket" << endl;
    }

    unsigned char client_ip[16] = {0};
    size_t ip_len;
    ret = mbedtls_net_accept(&listen_fd, &client_fd, client_ip,
      sizeof(client_ip), &ip_len);
    if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
      ret = 0;
      continue;
    } else if (ret != 0) {
      mbedtls_printf("  [ main ] failed: mbedtls_net_accept returned -0x%04x\n", ret);
      break;
    }

    mbedtls_printf("  [ main ]  ok\n");
    mbedtls_printf("  [ main ]  Creating a new thread for client %d\n", client_fd.fd);

    if (thread_create(NULL, &client_fd, client_ip, &ip_len, cdr_router_host,
      cdr_router_port) == NULL) {
      mbedtls_printf("  [ main ]  failed: thread_create returned %d\n", ret);
      mbedtls_net_free(&client_fd);
      continue;
    }
    ret = 0;
  } // while (true)
  delete threads;
  ssl_conn_teardown(eid);
  sgx_destroy_enclave(eid);
  return (ret);
}
