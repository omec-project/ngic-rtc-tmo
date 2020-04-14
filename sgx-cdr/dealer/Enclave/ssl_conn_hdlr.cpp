/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// dpdk formatting
// remove dead/commented code
#include "ssl_conn_hdlr.h"

#include <exception>
#include <map>
#include <string>
#include <mbedtls/net.h>
#include <mbedtls/debug.h>
#include "glue.h"
#include "helper.h"
#include "crypto.h"
#include "kms_client.h"
#include "Enclave_t.h"

#define LONG_RESPONSE "<p>01-blah-blah-blah-blah-blah-blah-blah-blah-blah\r\n" \
    "02-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah\r\n"  \
    "03-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah\r\n"  \
    "04-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah\r\n"  \
    "05-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah\r\n"  \
    "06-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah\r\n"  \
    "07-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah</p>\r\n"

/* Uncomment LONG_RESPONSE at the end of HTTP_RESPONSE to test sending longer
 * packets (for fragmentation purposes) */
#define HTTP_RESPONSE \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>mbed TLS Test Server</h2>\r\n" \
    "<p>Successful connection using: %s</p>\r\n" // LONG_RESPONSE

/*
 AAD can not be set as stream name. We support named/unnamed stream for live mode.
 for unnamed stream, there will be no identity at dealer OUT side. unnamed stream
 can match to any named stream.
*/
#define KMS_KEY_FILE "./kms_key.dat"
#define KEY_CERT_FILE "./key_cert.dat"
unsigned long cdrfilesize = (10*1024*1024); // 10MB

static Crypto AESGCM(CRYPTO_TYPE_AES_GCM);

std::map<std::string, int> seqmap;

extern "C" {
void create_key_and_x509(mbedtls_pk_context*, mbedtls_x509_crt*, uint8_t* der_cert, int* der_cert_len, uint8_t* der_key, int* der_key_len);
void handle_ftp_control(mbedtls_ssl_context* ssl, uint32_t ftp_pasv_port, uint32_t ftp_server_ip);
}

const int TLSConnectionHandler::ip_str_len = 16;
const int TLSConnectionHandler::enc_str_size = 256;

// ************ helper functions *******************************************

// ****************************************************************************

/**
 * @Name : TLSConnectionHandler
 * @return : Returns none
 * @Description : Function to initialize SSL config and other stuff
 */
TLSConnectionHandler::TLSConnectionHandler(enclave_params_t *p, sgx_status_t  *res) {
	int ret;

	//process enclave parameters
	kmsserver = (char*) p->kmsserver;
	kmsport = (char*) p->kmsport;
	keynamespace = (char*) p->keynamespace;

        peercert = NULL;
	m_cdrPath = string(p->cdrpath);
	m_cdrArchPath = string(p->cdrarchpath);
	cdrfilesize = p->cdrfilesize;

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
	unsigned char alloc_buf[100000];
#endif
#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_cache_context cache;
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
	mbedtls_memory_buffer_alloc_init( alloc_buf, sizeof(alloc_buf) );
#endif

#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_cache_init(&cache);
#endif

	mbedtls_entropy_init(&entropy);
	mbedtls_x509_crt_init(&cachain);
	mbedtls_pk_init(&pkey);
	mbedtls_x509_crt_init(&srvcert);
	// create key and cert only once

   	int32_t der_key_len = 2048;
   	int32_t der_crt_len = 8192;
   	int32_t size = der_key_len + der_crt_len;
   	uint8_t *temp_buff = (uint8_t *) malloc(size);
   	memset(temp_buff, 0, size);

   	// Attempt to read key and cert from protected key file
   	// If key is found in file then use it 
   	ret  = unseal_from_file(temp_buff, (uint32_t *)&size, KEY_CERT_FILE); 

   	if ((ret == SGX_SUCCESS) && (size == (der_key_len + der_crt_len))) {

            ret = mbedtls_pk_parse_key(&pkey, temp_buff, der_key_len, NULL, NULL);

            if (ret != SGX_SUCCESS) { //could not write to secured file 
               mbedtls_printf("ERROR key load failed\n");
	       *res = SGX_ERROR_UNEXPECTED;
               throw std::runtime_error(""); 
            }

            ret = mbedtls_x509_crt_parse_der(&srvcert, &temp_buff[der_key_len] , der_crt_len); 

            if (ret != SGX_SUCCESS) { //could not write to secured file 
               mbedtls_printf("ERROR cert load failed\n");
	       *res = SGX_ERROR_UNEXPECTED;
               throw std::runtime_error("");
            }

            mbedtls_printf("\npriv key loaded from secured file : Successful\n"); 

   	} else { //KMS key file does not exist. attempt to read from KMS Server

	    mbedtls_printf("WARNING: priv key and cert load failed. Key file is likely corrupt or missing\n");
            mbedtls_printf("Generating priv key and cert\n");

            create_key_and_x509(&pkey, &srvcert, &temp_buff[der_key_len], &der_crt_len, temp_buff, &der_key_len);

            ret = seal_to_file(temp_buff, size , KEY_CERT_FILE);

            if (ret != SGX_SUCCESS) { //could not write to secured file 
               mbedtls_printf("ERROR key/cert file open for write failed\n");
	       *res = SGX_ERROR_UNEXPECTED;
               throw std::runtime_error("");
            } else {
               mbedtls_printf("\nkey/cert write to protected file : Successful\n"); 
            }

        }
        if (temp_buff)
           free(temp_buff); 

	mbedtls_ssl_config_init(&conf);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	/*
	 * We use only a single entropy source that is used in all the threads.
	 */

	/*
	 * 1. Load the certificates and private RSA key
	 */
	//mbedtls_printf("\n  . Loading the server cert. and key...");
	/*
	 * This demonstration program uses embedded test certificates.
	 * Instead, you may want to use mbedtls_x509_crt_parse_file() to read the
	 * server and CA certificates, as well as mbedtls_pk_parse_keyfile().
	 ret = mbedtls_x509_crt_parse(&srvcert, (const unsigned char *) mbedtls_test_srv_crt,
	 mbedtls_test_srv_crt_len);
	 if (ret != 0) {
	 mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
	 throw std::runtime_error("");
	 }

	 ret = mbedtls_x509_crt_parse(&cachain, (const unsigned char *) mbedtls_test_cas_pem,
	 mbedtls_test_cas_pem_len);
	 if (ret != 0) {
	 mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
	 throw std::runtime_error("");
	 }

	 mbedtls_pk_init(&pkey);
	 ret = mbedtls_pk_parse_key(&pkey, (const unsigned char *) mbedtls_test_srv_key,
	 mbedtls_test_srv_key_len, NULL, 0);
	 if (ret != 0) {
	 mbedtls_printf(" failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret);
	 throw std::runtime_error("");
	 }

	 */

	// load CA chain
	// compute buffer length along with NULL terminating character; mbedtls expects length including it.
	size_t ca_chain_length = strlen(mozilla_ca_bundle) + 1;
	ret = mbedtls_x509_crt_parse(&cachain,
			(const unsigned char*) mozilla_ca_bundle, ca_chain_length);
	if (ret != 0) {
		mbedtls_printf(
				" failed to load CA chain\n  !  mbedtls_x509_crt_parse returned %d\n\n",
				ret);
	        *res = SGX_ERROR_UNEXPECTED;
		throw std::runtime_error("");

	}
	// set verification to optional.
	// DP/CTF will have CA signed certificates but key manager will have self-signed certificate
	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
	mbedtls_ssl_conf_ca_chain(&conf, &cachain, NULL);
	//mbedtls_printf(" ok\n");

	/*
	 * 1b. Seed the random number generator
	 */
	//mbedtls_printf("  . Seeding the random number generator...");
	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
			(const unsigned char *) pers.c_str(), pers.length())) != 0) {
		mbedtls_printf(" failed: mbedtls_ctr_drbg_seed returned -0x%04x\n",
				-ret);
	        *res = SGX_ERROR_UNEXPECTED;
		throw std::runtime_error("");
	}
	// mbedtls_printf(" ok\n");

	/*
	 * 1c. Prepare SSL configuration
	 */
	//mbedtls_printf("  . Setting up the SSL data....");
	if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER,
			MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
		mbedtls_printf(
				" failed: mbedtls_ssl_config_defaults returned -0x%04x\n",
				-ret);
	        *res = SGX_ERROR_UNEXPECTED;
		throw std::runtime_error("");
	}

	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

	/*
	 * setup debug
	 */
	mbedtls_ssl_conf_dbg(&conf, mydebug, NULL);
	// if debug_level is not set (could be set via other constructors), set it to 0
	if (debug_level < 0) {
		debug_level = 0;
	}
	mbedtls_debug_set_threshold(debug_level);

	/* mbedtls_ssl_cache_get() and mbedtls_ssl_cache_set() are thread-safe if
	 * MBEDTLS_THREADING_C is set.
	 */
#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_conf_session_cache(&conf, &cache, mbedtls_ssl_cache_get,
			mbedtls_ssl_cache_set);
#endif

	//mbedtls_ssl_conf_ca_chain(&conf, &cachain, NULL);
	if ((ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey)) != 0) {
		mbedtls_printf(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n",
				ret);
	        *res = SGX_ERROR_UNEXPECTED;
		throw std::runtime_error("");
	}

	dealer_run_mode = 0;

	// request key from KMS
	//mbedtls_printf("\n Enclave Params: %s %s \n\n", params->kms_server, params->key_namespace);
	temp_buff = (uint8_t *) malloc(KEY_SIZE+(SGX_HASH_SIZE * 2));
	memset(temp_buff, 0, KEY_SIZE+(SGX_HASH_SIZE * 2));
	size = KEY_SIZE+(SGX_HASH_SIZE * 2);;
	key_from_kms = (char *)malloc(KEY_SIZE); 
	memset(key_from_kms, 0, KEY_SIZE);


	// Attempt to read kms key from protected key file
   // If key is found in file then use it 
   ret  = unseal_from_file(temp_buff, (uint32_t *)&size, KMS_KEY_FILE); // attempt to read key from KMS file

   if ((ret == SGX_SUCCESS) && (size == KEY_SIZE+(SGX_HASH_SIZE * 2))) { 
	memcpy(key_from_kms,temp_buff,KEY_SIZE);
	memcpy(kms_mrenclave, &temp_buff[KEY_SIZE], (SGX_HASH_SIZE * 2));
	mbedtls_printf("\nKMS key loaded from secured file : Successful\n"); 
   } else { //KMS key file does not exist. attempt to read from KMS Server
		      
	mbedtls_printf("WARNING: KMS key load failed. Key file is likely corrupt or missing\n");
	mbedtls_printf("Attempting key read from KMS\n"); 

	if (get_key_from_kms(key_from_kms) != 0) { 
		mbedtls_printf("ERROR: Failed to get key from KMS\n");
	        *res = SGX_ERROR_UNEXPECTED;
		throw std::runtime_error("");
	 } else {
		char *null_key_check = (char *)malloc(KEY_SIZE); 
		memset(null_key_check, 0, KEY_SIZE);
		if(memcmp(null_key_check, key_from_kms, KEY_SIZE) == 0) {
		      mbedtls_printf("ERROR: No key received from KMS\n");
	              *res = SGX_ERROR_UNEXPECTED;
		      throw std::runtime_error("");
		}
		if (null_key_check)
		     free(null_key_check);
         // Got Key from KMS. Now store into secure keyfile
         
	    	memcpy(temp_buff,key_from_kms,KEY_SIZE);
           	memcpy(&temp_buff[KEY_SIZE], kms_mrenclave,(SGX_HASH_SIZE * 2));
            	ret  = seal_to_file(temp_buff, KEY_SIZE + (SGX_HASH_SIZE * 2), KMS_KEY_FILE);
            	if (ret != SGX_SUCCESS) { //could not write to secured file 
		        mbedtls_printf("ERROR: KMS key file open for write failed\n");
	                *res = SGX_ERROR_UNEXPECTED;
              		throw std::runtime_error("");
            	} else {
              		mbedtls_printf("\nKMS key write to protected file : Successful\n"); 
            	}
         } 
   }  
   if (temp_buff)
     free(temp_buff); 

   *res = SGX_SUCCESS;
         
}

/**
 * @Name : ~TLSConnectionHandler
 * @return : Returns none
 * @Description : Function to free SSL config and Cerificate
 */
TLSConnectionHandler::~TLSConnectionHandler() {
	mbedtls_x509_crt_free(&srvcert);
	mbedtls_x509_crt_free(peercert);
	mbedtls_pk_free(&pkey);
#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_cache_free (&cache);
#endif
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	mbedtls_ssl_config_free(&conf);

	sgx_thread_mutex_destroy(&mutex);

	free(key_from_kms);

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
	mbedtls_memory_buffer_alloc_free();
#endif

#if defined(_WIN32)
	mbedtls_printf( "  Press Enter to exit this program.\n" );
	fflush( stdout ); getchar();
#endif
}

/**
 * @Name : get_key_from_kms
 * @arguments : [In] identifier
 * @arguments : [Out] key
 * @return : Returns 0 on success, on failure returns error code
 * @Description : Function to get key from KMS
 */
int TLSConnectionHandler::get_key_from_kms(char *key) {
	client_opt_t opt;
	unsigned char buf[1024];
	client_opt_init(&opt);
	opt.debug_level = 1;
	opt.server_name = kmsserver.c_str();
	opt.server_port = kmsport.c_str();
	memcpy(opt.key_namespace, keynamespace.c_str(), KEY_NAMESPACE_LEN);
	// make sure string is NULL terminated
	opt.key_namespace[KEY_NAMESPACE_LEN - 1] = 0;
	opt.auth_mode = MBEDTLS_SSL_VERIFY_OPTIONAL;

	int r = kms_client(opt, NULL, 0, buf, sizeof buf, &pkey, &srvcert,
			&cachain);
	if (r == 0) {
		memcpy(key, buf, KEY_SIZE);

		//mbedtls_printf("\nKey retrieved from KMS: ");
		//for(int i=0; i<KEY_SIZE; i++)
		//	mbedtls_printf("%02x ", key[i]);
		//mbedtls_printf("\n");

		return 0;
	}
	return r;
}

/**
 * @Name : initialize_dealer_mode
 * @arguments : [In] run_mode
 *		[In] thread_info
 * @return : Returns none
 * @Description : Function to initialize Dealer mode
 */
void TLSConnectionHandler::initialize_dealer_mode(int run_mode) {
	dealer_run_mode = run_mode;
}


/**
 * @Name : handle
 * @arguments : [In] thread_id
 *		[In] thread_info
 * @return : Returns none
 * @Description : Function to handle Dealer-In and Dealer-Out
 */
void TLSConnectionHandler::handle(long int thread_id,
		thread_info_t *thread_info) {
	int ret, len;
	mbedtls_net_context *client_fd = &thread_info->client_fd;
	unsigned char buf[1024];
	mbedtls_ssl_context ssl;

	// thread local data
	mbedtls_ssl_config _conf;
	memcpy(&_conf, &this->conf, sizeof(mbedtls_ssl_config));
	thread_info->config = &_conf;
	thread_info->thread_complete = 0;

	/* Make sure memory references are valid */
	mbedtls_ssl_init(&ssl);

	//mbedtls_printf("  [ #%ld ]  Setting up SSL/TLS data\n", thread_id);


	/*
	 * 4. Get the SSL context ready
	 */
	if ((ret = mbedtls_ssl_setup(&ssl, thread_info->config)) != 0) {
		mbedtls_printf(
				"  [ #%ld ]  failed: mbedtls_ssl_setup returned -0x%04x\n",
				thread_id, -ret);
		goto thread_exit;
	}

	if ((ret = mbedtls_ssl_set_client_transport_id(&ssl, thread_info->client_ip,
			thread_info->ip_len)) != 0) {
		mbedtls_printf(
				"mbedtls_ssl_set_client_transport_id() returned -0x%x\n\n",
				-ret);
		goto thread_exit;
	}

	//mbedtls_printf("client_fd is %d\n", client_fd->fd);
	mbedtls_ssl_set_bio(&ssl, client_fd, mbedtls_net_send_ocall,
			mbedtls_net_recv_ocall, NULL);

	/*
	 * 5. Handshake
	 */
	//mbedtls_printf("  [ #%ld ]  Performing the SSL/TLS handshake\n", thread_id);
	while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ
				&& ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			mbedtls_printf(
					"  [ #%ld ]  failed: mbedtls_ssl_handshake returned -0x%04x\n",
					thread_id, -ret);
			goto thread_exit;
		}
	}

	//mbedtls_printf("  [ #%ld ]  ok\n", thread_id);

	// verify client certificate before actual read/write happens
	if (!VerifyCertificate(&ssl)) {
		mbedtls_printf("ERROR: Client Certificate verification failed...exiting thread\n");
		goto thread_exit;
	}
	/*
	 * 6. Read the HTTP Request
	 */
	//mbedtls_printf("  [ #%ld ]  < Read from client\n", thread_id);
	//mbedtls_printf("  %d  < Read from client\n", dealer_run_mode);
	if (dealer_run_mode == IN) {

#ifndef SGX_FTPS
	   const char *close_msg = "close";
	   zmq_handle *handle = NULL;
	   zmq_context *context = NULL;
	   uint8_t *enc_str = NULL;
      size_t lenOut;
      unsigned char message[1024];
		// Generate client IP string
		memset(buf, 0, sizeof(buf));

		/*
		 snprintf(buf, TLSConnectionHandler::ip_str_len, "%d.%d.%d.%d",
		 ssl.cli_id[0], ssl.cli_id[1],
		 ssl.cli_id[2], ssl.cli_id[3]);
		 len = strlen((char *) buf);
		 */

		// read identity from DP
		ret = mbedtls_ssl_read(&ssl, buf, 1024);
		len = strlen((char*) buf);
		switch (ret) {
		case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
			break;
		case 0:
		case MBEDTLS_ERR_NET_CONN_RESET:
			break;
		}
		mbedtls_printf("INFO: identity read from DP: %s\n", buf);

		// set crypto parameters
		AESGCM.set_params_aesgcm((uint8_t *)key_from_kms, buf, len);

		// Prepend message type : 0
		memset(message, 0, sizeof(message));
		message[0] = MSG_FILENAME + '0';
		memcpy(message + 1, buf, len);
		//memcpy(message, buf, len);
		if ((handle = conn_to_in_router(thread_info->cdr_router_host,
				thread_info->cdr_router_port, (char *) message)) == NULL) {
			goto thread_exit;
		}

		if (send_msg_to_in_router(handle, message, strlen((char *) message))
				== -1) {
			goto thread_exit;
		}

		while (1) {
			len = sizeof(buf) - 1;
			memset(buf, 0, sizeof(buf));
			while ((ret = mbedtls_ssl_read(&ssl, buf, len)) <= 0) {

				if (ret == MBEDTLS_ERR_SSL_WANT_READ
						|| ret == MBEDTLS_ERR_SSL_WANT_WRITE)
					continue;

				switch (ret) {
				case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
					mbedtls_printf(
							"  [ #%ld ]  Connection was closed gracefully\n",
							thread_id);
					goto thread_exit;

				case 0:
				case MBEDTLS_ERR_NET_CONN_RESET:
					mbedtls_printf("  [ #%ld ]  Connection was reset by peer\n",
							thread_id);
					memset(message, 0, sizeof(message));
					message[0] = MSG_CLOSE_PROTECTED_FILE + '0';
					memcpy(message + 1, close_msg, strlen(close_msg)); // +1 for msg type
					send_msg_to_in_router(handle, message,
							strlen((char *) message));
					close_router_conn(handle,context);
					goto thread_exit;

				default:
					mbedtls_printf(
							"  [ #%ld ]  mbedtls_ssl_read returned -0x%04x\n",
							thread_id, -ret);
					goto thread_exit;
				}
			} // while

			len = ret;
			//mbedtls_printf("Read data : %s\n=====\n", (char *) buf);
			enc_str = (uint8_t *) malloc(TLSConnectionHandler::enc_str_size);

			if (enc_str == NULL) {
				mbedtls_printf("Memory allocation failed for encryption buffer\n");
				continue;
			}

			memset(enc_str, 0, TLSConnectionHandler::enc_str_size);

			// Prepend msg type - 1 for DATA
			// mbedtls_printf("DEBUG : sending data %s to in-router", buf);
			memset(message, 0, 1024);
			message[0] = MSG_DATA + '0';
			memcpy(message + 1, buf, len);
			enc_str[0] = message[0];
			AESGCM.encrypt((char *) message+1, len, (char *)
					enc_str+1, &lenOut);
			send_msg_to_in_router(handle, enc_str, lenOut + 1);// +1 for msg type
			free(enc_str);
		}	 //WHILE 1
#else // FTPS build
      SGX_FILE *protected_fp;
      string cdrPath = string(m_cdrPath);
      string cdrArchPath = string(m_cdrArchPath);
      std::map<std::string, int>::iterator it;
      char filename[128] = {0,};
      char date_time[16] = {0,};
      int seq_num = 0;
      char seq[10] = {0,};
      char node_id[32] = {0,};
      size_t writelen = 0;
      size_t total_cdr_bytes = 0;

      ret = mbedtls_ssl_read(&ssl, (unsigned char *)filename, 128); //read 128 bytes for filename
      switch (ret) {
      case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
			goto thread_exit;
         break;
      case 0:
      case MBEDTLS_ERR_NET_CONN_RESET:
			goto thread_exit;
         break;

      }
      if (strlen(filename) >= 32) {
         mbedtls_printf("NodeID (>32 bytes) not supported \n");
			goto thread_exit;
      }

      mbedtls_printf("INFO: NodeID read from DP: %s\n", filename);

      memcpy(node_id, filename, strlen(filename));

      strtok(filename, "\n"); //Remove any trailing "\n" character

      strncat(filename,"_",1);
      ocall_date_time(date_time);
      strncat(filename, date_time, 14); //Fixed YYYYMMDDHHMMSS 14 byte format
      strncat(filename,".cdr",4);

      if (cdrPath.at(cdrPath.size() - 1) != '/')
               cdrPath.append("/");

      cdrPath.append(filename);

      string::size_type pos = 0; 

      // Append MRENCLAVE of KMS before ".extn"
      pos = cdrPath.find_last_of(".");
      if (pos == string::npos)
         pos = cdrPath.size();

      cdrPath.insert(pos, "_");
      cdrPath.insert(pos + 1, kms_mrenclave);

      // Append Seq Num before ".extn"
      it = seqmap.find(node_id);
      if (it != seqmap.end()) {
          it->second += 1;
          seq_num = it->second;
      } else {
          seqmap.insert(std::make_pair(node_id, 1));
          seq_num = 1;
      }

      snprintf(seq, 10, "%d", seq_num);
      pos = cdrPath.find_last_of(".");
      if (pos == string::npos)
         pos = cdrPath.size();

      cdrPath.insert(pos, "_");
      cdrPath.insert(pos + 1, seq);


      if (cdrArchPath.at(cdrArchPath.size() - 1) != '/')
               cdrArchPath.append("/");

      cdrArchPath.append(filename);

      // Append MRENCLAVE of KMS before ".extn"
      pos = cdrArchPath.find_last_of(".");
      if (pos == string::npos)
         pos = cdrArchPath.size();

      cdrArchPath.insert(pos, "_");
      cdrArchPath.insert(pos + 1, kms_mrenclave);

      // Append Seq Num before ".extn"
      pos = cdrArchPath.find_last_of(".");
      if (pos == string::npos)
         pos = cdrArchPath.size();

      cdrArchPath.insert(pos, "_");
      cdrArchPath.insert(pos + 1, seq);

      mbedtls_printf("INFO: Protected CDR filename len : %d : %s\n", strlen(cdrPath.c_str()),cdrPath.c_str());
      if ((protected_fp = open_secure_file(cdrPath.c_str(), "a+",  key_from_kms)) == NULL) {
         mbedtls_printf("Unable to open protected CDR file for %s\n", cdrPath.c_str());
			goto thread_exit;
      }

      while (1) {
         memset(buf, 0, sizeof(buf));
         while ((ret = mbedtls_ssl_read(&ssl, buf, sizeof(buf))) <= 0) {

            if (ret == MBEDTLS_ERR_SSL_WANT_READ
                  || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
               continue;

            switch (ret) {
            case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
               mbedtls_printf(
                     "  [ #%ld ]  Connection was closed gracefully\n",
                     thread_id);
               close_protected_fs(protected_fp);
               ocall_rename_file(cdrPath.c_str(), cdrArchPath.c_str());
               goto thread_exit;
            
            case 0:
            case MBEDTLS_ERR_NET_CONN_RESET:
               mbedtls_printf("  [ #%ld ]  Connection was reset by peer\n",
                     thread_id);
               close_protected_fs(protected_fp);
               ocall_rename_file(cdrPath.c_str(), cdrArchPath.c_str());
               goto thread_exit;
            
            default:
               mbedtls_printf(
                     "  [ #%ld ]  mbedtls_ssl_read returned -0x%04x\n",
                     thread_id, -ret);
               close_protected_fs(protected_fp);
               goto thread_exit;
            }
         } // while

         writelen = ret; 

         if (sgx_fwrite(buf, 1, writelen, protected_fp) != writelen) {
            mbedtls_printf("Unable to write protected CDR file for %s\n", cdrPath.c_str());
            close_protected_fs(protected_fp);
			   goto thread_exit;
         }

         total_cdr_bytes += writelen;
         if (total_cdr_bytes >= cdrfilesize) {
               mbedtls_printf("CDR file size exceeded, writing CDR to new file\n");
               int prev_len = strlen(seq);
               close_protected_fs(protected_fp);
               ocall_rename_file(cdrPath.c_str(), cdrArchPath.c_str());
               total_cdr_bytes = 0;
               ocall_date_time(date_time);
               // (84 + prev_len) chars from the end is where datetime stamp starts
               cdrPath.replace(cdrPath.length()-(84 + prev_len), 14, date_time);
               // (84 + prev_len) chars from the end is where datetime stamp starts
               cdrArchPath.replace(cdrArchPath.length()-(84 + prev_len), 14, date_time);

               it = seqmap.find(node_id);
               if (it != seqmap.end()) {
                  it->second += 1;
               }
               snprintf(seq, 10, "%d", it->second);

               pos = cdrPath.find_last_of("_");
               if (pos == string::npos)
                   pos = cdrPath.size();

               cdrPath.erase(pos + 1, prev_len);
               cdrPath.insert(pos + 1, seq);

               pos = cdrArchPath.find_last_of("_");
               if (pos == string::npos)
                   pos = cdrArchPath.size();

               cdrArchPath.erase(pos + 1, prev_len);
               cdrArchPath.insert(pos + 1, seq);

               if ((protected_fp = open_secure_file(cdrPath.c_str(), "a+",  key_from_kms)) == NULL) {
                  mbedtls_printf("Unable to open protected CDR file for %s\n", cdrPath.c_str());
			         goto thread_exit;
               }
         }
      }
#endif
	} else if (dealer_run_mode == OUT) {
#ifndef SGX_FTPS
		int offline = 0;
		if (get_msg_out_router_send_to_ctf(thread_id, &ssl,
				thread_info->cdr_router_host, thread_info->cdr_router_port,
				key_from_kms, offline, m_cdrPath, m_cdrArchPath)
				== MBEDTLS_ERR_NET_CONN_RESET) {
			goto thread_exit;
		}
#else
	   mbedtls_printf("  [ #%ld ]  in FTP mode %d\n", thread_id,thread_info->ftp_params.request);
      if (thread_info->ftp_params.request == 5)  { // FTP File Listing Flow 
		int buf_len = strlen((const char *)thread_info->ftp_params.output_buffer);
		unsigned int buf_idx = 0;
		while ((ret = mbedtls_ssl_write(&ssl, (const unsigned char *)thread_info->ftp_params.output_buffer + buf_idx,
				buf_len))) {

			if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
				continue;

			if( ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY )
				break;

			if (ret != buf_len) {
				buf_idx += ret;
				buf_len -= ret;
				continue;
			}
			break;
		}
      } else if (thread_info->ftp_params.request == 6) { // FTP File transfer Flow
         SGX_FILE *handle = NULL;
         unsigned char *read_buff = (unsigned char *)malloc(1024);

         if (read_buff == NULL) {
            mbedtls_printf("Cannot allocate memory\n");
			   goto thread_exit;
         }

         // Check if filename contains MRENCLAVE value after "_" and before "extn"
         string cdrPath(thread_info->ftp_params.cdr_file_path);
         size_t pos = cdrPath.find_last_of("_");
         if (pos == string::npos) {
             mbedtls_printf("file name not valid.\n");
             free(read_buff);
			    goto thread_exit;
         }

         if (cdrPath.compare((pos - (SGX_HASH_SIZE * 2)), SGX_HASH_SIZE * 2, kms_mrenclave) != 0) {
            mbedtls_printf("filename doesn't contain valid MRENCLAVE value.\n");
            free(read_buff);
			   goto thread_exit;
         }

         handle = open_secure_file(thread_info->ftp_params.cdr_file_path, "r", key_from_kms);
         if (handle == NULL) {
            mbedtls_printf("Error opening secure file. File is corrupt or tampered\n");
            free(read_buff);
			   goto thread_exit;
         }

         while (!sgx_feof(handle)) {
            len = sgx_fread(read_buff, 1, 1024, handle);
            if (sgx_ferror(handle) != 0) {
               mbedtls_printf("Failed to read data from protected file \n");
               free(read_buff);
			      goto thread_exit;
            }
            if (mbedtls_ssl_write(&ssl, read_buff, len) <= 0) {
               mbedtls_printf("  [ #%ld ]  failed: peer closed the connection or connection error\n", thread_id);
               free(read_buff);
			      goto thread_exit;
            }
         }
         free(read_buff);
      } else { // FTP Control Flow 
         handle_ftp_control(&ssl, thread_info->ftp_params.ftp_pasv_port, thread_info->ftp_params.ftp_server_ip);
	      mbedtls_printf("  [ #%ld ]  Finished FTP control mode handling \n", thread_id);
      }
#endif
   }
         
      
	mbedtls_printf("  [ #%ld ]  . Closing the connection...", thread_id);

	while ((ret = mbedtls_ssl_close_notify(&ssl)) < 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ
				&& ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			mbedtls_printf(
					"  [ #%ld ]  failed: mbedtls_ssl_close_notify returned -0x%04x\n",
					thread_id, ret);
			goto thread_exit;
		}
	}

	//mbedtls_printf(" ok\n");

	ret = 0;

	thread_exit:

#ifdef MBEDTLS_ERROR_C
	if (ret != 0) {
		char error_buf[100];
		mbedtls_strerror(ret, error_buf, 100);
		mbedtls_printf("  [ #%ld ]  Last error was: -0x%04x - %s\n\n",
				thread_id, -ret, error_buf);
	}
#endif

	//mbedtls_printf(" yo cleanup\n");

	mbedtls_ssl_free(&ssl);

	thread_info->config = NULL;
	thread_info->thread_complete = 1;
}

const string TLSConnectionHandler::pers = "ssl_pthread_server";
sgx_thread_mutex_t TLSConnectionHandler::mutex = SGX_THREAD_MUTEX_INITIALIZER;

void TLSConnectionHandler::mydebug(void *ctx, int level, const char *file,
		int line, const char *str) {
	(void) ctx;
	(void) level;
	long int thread_id = 0;
	sgx_thread_mutex_lock(&mutex);

	mbedtls_printf("%s:%04d: [ #%ld ] %s", file, line, thread_id, str);

	sgx_thread_mutex_unlock(&mutex);
}

bool TLSConnectionHandler::VerifyCertificate(mbedtls_ssl_context *ssl) {
	uint32_t flags;
	int ret;

	//mbedtls_printf("VerifyCertificate(): verifying certificate ...");
	mbedtls_x509_crt * peercert;
	//mbedtls_x509_crt *peercert=new mbedtls_x509_crt;
	//mbedtls_x509_crt_init(peercert);
	peercert = (mbedtls_x509_crt *) mbedtls_ssl_get_peer_cert(ssl);
	if (peercert != NULL) {
		ret = mbedtls_x509_crt_verify(peercert, &cachain, NULL, NULL, &flags,
		NULL, NULL);
		if (ret == 0) {
			//DP or CTF on the other side
			//mbedtls_printf("VerifyCertificate(): certificate verified successfully\n\n");
			if (dealer_run_mode == IN)
				mbedtls_printf("Connection from trusted DP\n\n");
			else if (dealer_run_mode == OUT)
				mbedtls_printf("Connection from trusted CTF\n\n");
			return true;
		} else {

			// ###################### <TODO>: check with Somnath ###############
			// This section was verifying the self-signed certificate from KMS.
			// We have that verification code with KMS client. Here we will verify
			// only DP/CTF CA signed certificates.
			// Removing SGX quote verification code from Dealer's server side verification
			// #################################################################
			mbedtls_printf("VerifyCertificate(): return code: %X \n\n", ret);
			return false;
		}
	} else // no peer certificate
	{
		mbedtls_printf(
				"VerifyCertificate(): failed to get peer certificate \n\n");
		return false;
	}
}
