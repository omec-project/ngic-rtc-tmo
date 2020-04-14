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

#ifndef CRYPTO_H
#define CRYPTO_H

#include "sgx_trts.h"
#include "sgx_tcrypto.h"

#define BUFLEN 2048
#define CRYPTO_TYPE_AES_GCM 1
#define CRYPTO_TYPE_AES_CTR 2
#define CRYPTO_TYPE_UNKNOWN -500

class Crypto {
public:
	Crypto(int t);
	~Crypto();

	// APIs
	int encrypt(char *, size_t, char *, size_t *);
	int decrypt(char *, size_t, char *, size_t *);
	int set_params_aesgcm(sgx_aes_gcm_128bit_key_t, uint8_t*, size_t);
	int set_params_aesctr(sgx_aes_ctr_128bit_key_t, uint8_t*);

private:
	// encryption type
	int type;

	// internal APIs for AES-GCM
	int encrypt_aesgcm(char*, size_t, char*, size_t *);
	int decrypt_aesgcm(char*, size_t, char*, size_t *);
	sgx_aes_gcm_128bit_key_t aesgcm_key;
	uint8_t *aad;
	size_t aad_size;

	// internal APIs for AES-CTR
	int encrypt_aesctr(char*, size_t, char*);
	int decrypt_aesctr(char*, size_t, char*);
	sgx_aes_ctr_128bit_key_t aesctr_key;
	uint32_t ctr_num_bit_size;
	uint8_t ctr[16];

};

// other testing related fuctions
void test_crypto(int);

#endif
