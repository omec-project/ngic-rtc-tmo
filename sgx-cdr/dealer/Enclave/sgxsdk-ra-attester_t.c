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

#include <assert.h>

#include <sgx_uae_service.h>

#include "Enclave_t.h" // OCALLs

/* Trusted portion (called from within the enclave) to do remote
   attestation with the SGX SDK.  */

void do_remote_attestation(sgx_report_data_t* report_data,
                           attestation_verification_report_t* r);

void do_remote_attestation
(
    sgx_report_data_t* report_data,
    attestation_verification_report_t* attn_report
)
{
    sgx_target_info_t target_info = {0, };
    ocall_sgx_init_quote(&target_info);

    sgx_report_t report = {0, };
    sgx_status_t status = sgx_create_report(&target_info, report_data, &report);
    assert(status == SGX_SUCCESS);

    ocall_remote_attestation(&report, attn_report);
}
