
/*
 * Copyright (c) 2020 Intel Corporation
 *
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



#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>

#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_common.h>
#include <rte_acl.h>

#include "interface.h"
#include "cp.h"
#include "gtpv2c_set_ie.h"
#include "gtpv2c.h"
#include "sctf.h"
#include "cp_stats.h"

#define RTE_LOGTYPE_CP RTE_LOGTYPE_USER4

extern struct response_info resp_t;
extern socklen_t s11_mme_sockaddr_len;
extern socklen_t s5s8_pgwc_sockaddr_len;
extern sctf_msg_t *sctf_msg;
extern uint8_t send_cdr;
uint16_t op_id = 0;

/**
 * @brief Adds the current op_id to the hash table used to account for NB
 * Messages
 */
void
add_resp_op_id_hash(void)
{
	int ret;

	switch (resp_t.msg_type) {
		case GTP_CREATE_SESSION_REQ:
		case GTP_MODIFY_BEARER_REQ:
		case GTP_RELEASE_ACCESS_BEARERS_REQ:
		case GTP_DELETE_SESSION_REQ: {
			struct response_info *tmp = rte_zmalloc("test",
					sizeof(struct response_info),
					RTE_CACHE_LINE_SIZE);
			struct response_info *tmp_resp = NULL;

			if (NULL == tmp)
				rte_panic("%s: Failure to allocate create session buffer: "
						"%s (%s:%d)\n", __func__, rte_strerror(rte_errno),
						__FILE__,
						__LINE__);

			memcpy(tmp, &resp_t, sizeof(struct response_info));

			/* SM- IMSI/FTEID Hash table in-consistency issue:
			 * Check if any existing entries available in resp_op_id_hash
			 * (stale entries) and remove the entry if it exists and clear
			 * the resources.
			 */
			ret = rte_hash_lookup_data(resp_op_id_hash, (void *)&op_id,
					(void **)&tmp_resp);

			if (tmp_resp != NULL) {
				if ((tmp_resp->msg_type == GTP_MODIFY_BEARER_REQ) ||
						(tmp_resp->msg_type == GTP_DELETE_SESSION_REQ)) {
					/* SM- CDR Record generation for resp_op_id_hash stale
					 * entry case: Generate CDR Record, encode in ASN format
					 * and send the record */
					uint8_t der[DER_LEN];
					uint16_t der_length = 0;
					struct resp_msgbuf rbuf;
					memset(&rbuf, 0, sizeof(struct resp_msgbuf));

					rbuf.cdr_msg.ue_context = tmp_resp->cp_context_ref;
					rbuf.cdr_msg.session_info =
						tmp_resp->cp_context_ref->dp_session;
					rbuf.op_id = op_id;
					rbuf.cdr_msg.record_closure_cause = CDR_REC_ABNORMAL_REL;
					time((time_t *)&rbuf.cdr_msg.timeOfReport);

					sctf_msg_assemble(&rbuf);
					der_length = sctf_to_asn1_encode(sctf_msg, der);

					if((der_length != 0) && send_cdr)
						write_sctf(der, der_length);
				}

				/* Remove the entry from resp_op_id_hash before inserting the
				 * new entry */
				ret = rte_hash_del_key(resp_op_id_hash, (void *)&op_id);

				/* Clear the context reference */
				delete_cp_context(&(tmp_resp->cp_context_hash),
					tmp_resp->cp_context_ref, tmp_resp->cp_pdn_ref,
					tmp_resp->ebi);
			}

			ret = rte_hash_add_key_data(resp_op_id_hash, (void *)&op_id,
					(void *)tmp);
			if (ret) {
				fprintf(stderr, "%s: rte_hash_add_key_data failed for "
						" op_id %u: %s (%u)\n", __func__,
						op_id, rte_strerror(abs(ret)), ret);
			}
			break;
		} /* Req handling case */

		default:
			/*Adding entry for received entry for unknown request for now.
			 * For future reference*/
			ret = rte_hash_add_key_data(resp_op_id_hash, (void *)&op_id, NULL);
			if (ret) {
				fprintf(stderr, "%s: rte_hash_add_key_data failed for "
						" op_id %u: %s (%u)\n", __func__,
						op_id, rte_strerror(abs(ret)), ret);
			}
			break;
	} /* switch case */

	RTE_LOG_DP(DEBUG, CP, "Added op_id; %u\n", op_id);

	++op_id;
}

/**
 * @brief Deletes the op_id from the hash table used to account for NB
 * Messages
 * @param resp_op_id
 * op_id received in process_dp_resp message to indicate message
 * was received and processed by the DPN
 */
void
del_resp_op_id(uint16_t resp_op_id)
{
	int ret = 0;
	struct response_info *tmp = NULL;

	RTE_LOG_DP(DEBUG, CP, "Deleting op_id; %u\n", resp_op_id);

	ret = rte_hash_lookup_data(resp_op_id_hash, (void *)&resp_op_id,
			(void **)&tmp);
	if (ret < 0) {
		RTE_LOG_DP(DEBUG, CP, "%s::rte_hash_lookup_data failed!!!"
				"\n\top_id= %u\n", __func__, resp_op_id);
		return;
	} else {
		/* SM: In the following scenario OP_ID stats shows wrong count
		 *  1: cp starts:: sends CSR, MBR requests to DP > stops;
		 *  2. dp starts:: processes msgs from zmq broker > stops
		 *  3: cp starts:: but now processes resp msgs from dp per
		 *     #1:: cp_stats OPID goes negative
		 *
		 * This issue is solved by incrementing cups_opid_rsp count only
		 * if the resonse message belongs to the CP
		 * NOTE: op_id should be unique across multilple CP instances >> TBD
		 */
		cups_opid_rsp++;
	}

#ifndef SIMU_CP
	uint16_t payload_length;

	switch (tmp->msg_type) {
		case GTP_CREATE_SESSION_REQ: {
			switch(spgw_cfg){
				case SGWC:
				case SPGWC: {
					/* TMOPL VCCCCB-19: cause argument for s11 response */
					set_create_session_response(&(tmp->gtpv2c_tx_t),
							tmp->gtpv2c_tx_t.teid_u.has_teid.seq,
							&(tmp->context_t), &(tmp->pdn_t),
							&(tmp->bearer_t), tmp->cause_val);

					payload_length = ntohs(tmp->gtpv2c_tx_t.gtpc.length)
						+ sizeof(tmp->gtpv2c_tx_t.gtpc);

					gtpv2c_send(s11_fd, (uint8_t*)&(tmp->gtpv2c_tx_t),
							payload_length,
							(struct sockaddr *) &s11_mme_sockaddr,
							s11_mme_sockaddr_len);
					break;
					}

				case PGWC: {
					set_pgwc_s5s8_create_session_response(&(tmp->gtpv2c_tx_t),
							tmp->gtpv2c_tx_t.teid_u.has_teid.seq, &(tmp->pdn_t),
							&(tmp->bearer_t));

					payload_length = ntohs(tmp->gtpv2c_tx_t.gtpc.length)
						+ sizeof(tmp->gtpv2c_tx_t.gtpc);

					gtpv2c_send(s5s8_pgwc_fd, (uint8_t*)&(tmp->gtpv2c_tx_t),
							payload_length,
							(struct sockaddr *) &s5s8_sgwc_sockaddr,
							s5s8_pgwc_sockaddr_len);
					break;
					}
				default:
					break;
			}/* Case cp type*/

			break;
		}/* Case Create session req*/

		case GTP_MODIFY_BEARER_REQ:
		case GTP_RELEASE_ACCESS_BEARERS_REQ: {
			/* VCCCCB-47 ModifyBearerResponse sent during ReleaseAccessBearers Procedure
			 * Send ReleaseAccessBearers response
			 */
			if (tmp->msg_type == GTP_MODIFY_BEARER_REQ) {
				set_modify_bearer_response(&(tmp->gtpv2c_tx_t),
						tmp->gtpv2c_tx_t.teid_u.has_teid.seq,
						&(tmp->context_t), &(tmp->bearer_t), tmp->cause_val);
			} else {
				set_release_access_bearer_response(&(tmp->gtpv2c_tx_t),
						tmp->gtpv2c_tx_t.teid_u.has_teid.seq,
						&(tmp->context_t));
			}

			payload_length = ntohs(tmp->gtpv2c_tx_t.gtpc.length)
				+ sizeof(tmp->gtpv2c_tx_t.gtpc);

			gtpv2c_send(s11_fd, (uint8_t*)&(tmp->gtpv2c_tx_t),
					payload_length,
					(struct sockaddr *) &s11_mme_sockaddr,
					s11_mme_sockaddr_len);
			break;
		} /* Case modify session req or release access bearer req */

		case GTP_DELETE_SESSION_REQ: {
			switch(spgw_cfg){
				case SGWC:
				case SPGWC:
					/* SM- IMSI/FTEID Hash table in-consistency issue:
					 * After receiving the Delete Session Response from DP,
					 * free the context resources. Please note that the entries
					 * from IMSI/FTEID hash already removed before sending
					 * Request to DP. So we only need to clear the context
					 * which is stored to use for CDR processing.
					 */
					delete_cp_context(&(tmp->cp_context_hash), tmp->cp_context_ref,
								tmp->cp_pdn_ref, tmp->ebi);

					/* ASR- VCCCCB-28 Delete session delete_session_resp proactively
					 * sent by process_create_session_request(...) on
					 * implicit session delete (i.e without Delete Session
					 * Request from MME)
					 */
					if (tmp->cause_val ==
							GTPV2C_CAUSE_MULTIPLE_CONNECTIONS_ON_APN_NOT_ALLOWED)
						break;
					set_gtpv2c_teid_header(&(tmp->gtpv2c_tx_t),
							GTP_DELETE_SESSION_RSP,
							htonl(tmp->context_t.s11_mme_gtpc_teid),
							tmp->gtpv2c_tx_t.teid_u.has_teid.seq);

					set_cause_ie(&(tmp->gtpv2c_tx_t), tmp->cause_val,
							IE_INSTANCE_ZERO);

					payload_length = ntohs(tmp->gtpv2c_tx_t.gtpc.length)
						+ sizeof(tmp->gtpv2c_tx_t.gtpc);

					gtpv2c_send(s11_fd, (uint8_t*)&(tmp->gtpv2c_tx_t),
							payload_length,
							(struct sockaddr *) &s11_mme_sockaddr,
							s11_mme_sockaddr_len);
					break;

				case PGWC:
					set_gtpv2c_teid_header(&(tmp->gtpv2c_tx_t),
							GTP_DELETE_SESSION_RSP,
							tmp->s5s8_sgw_gtpc_del_teid_ptr,
							tmp->gtpv2c_tx_t.teid_u.has_teid.seq);

					set_cause_ie(&(tmp->gtpv2c_tx_t), tmp->cause_val,
							IE_INSTANCE_ZERO);

					payload_length = ntohs(tmp->gtpv2c_tx_t.gtpc.length)
						+ sizeof(tmp->gtpv2c_tx_t.gtpc);

					gtpv2c_send(s5s8_pgwc_fd, (uint8_t*)&(tmp->gtpv2c_tx_t),
							payload_length,
							(struct sockaddr *) &s5s8_sgwc_sockaddr,
							s5s8_pgwc_sockaddr_len);
					break;

				default:
					break;
			}/* case cp type*/
			break;

		}/*case delete session req */

		default:
			break;
	}/* case msg_type */
#endif /* !SIMU_CP */

	ret = rte_hash_del_key(resp_op_id_hash, (void *)&resp_op_id);

	if (ret < 0) {
		fprintf(stderr, "%s:rte_hash_del_key failed for op_id %u"
				": %s (%u)\n", __func__,
				resp_op_id,
				rte_strerror(abs(ret)), ret);
	}

	if (NULL != tmp) {
		/* free the memory */
		rte_free(tmp);
	}
}


