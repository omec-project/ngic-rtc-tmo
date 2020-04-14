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

#include <rte_debug.h>

#include "gtpv2c_messages.h"
#include "../cp_dp_api/cp_dp_api.h"
#include "gtpv2c_set_ie.h"

#define RTE_LOGTYPE_CP RTE_LOGTYPE_USER4

extern struct response_info resp_t;

/**
 * Handles the removal of data structures internal to the control plane
 * as well as notifying the data plane of such changes.
 * @param ds_req
 *   structure containing create delete session request
 * @param _context
 *   ue_context to be removed/refreshed to remaining active sessions
 * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *   specified cause error value
 *   \- < 0 for all other errors
 */
int
delete_dp_context(delete_session_request_t *ds_req,
			ue_context **_context)
{
	int ret;
	int i, j;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	eps_bearer *bearer = NULL;

	ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
	    (const void *) &ds_req->header.teid.has_teid.teid,
	    (void **) &context);

	if (ret < 0 || !context)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

	uint8_t ebi_index = 0;
	if (ds_req->linked_ebi.header.len) {
		ebi_index = ds_req->linked_ebi.eps_bearer_id - 5;
	}

	/* SM- TMOPL VCCCCB-35
	 * Send Delete session response based on SI
	 */
	if (ds_req->indication_flags.header.len) {
		context->indication_value.si = ds_req->indication_flags.indication_value.si;
	}

	/* ASR- TMOPL VCCCCB-25:
	 * Charging integration on CP + Secure CDR transfer interface
	 * delete sessions @dp
	 */
	for (i = 0; i < context->num_pdns; i++) {
		pdn = context->pdns[i];
		for (j = 0; j < pdn->num_bearers; ++j) {
			if (context->eps_bearers[j] == pdn->eps_bearers[j]) {
				bearer = context->eps_bearers[j];

				/* Set the delete session response */
				 /* TODO: Revisit: Handle type received from message
				  * resp_t.msg_type = ds_req->header.gtpc.type; */
				resp_t.msg_type = GTP_DELETE_SESSION_REQ;
				resp_t.context_t = *context;
				/* Preserve ue_context hash reference */
				resp_t.cp_context_hash = *_context;
				resp_t.cp_context_ref = context;
				resp_t.cp_pdn_ref = pdn;
				resp_t.ebi = ebi_index;

				struct session_info si;
				memset(&si, 0, sizeof(si));

				/**
				 * ebi and s1u_sgw_teid is set here for zmq/sdn
				 */
				if (ds_req->linked_ebi.header.len) {
					si.bearer_id = ds_req->linked_ebi.eps_bearer_id;
				} else {
					si.bearer_id = bearer->eps_bearer_id;
				}
				si.ue_addr.u.ipv4_addr =
					htonl(pdn->ipv4.s_addr);
				si.ul_s1_info.sgw_teid =
					htonl(bearer->s1u_sgw_gtpu_teid);
				si.sess_id = SESS_ID(
						context->s11_sgw_gtpc_teid,
						si.bearer_id);
				struct dp_id dp_id = { .id = DPN_ID };

				session_delete(dp_id, &si);

				/* SM- IMSI/FTEID Hash table in-consistency issue:
				 * Remove entry from imsi/fteid hash without relying on
				 * Delete Session response from DP. In this way, even if
				 * DP not responding for the Delete Session Request, CP HASH
				 * table will be cleaned and consistency maintained
				 */

				rte_hash_del_key(ue_context_by_imsi_hash,
						(const void *) &context->imsi);
				rte_hash_del_key(ue_context_by_fteid_hash,
						(const void *) &context->s11_sgw_gtpc_teid);
			} else {
				rte_panic("@%s::Bearers incorrectly provisioned!!!\n",
						__func__);
			}
		}
	}
	return 0;
}

/**
 * Handles the removal of data structures internal to the control plane
 * as well as notifying the data plane of such changes.
 * @param _context
 *   ue_context to be removed/refreshed to remaining active sessions
 * @param context
 *   ue_context pertaining to the session to be deleted
 * @param pdn
 *   pdn_connection pertaining to the session to be removed
 * @param ebi
 *   EPS bearer index pertaining to pdn of session to be deleted
 * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *   specified cause error value
 *   \- < 0 for all other errors
 */
int
delete_cp_context(ue_context **_context, ue_context *context,
			pdn_connection *pdn, uint8_t ebi)
{
	int i;

	for (i = 0; i < pdn->num_bearers; i++) {
		release_ip(pdn->apn_in_use, &pdn->ipv4);
		rte_free(pdn->eps_bearers[i]);
		pdn->eps_bearers[i] = NULL;
		context->eps_bearers[i] = NULL;
		context->bearer_bitmap &= ~(1 << i);
	}
	--context->num_pdns;
	rte_free(pdn);
	context->pdns[ebi] = NULL;
	context->teid_bitmap = 0;
	if (context->dp_session)
		rte_free(context->dp_session);

	/* Update ue_context hash reference @remaining context */
	/* ASR- TODO: Check:: ue_context hash will always have residue
	 * ue_context hash will never be empty, even after all sessions deleted
	 * */
	if(context->num_pdns == 0) {
		rte_free(context);
		context = NULL;
	}
	*_context = context;
	return 0;
}

/**
 * Handles the processing of delete session request messages received by the
 * control plane.
 *
 * @param gtpv2c_rx
 *   gtpv2c message buffer containing delete session request message
 * @param gtpv2c_s11_tx
 *   gtpc2c message transmission buffer to contain s11 response message
 * @param gtpv2c_s5s8_tx
 *   gtpc2c message transmission buffer to contain s5s8 response message
 * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *   specified cause error value
 *   \- < 0 for all other errors
 */
int
process_delete_session_request(gtpv2c_header *gtpv2c_rx,
		gtpv2c_header *gtpv2c_s11_tx, gtpv2c_header *gtpv2c_s5s8_tx)
{
	gtpv2c_header_t header = { 0 };
	ue_context *context = NULL;
	int ret = 0;
	uint8_t cause_val = 0;
	delete_session_request_t *ds_req = NULL;
	uint16_t msg_len;

	decode_gtpv2c_header_t((uint8_t *) gtpv2c_rx, &header);
	msg_len = header.gtpc.message_len;
	if (msg_len > MAX_GTPV2C_LENGTH)
		return -EPERM;

	ds_req = rte_zmalloc_socket(NULL, MAX_GTPV2C_LENGTH,
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (!ds_req)
		return -EPERM;

	decode_delete_session_request_t((uint8_t *) gtpv2c_rx, ds_req);

	if (spgw_cfg == SGWC) {
		pdn_connection *pdn = NULL;
		uint32_t s5s8_pgw_gtpc_del_teid;
		static uint32_t process_sgwc_s5s8_ds_req_cnt;

		/* s11_sgw_gtpc_teid= key->ue_context_by_fteid_hash */
		ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
			(const void *) &ds_req->header.teid.has_teid.teid,
			(void **) &context);

		if (ret < 0 || !context) {
			/* VCCCCB-50: GTPV2C_CAUSE_CONTEXT_NOT_FOUND not send after CP restart */
			set_gtpv2c_teid_header(gtpv2c_s11_tx, GTP_DELETE_SESSION_RSP,
			    0, gtpv2c_rx->teid_u.has_teid.seq);
			set_cause_ie(gtpv2c_s11_tx, GTPV2C_CAUSE_CONTEXT_NOT_FOUND, IE_INSTANCE_ZERO);
			rte_free(ds_req);
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}

		if (ds_req->indication_flags.indication_value.si) {
			rte_free(ds_req);
			return ret;
		}

		uint8_t del_ebi_index = ds_req->linked_ebi.eps_bearer_id - 5;
		pdn = context->pdns[del_ebi_index];
		/* s11_sgw_gtpc_teid = s5s8_pgw_gtpc_base_teid =
		 * key->ue_context_by_fteid_hash */
		s5s8_pgw_gtpc_del_teid = pdn->s5s8_pgw_gtpc_teid;
		ret =
			gen_sgwc_s5s8_delete_session_request(gtpv2c_rx,
				gtpv2c_s5s8_tx, s5s8_pgw_gtpc_del_teid,
				gtpv2c_rx->teid_u.has_teid.seq, ds_req->linked_ebi.eps_bearer_id);
		RTE_LOG(DEBUG, CP, "NGIC- delete_session.c::"
				"\n\tprocess_delete_session_request::case= %d;"
				"\n\tprocess_sgwc_s5s8_ds_req_cnt= %u;"
				"\n\tue_ip= pdn->ipv4= %s;"
				"\n\tpdn->s5s8_sgw_gtpc_ipv4= %s;"
				"\n\tpdn->s5s8_sgw_gtpc_teid= %X;"
				"\n\tpdn->s5s8_pgw_gtpc_ipv4= %s;"
				"\n\tpdn->s5s8_pgw_gtpc_teid= %X;"
				"\n\tgen_delete_s5s8_session_request= %d\n",
				spgw_cfg, process_sgwc_s5s8_ds_req_cnt++,
				inet_ntoa(pdn->ipv4),
				inet_ntoa(pdn->s5s8_sgw_gtpc_ipv4),
				pdn->s5s8_sgw_gtpc_teid,
				inet_ntoa(pdn->s5s8_pgw_gtpc_ipv4),
				pdn->s5s8_pgw_gtpc_teid,
				ret);
		rte_free(ds_req);
		return ret;
	}

	gtpv2c_s11_tx->teid_u.has_teid.seq = gtpv2c_rx->teid_u.has_teid.seq;
	cause_val = GTPV2C_CAUSE_REQUEST_ACCEPTED;

	resp_t.cause_val = cause_val;
	resp_t.gtpv2c_tx_t = *gtpv2c_s11_tx;

	ret = delete_dp_context(ds_req, &context);
	if (ret) {
		/* VCCCCB-50: GTPV2C_CAUSE_CONTEXT_NOT_FOUND not send after CP restart */
		set_gtpv2c_teid_header(gtpv2c_s11_tx, GTP_DELETE_SESSION_RSP,
		    0, gtpv2c_rx->teid_u.has_teid.seq);
		set_cause_ie(gtpv2c_s11_tx, ret, IE_INSTANCE_ZERO);
		rte_free(ds_req);
		return ret;
	}

	rte_free(ds_req);
	return 0;
}
