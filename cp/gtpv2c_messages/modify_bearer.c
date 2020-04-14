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

#include "ue.h"
#include "gtpv2c_messages.h"
#include "gtpv2c_set_ie.h"
#include "../cp_dp_api/cp_dp_api.h"

struct parse_modify_bearer_request_t {
	ue_context *context;
	pdn_connection *pdn;
	eps_bearer *bearer;

	gtpv2c_ie *bearer_context_to_be_created_ebi;
	gtpv2c_ie *s1u_enb_fteid;
	uint8_t *delay;
	uint32_t *s11_mme_gtpc_fteid;
};
extern uint32_t num_adc_rules;
extern uint32_t adc_rule_id[];
extern struct response_info resp_t;

/**
 * from parameters, populates gtpv2c message 'modify bearer response' and
 * populates required information elements as defined by
 * clause 7.2.8 3gpp 29.274
 * @param gtpv2c_tx
 *   transmission buffer to contain 'modify bearer request' message
 * @param sequence
 *   sequence number as described by clause 7.6 3gpp 29.274
 * @param context
 *   UE Context data structure pertaining to the bearer to be modified
 * @param bearer
 *   bearer data structure to be modified
 */
void
//set_modify_bearer_response(gtpv2c_header *gtpv2c_tx,
//		uint32_t sequence, ue_context *context, eps_bearer *bearer)
set_modify_bearer_response(gtpv2c_header *gtpv2c_tx,
		uint32_t sequence, ue_context *context,
		eps_bearer *bearer, uint8_t cause_val)
{
	modify_bearer_response_t mb_resp = {0};

	set_gtpv2c_teid_header((gtpv2c_header *) &mb_resp, GTP_MODIFY_BEARER_RSP,
	    context->s11_mme_gtpc_teid, sequence);

	/* TMOPL VCCCCB-19: cause argument for s11 response */
	set_cause_response(&mb_resp.cause, IE_INSTANCE_ZERO, cause_val);

	set_ie_header(&mb_resp.bearer_context.header, IE_BEARER_CONTEXT,
			IE_INSTANCE_ZERO, 0);

	/* TMOPL VCCCCB-19: cause argument for s11 response */
	set_cause_response(&mb_resp.bearer_context.cause, IE_INSTANCE_ZERO,
					GTPV2C_CAUSE_REQUEST_ACCEPTED);

	mb_resp.bearer_context.header.len +=
		sizeof(struct cause_ie_hdr_t) + IE_HEADER_SIZE;

	set_ebi(&mb_resp.bearer_context.ebi, IE_INSTANCE_ZERO,
			bearer->eps_bearer_id);
	mb_resp.bearer_context.header.len += sizeof(uint8_t) + IE_HEADER_SIZE;

	struct in_addr ip;
	ip.s_addr = htonl(s1u_sgw_ip.s_addr);
	set_ipv4_fteid(&mb_resp.bearer_context.s1u_sgw_ftied,
			GTPV2C_IFTYPE_S1U_SGW_GTPU, IE_INSTANCE_ZERO, ip,
			htonl(bearer->s1u_sgw_gtpu_teid));
	mb_resp.bearer_context.header.len += sizeof(struct fteid_ie_hdr_t) +
		sizeof(struct in_addr) + IE_HEADER_SIZE;

	uint16_t msg_len = 0;
	encode_modify_bearer_response_t(&mb_resp, (uint8_t *)gtpv2c_tx,
			&msg_len);
	gtpv2c_tx->gtpc.length = htons(msg_len - 4);
}

/**
 * Handles the processing of modify bearer request messages received by the
 * control plane.
 *
 * @param gtpv2c_rx
 *   gtpv2c message buffer containing the modify bearer request message
 * @param gtpv2c_tx
 *   gtpv2c message transmission buffer to response message
 * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *   specified cause error value
 *   \- < 0 for all other errors
 */
int
process_modify_bearer_request(gtpv2c_header *gtpv2c_rx,
		gtpv2c_header *gtpv2c_tx)
{
	gtpv2c_header_t header = { 0 };
	struct dp_id dp_id = { .id = DPN_ID };
	modify_bearer_request_t *mb_req = NULL;
	uint32_t i;
	ue_context *context = NULL;
	eps_bearer *bearer = NULL;
	pdn_connection *pdn = NULL;
	uint8_t cause_val = 0;
	uint16_t msg_len;

	decode_gtpv2c_header_t((uint8_t *) gtpv2c_rx, &header);
	msg_len = header.gtpc.message_len;
	if (msg_len > MAX_GTPV2C_LENGTH)
		return -EPERM;

	mb_req = rte_zmalloc_socket(NULL, MAX_GTPV2C_LENGTH,
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (!mb_req)
		return -EPERM;

	decode_modify_bearer_request_t((uint8_t *) gtpv2c_rx, mb_req);

	int ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
	    (const void *) &mb_req->header.teid.has_teid.teid,
	    (void **) &context);

	if (ret < 0 || !context) {
		/* VCCCCB-50: GTPV2C_CAUSE_CONTEXT_NOT_FOUND not send after CP restart */
		set_gtpv2c_teid_header(gtpv2c_tx, GTP_MODIFY_BEARER_RSP,
		    0, gtpv2c_rx->teid_u.has_teid.seq);
		set_cause_ie(gtpv2c_tx, GTPV2C_CAUSE_CONTEXT_NOT_FOUND, IE_INSTANCE_ZERO);
		rte_free(mb_req);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	if (!mb_req->bearer_context.ebi.header.len
			|| !mb_req->bearer_context.s1u_enodeb_ftied.header.len) {
			fprintf(stderr, "Dropping packet\n");
			rte_free(mb_req);
			return -EPERM;
	}

	uint8_t ebi_index = mb_req->bearer_context.ebi.eps_bearer_id - 5;
	if (!(context->bearer_bitmap & (1 << ebi_index))) {
		fprintf(stderr,
			"Received modify bearer on non-existent EBI - "
			"Dropping packet\n");
		rte_free(mb_req);
		return -EPERM;
	}

	/* ASR- TMOPL VCCCCB-25
	 * Charging integration on CP + Secure CDR transfer interface
	 */
	if (mb_req->uli.header.len) {
		memcpy(&context->tai, &mb_req->uli.tai, sizeof(struct tai_t));
		memcpy(&context->ecgi, &mb_req->uli.ecgi, sizeof(struct ecgi_t));
	}

	bearer = context->eps_bearers[ebi_index];
	if (!bearer) {
		fprintf(stderr,
			"Received modify bearer on non-existent EBI - "
			"Bitmap Inconsistency - Dropping packet\n");
		rte_free(mb_req);
		return -EPERM;
	}

	pdn = bearer->pdn;

	/* TODO something with modify_bearer_request.delay if set */

	if (mb_req->s11_mme_fteid.header.len &&
			(context->s11_mme_gtpc_teid != mb_req->s11_mme_fteid.teid_gre))
		context->s11_mme_gtpc_teid = mb_req->s11_mme_fteid.teid_gre;

	bearer->s1u_enb_gtpu_ipv4 =
			mb_req->bearer_context.s1u_enodeb_ftied.ip.ipv4;

	bearer->s1u_enb_gtpu_teid =
			mb_req->bearer_context.s1u_enodeb_ftied.teid_gre;

	bearer->eps_bearer_id = mb_req->bearer_context.ebi.eps_bearer_id;

	cause_val = GTPV2C_CAUSE_REQUEST_ACCEPTED;;
	/*Set modify bearer response*/
	resp_t.cause_val = cause_val;
	resp_t.gtpv2c_tx_t = *gtpv2c_tx;
	resp_t.context_t = *context;
	resp_t.cp_context_ref = context;
	resp_t.bearer_t = *bearer;
	resp_t.gtpv2c_tx_t.teid_u.has_teid.seq = mb_req->header.teid.has_teid.seq;
	resp_t.msg_type = GTP_MODIFY_BEARER_REQ;
	 /* TODO: Revisit: Handle type received from message
	  * resp_t.msg_type = mb_req->header.gtpc.type; */

	/* using the s1u_sgw_gtpu_teid as unique identifier to the session */
	/* ASR- TMOPL VCCCCB-25:
	 * Charging integration on CP + Secure CDR transfer interface
	 * Retrive session_info on CP heap from ue_context
	 */
	struct session_info *session;
	session = context->dp_session;

	session->ue_addr.iptype = IPTYPE_IPV4;
	 session->ue_addr.u.ipv4_addr =
		 pdn->ipv4.s_addr;
	 session->ul_s1_info.sgw_teid =
		htonl(bearer->s1u_sgw_gtpu_teid);
	 session->ul_s1_info.sgw_addr.iptype = IPTYPE_IPV4;
	 session->ul_s1_info.sgw_addr.u.ipv4_addr =
		 htonl(bearer->s1u_sgw_gtpu_ipv4.s_addr);
	 session->ul_s1_info.enb_addr.iptype = IPTYPE_IPV4;
	 session->ul_s1_info.enb_addr.u.ipv4_addr =
		 bearer->s1u_enb_gtpu_ipv4.s_addr;
	 session->dl_s1_info.enb_teid =
		 bearer->s1u_enb_gtpu_teid;
	 session->dl_s1_info.enb_addr.iptype = IPTYPE_IPV4;
	 session->dl_s1_info.enb_addr.u.ipv4_addr =
		 bearer->s1u_enb_gtpu_ipv4.s_addr;
	 session->dl_s1_info.sgw_addr.iptype = IPTYPE_IPV4;
	 session->dl_s1_info.sgw_addr.u.ipv4_addr =
		 htonl(bearer->s1u_sgw_gtpu_ipv4.s_addr);
	 session->ul_apn_mtr_idx = 0;
	 session->dl_apn_mtr_idx = 0;
	 session->num_ul_pcc_rules = 1;
	 session->ul_pcc_rule_id[0] = FIRST_FILTER_ID;
	 session->num_dl_pcc_rules = 1;
	 session->dl_pcc_rule_id[0] = FIRST_FILTER_ID;

	 session->num_adc_rules = num_adc_rules;
	 for (i = 0; i < num_adc_rules; ++i)
			 session->adc_rule_id[i] = adc_rule_id[i];

	 session->sess_id = SESS_ID(
			context->s11_sgw_gtpc_teid,
			bearer->eps_bearer_id);

	if (session_modify(dp_id, session) < 0)
		rte_exit(EXIT_FAILURE, "Bearer Session modify fail !!!");
	rte_free(mb_req);
	return 0;
}
