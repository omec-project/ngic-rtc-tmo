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

#include <errno.h>

#include <rte_debug.h>

#include "packet_filters.h"
#include "gtpv2c_messages.h"
#include "gtpv2c_set_ie.h"
#include "../cp_dp_api/cp_dp_api.h"

#define RTE_LOGTYPE_CP RTE_LOGTYPE_USER4


extern uint32_t num_adc_rules;
extern uint32_t adc_rule_id[];
extern socklen_t s11_mme_sockaddr_len;
struct response_info resp_t;

/* The global PCO structure variable */
pco_ie_t cs_req_pco;

/**
 * from parameters, populates gtpv2c message 'create session response' and
 * populates required information elements as defined by
 * clause 7.2.2 3gpp 29.274
 * @param gtpv2c_tx
 *   transmission buffer to contain 'create session response' message
 * @param sequence
 *   sequence number as described by clause 7.6 3gpp 29.274
 * @param context
 *   UE Context data structure pertaining to the session to be created
 * @param pdn
 *   PDN Connection data structure pertaining to the session to be created
 * @param bearer
 *   Default EPS Bearer corresponding to the PDN Connection to be created
 * @param cause value
 *   Cause values per 3GPP TS 29.274, Table 8.4-1
 * @return
 *   void
 */
/* TMOPL VCCCCB-19: cause argument for s11 response */
void
set_create_session_response(gtpv2c_header *gtpv2c_tx,
		uint32_t sequence, ue_context *context, pdn_connection *pdn,
		eps_bearer *bearer, uint8_t cause_val)
{
	struct in_addr s5s8pgwuip;
	struct in_addr ip;
	uint32_t ulambr = 0, dlambr = 0;
	create_session_response_t cs_resp = {0};

	if (cause_val == GTPV2C_CAUSE_REQUEST_ACCEPTED) {
		set_gtpv2c_teid_header((gtpv2c_header *)&cs_resp.header,
				GTP_CREATE_SESSION_RSP, context->s11_mme_gtpc_teid,
				sequence);
		set_cause_response(&cs_resp.cause, IE_INSTANCE_ZERO, cause_val);

		ip.s_addr = ntohl(s11_sgw_ip.s_addr);
		set_ipv4_fteid(&cs_resp.s11_ftied, GTPV2C_IFTYPE_S11S4_SGW_GTPC,
				IE_INSTANCE_ZERO, ip, context->s11_sgw_gtpc_teid);
		set_ipv4_fteid(&cs_resp.pgws5s8_pmip, GTPV2C_IFTYPE_S5S8_PGW_GTPC,
				IE_INSTANCE_ONE,
				pdn->s5s8_pgw_gtpc_ipv4, pdn->s5s8_pgw_gtpc_teid);

		set_ipv4_paa(&cs_resp.paa, IE_INSTANCE_ZERO, pdn->ipv4);

		set_apn_restriction(&cs_resp.apn_restriction, IE_INSTANCE_ZERO,
				pdn->apn_restriction);

		/* Set AMBR in CS Response */
		if (pdn->apn_ambr.ambr_uplink <= pdn->apn_in_use->apn_ambr.ambr_uplink)
			ulambr = pdn->apn_ambr.ambr_uplink;
		else
			ulambr = pdn->apn_in_use->apn_ambr.ambr_uplink;

		if (pdn->apn_ambr.ambr_downlink <= pdn->apn_in_use->apn_ambr.ambr_downlink)
			dlambr = pdn->apn_ambr.ambr_downlink;
		else
			dlambr = pdn->apn_in_use->apn_ambr.ambr_downlink;

		set_ambr(&cs_resp.ambr, IE_INSTANCE_ZERO, ulambr, dlambr);

		/* Set the PCO variables in CS response */
		set_pco(&cs_resp.pco, IE_INSTANCE_ZERO,
				primary_dns_ip, secondary_dns_ip);
	} else {
		set_gtpv2c_teid_header((gtpv2c_header *)&cs_resp.header,
				GTP_CREATE_SESSION_RSP, context->s11_mme_gtpc_teid,
				sequence);
		set_cause_response(&cs_resp.cause, IE_INSTANCE_ZERO, cause_val);
	}

	/* Set Bearer Context Grouped IE */
	set_ie_header(&cs_resp.bearer_context.header, IE_BEARER_CONTEXT,
			IE_INSTANCE_ZERO, 0);

	set_cause_response(&cs_resp.bearer_context.cause,
			IE_INSTANCE_ZERO, cause_val);

	set_ebi(&cs_resp.bearer_context.ebi, IE_INSTANCE_ZERO,
			bearer->eps_bearer_id);

	/* Adjust bearer_context.header.len::
	 * sizeof(struct cause_ie)=6; sizeof(struct fteid_ie_hdr_t)=5 */
	cs_resp.bearer_context.header.len += sizeof(struct cause_ie) +
										sizeof(struct fteid_ie_hdr_t);

	if (cause_val == GTPV2C_CAUSE_REQUEST_ACCEPTED) {
		if (bearer->s11u_mme_gtpu_teid) {
			printf("S11U Detect- set_create_session_response-"
					"\n\tbearer->s11u_mme_gtpu_teid= %X;"
					"\n\tGTPV2C_IFTYPE_S11U_MME_GTPU= %X\n",
					htonl(bearer->s11u_mme_gtpu_teid),
					GTPV2C_IFTYPE_S11U_SGW_GTPU);

			/* TODO: set fteid values to create session response member */
			/*
			printf("S11U Detect- set_create_session_response-"
					"\n\tbearer->s11u_mme_gtpu_teid= %X;"
					"\n\tGTPV2C_IFTYPE_S11U_MME_GTPU= %X\n",
					bearer->s11u_mme_gtpu_teid,
					GTPV2C_IFTYPE_S11U_SGW_GTPU);
			add_grouped_ie_length(bearer_context_group,
		    set_ipv4_fteid_ie(gtpv2c_tx, GTPV2C_IFTYPE_S11U_SGW_GTPU,
				    IE_INSTANCE_SIX, s1u_sgw_ip,
				    bearer->s1u_sgw_gtpu_teid));
			*/

		} else {
			ip.s_addr = htonl(s1u_sgw_ip.s_addr);
		    set_ipv4_fteid(&cs_resp.bearer_context.s1u_sgw_ftied,
			GTPV2C_IFTYPE_S1U_SGW_GTPU,
				IE_INSTANCE_ZERO, ip,
				htonl(bearer->s1u_sgw_gtpu_teid));
			cs_resp.bearer_context.header.len += sizeof(struct fteid_ie_hdr_t) +
				sizeof(struct in_addr) + IE_HEADER_SIZE;
		}

		/* Convert the s5s8 pgwu ip to host byte order */
		s5s8pgwuip.s_addr = ntohl(s5s8_pgwu_ip.s_addr);

		set_ipv4_fteid(&cs_resp.bearer_context.s5s8_pgw,
				GTPV2C_IFTYPE_S5S8_PGW_GTPU,
				IE_INSTANCE_TWO, s5s8pgwuip,
				htonl(bearer->s1u_sgw_gtpu_teid));
		cs_resp.bearer_context.header.len += sizeof(struct fteid_ie_hdr_t) +
				sizeof(struct in_addr) + IE_HEADER_SIZE;
	}

	uint16_t msg_len = 0;
	encode_create_session_response_t(&cs_resp, (uint8_t *)gtpv2c_tx,
			&msg_len);
	if (cause_val == GTPV2C_CAUSE_REQUEST_ACCEPTED) {
		/* Adjust gtpc.length::sizeof(gtpv2c_ie)=4 */
		gtpv2c_tx->gtpc.length = htons(msg_len - sizeof(gtpv2c_ie));
	} else {
		/* Adjust gtpc.length::sizeof(gtpv2c_ie)=4; IE_HEADER_SIZE=4 */
		gtpv2c_tx->gtpc.length = htons(msg_len - sizeof(gtpv2c_ie)
										- 2*IE_HEADER_SIZE);
	}
}

/**
 * Handles the processing of create session request messages received by the
 * control plane
 *
 * @param gtpv2c_rx
 *   gtpv2c message buffer containing the create session request message
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
process_create_session_request(gtpv2c_header *gtpv2c_rx,
		gtpv2c_header *gtpv2c_s11_tx, gtpv2c_header *gtpv2c_s5s8_tx)
{
	gtpv2c_header_t header = { 0 };
	create_session_request_t *csr = NULL;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	eps_bearer *bearer = NULL;
	apn *apn_req = NULL;
	struct in_addr ue_ip;
	int apn_indx = 0;
	int ret;
	uint8_t cause_res = 0;
	uint8_t cause_val = 0;
	uint64_t imsi = UINT64_MAX;
	static uint32_t process_sgwc_s5s8_cs_req_cnt;
	static uint32_t process_spgwc_s11_cs_res_cnt;

	uint16_t msg_len;

	decode_gtpv2c_header_t((uint8_t *) gtpv2c_rx, &header);
	msg_len = header.gtpc.message_len;
	if (msg_len > MAX_GTPV2C_LENGTH)
		return -EPERM;

	csr = rte_zmalloc_socket(NULL, MAX_GTPV2C_LENGTH,
	    RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (!csr)
		return -EPERM;

	ret = decode_create_session_request_t((uint8_t *) gtpv2c_rx,
			csr);
	if (!ret) {
		rte_free(csr);
		return -EPERM;
	}

	if (csr->indication.header.len &&
			csr->indication.indication_value.uimsi) {
		fprintf(stderr, "Unauthenticated IMSI Not Yet Implemented - "
				"Dropping packet\n");
		rte_free(csr);
		return -EPERM;
	}

	if (!csr->indication.header.len
			|| !csr->apn_restriction.header.len
			|| !csr->bearer_context.header.len
			|| !csr->sender_ftied.header.len /* S11 FTEID */
			|| !csr->s5s8pgw_pmip.header.len /* S5S8 PGW FTEID */
			|| !csr->imsi.header.len
			|| !csr->ambr.header.len
			|| !csr->pdn_type.header.len
			|| !csr->bearer_context.bearer_qos.header.len
			|| !csr->msisdn.header.len
			|| !(csr->pdn_type.pdn_type == PDN_IP_TYPE_IPV4) ) {
		fprintf(stderr, "Mandatory IE missing. Dropping packet\n");
		cause_res = GTPV2C_CAUSE_MANDATORY_IE_MISSING;
	}

	if (csr->pdn_type.pdn_type == PDN_IP_TYPE_IPV6 ||
			csr->pdn_type.pdn_type == PDN_IP_TYPE_IPV4V6) {
			fprintf(stderr, "IPv6 Not Yet Implemented\n");
			cause_res = GTPV2C_CAUSE_PREFERRED_PDN_TYPE_UNSUPPORTED;
	}

	/* ASR- TMOPL VCCCCB-29: No PGW s5/s8 FTEID ip validation */
	if (spgw_cfg == SPGWC) {
		if ((csr->s5s8pgw_pmip.teid_gre != 0) ||
		(csr->s5s8pgw_pmip.ip.ipv4.s_addr !=
		 htonl(s5s8_pgwc_ip.s_addr)))
			cause_res = GTPV2C_CAUSE_MANDATORY_IE_INCORRECT;
	}
	if (spgw_cfg == SGWC) {
		if ((csr->s5s8pgw_pmip.teid_gre != 0) ||
		(csr->s5s8pgw_pmip.ip.ipv4.s_addr != 0))
			cause_res = GTPV2C_CAUSE_MANDATORY_IE_INCORRECT;
	}

	apn_indx = get_apn_idx((char *)csr->apn.apn, csr->apn.header.len);
	if (apn_indx < 0)
			cause_res = GTPV2C_CAUSE_MISSING_UNKNOWN_APN;

	/* ASR- TMOPL VCCCCB-28
	 * Many PDN connections for the same IMSI on a given APN not allowed
	 * REQD: Many PDN connections same IMSI different APN
	 * ue_context_by_imsi_hash::Key= fn(IMSI, apn)
	 * Insert 4 bits apn_indx @byte7 of imsi; MAX_NB_APN: MAX VAL= 15
	 */
	memcpy(&imsi, csr->imsi.imsi, csr->imsi.header.len);
	*((uint8_t *)(&imsi) + APN_IMSI_KEY_POSTN) =
		*((uint8_t *)(&imsi) + APN_IMSI_KEY_POSTN) << APN_IMSI_KEY_LEN | apn_indx;

	/* ASR- TMOPL VCCCCB-28
	 * Many PDN connections for the same IMSI on a given APN not allowed
	 */
	ret = rte_hash_lookup_data(ue_context_by_imsi_hash, &imsi,
			(void **) &(context));
	if (ret != -ENOENT) {
		int retry = 0;
		/* ASR- ue_context exits. Perform implicit delete:
		 * delete_dp_context(...), session_delete(...), send delete_session_resp */
		delete_session_request_t ds_req = {0};
		ds_req.linked_ebi = csr->bearer_context.ebi;
		ds_req.header.teid.has_teid.teid = context->s11_sgw_gtpc_teid;

		gtpv2c_s11_tx->teid_u.has_teid.seq = gtpv2c_rx->teid_u.has_teid.seq;
		cause_val = GTPV2C_CAUSE_MULTIPLE_CONNECTIONS_ON_APN_NOT_ALLOWED;

		resp_t.cause_val = cause_val;
		resp_t.gtpv2c_tx_t = *gtpv2c_s11_tx;

		ret = delete_dp_context(&ds_req, &context);
		if (ret) {
			rte_free(csr);
			return ret;
		}
		/* SM- VCCCCB-28 Many PDN connections for same IMSI
		 * Wait for the existing resources to be cleaned up (after DP sends
		 * response). Otherwise exit after five retries.
		 */
		do {
			usleep(1000);
			retry++;
			/* This operation is multi-thread safe with regards to other lookup threads */
			ret = rte_hash_lookup(ue_context_by_imsi_hash, &imsi);
			if((ret == -ENOENT) || retry >= 5) {
				if (retry >= 5)
					cause_res = GTPV2C_CAUSE_SYSTEM_FAILURE;
				break;
			}
		} while(1);

		/* ASR- VCCCCB-28 Proactively send delete_session_resp on
		 * implicit session delete (i.e without Delete Session
		 * Request from MME)
		 */
		set_gtpv2c_teid_header(gtpv2c_s11_tx, GTP_DELETE_SESSION_RSP,
		    htonl(context->s11_mme_gtpc_teid), gtpv2c_rx->teid_u.has_teid.seq);

		set_cause_ie(gtpv2c_s11_tx, cause_val, IE_INSTANCE_ZERO);

		uint16_t payload_length = ntohs(gtpv2c_s11_tx->gtpc.length)
			+ sizeof(gtpv2c_s11_tx->gtpc);

		gtpv2c_send(s11_fd, (uint8_t*)gtpv2c_s11_tx,
				payload_length,
				(struct sockaddr *) &s11_mme_sockaddr,
				sizeof(s11_mme_sockaddr));
	}

	if (cause_res == 0) {
		apn_req = &apn_list[apn_indx];
		ret = acquire_ip(apn_req, &ue_ip);
		if (ret) {
			cause_res = GTPV2C_CAUSE_ALL_DYNAMIC_ADDRESSES_OCCUPIED;
		} else {
			primary_dns_ip = *apn_req->pdns;
			secondary_dns_ip = *apn_req->sdns;
		}
	}

	/*Copy the PCO variables to global PCO variable */
	memcpy(&cs_req_pco, &csr->pco, sizeof(pco_ie_t));
	uint8_t ebi_index = csr->bearer_context.ebi.eps_bearer_id - 5;

	/* TMOPL VCCCCB-19: cause argument for s11 response */
	if (cause_res == 0) {
		cause_res = GTPV2C_CAUSE_REQUEST_ACCEPTED;
		/* set s11_sgw_gtpc_teid= key->ue_context_by_fteid_hash */
		/* ASR- TMOPL VCCCCB-28
		 * Many PDN connections for the same IMSI on a given APN not allowed
		 * REQD: Many PDN connections same IMSI different APN
		 * ue_context_by_imsi_hash::Key= fn(IMSI, apn).
		 */
		ret = create_ue_context(csr->imsi.imsi, csr->imsi.header.len,
				csr->bearer_context.ebi.eps_bearer_id, &context, apn_indx);
		if (ret) {
			rte_free(csr);
			return ret;
		}

		if (csr->mei.header.len)
			memcpy(&context->mei, &csr->mei.mei, csr->mei.header.len);
		memcpy(context->msisdn, csr->msisdn.msisdn, BINARY_MSISDN_LEN);

		/* VCCCCB-44, CDR content verification
		 * Populate MNC/MCC from proper Serving Network IE */
		if (csr->serving_nw.header.len)
			memcpy(&context->serving_nw, &csr->serving_nw, sizeof(serving_network_ie_t));

		/* ASR- TMOPL VCCCCB-21
		 * NGIC state info re-design for billing and LI
		 */
		if (csr->uli.header.len) {
			memcpy(&context->tai, &csr->uli.tai, sizeof(struct tai_t));
			memcpy(&context->ecgi, &csr->uli.ecgi, sizeof(struct ecgi_t));
			memcpy(&context->uli_info, &csr->uli_info, sizeof(uli_info_ie_t));
		}
		if (csr->rat_type.header.len) {
			memcpy(&context->rat_type, &csr->rat_type, sizeof(rat_type_ie_t));
		}
		if (csr->seletion_mode.header.len) {
			memcpy(&context->seletion_mode,
					&csr->seletion_mode, sizeof(selection_mode_ie_t));
		}
		if (csr->pdn_type.header.len) {
			memcpy(&context->pdn_type,
					&csr->pdn_type + sizeof(csr->pdn_type.header),
					csr->pdn_type.header.len);
		}
		if (csr->paa.header.len) {
			memcpy(&context->paa,
					&csr->paa + sizeof(csr->paa.header),
					csr->paa.header.len);
			/* SM- TMOPL VCCCCB-44 CDR Content verification */
			context->paa.ip_type.ipv4.s_addr = ue_ip.s_addr;
		}
		if (csr->ue_timezone.header.len) {
			memcpy(&context->ue_timezone, &csr->ue_timezone,
					sizeof(ue_timezone_ie_t));
		}
		if (csr->charging_characteristics.header.len) {
			memcpy(&context->charging_characteristics,
					&csr->charging_characteristics,
					sizeof(charging_char_ie_t));
		}

		/* SM- TMOPL VCCCCB-35
		 * Send Delete session response based on SI
		 */
		memcpy(&context->indication_value, &csr->indication.indication_value,
				sizeof(indication_t));
		context->s11_sgw_gtpc_ipv4 = s11_sgw_ip;
		context->s11_mme_gtpc_teid = csr->sender_ftied.teid_gre;
		/* ASR- TMOPL VCCCCB-4 CP to support many MMEs
		 * set:
		 * 		s11_mme_sockaddr.sin_addr = csr->sender_ftied.ip.ipv4
		 */
		context->s11_mme_gtpc_ipv4 = csr->sender_ftied.ip.ipv4;

		pdn = context->pdns[ebi_index];
		{
			pdn->apn_in_use = apn_req;
			pdn->apn_ambr.ambr_downlink = csr->ambr.apn_ambr_dl;
			pdn->apn_ambr.ambr_uplink = csr->ambr.apn_ambr_ul;
			pdn->apn_restriction = csr->apn_restriction.restriction_type;
			pdn->ipv4.s_addr = htonl(ue_ip.s_addr);

			if (csr->pdn_type.pdn_type == PDN_TYPE_IPV4)
				pdn->pdn_type.ipv4 = 1;
			else if (csr->pdn_type.pdn_type == PDN_TYPE_IPV6)
				pdn->pdn_type.ipv6 = 1;
			else if (csr->pdn_type.pdn_type == PDN_TYPE_IPV4_IPV6) {
				pdn->pdn_type.ipv4 = 1;
				pdn->pdn_type.ipv6 = 1;
			}

			if (csr->charging_characteristics.header.len)
				memcpy(&pdn->charging_characteristics,
						&csr->charging_characteristics.value,
						sizeof(csr->charging_characteristics.value));

			pdn->s5s8_sgw_gtpc_ipv4 = s5s8_sgwc_ip;
			/* Note: s5s8_sgw_gtpc_teid =
			 * s11_sgw_gtpc_teid
			 */
			pdn->s5s8_sgw_gtpc_teid = context->s11_sgw_gtpc_teid;

			/* Copy the pgw-c ip address in host byte order */
			pdn->s5s8_pgw_gtpc_ipv4.s_addr = ntohl(s5s8_pgwc_ip.s_addr);

			/* Set the s5s8 pgw gtpc teid */
			set_s5s8_pgw_gtpc_teid(pdn);
		}

		bearer = context->eps_bearers[ebi_index];
		{
			/* TODO: Implement TFTs on default bearers
			   if (create_session_request.bearer_tft_ie) {
			   }
			   */
			bearer->qos.qos.ul_mbr =
				csr->bearer_context.bearer_qos.maximum_bit_rate_for_uplink;
			bearer->qos.qos.dl_mbr =
				csr->bearer_context.bearer_qos.maximum_bit_rate_for_downlink;
			bearer->qos.qos.ul_gbr =
				csr->bearer_context.bearer_qos.guaranteed_bit_rate_for_uplink;
			bearer->qos.qos.dl_gbr =
				csr->bearer_context.bearer_qos.guaranteed_bit_rate_for_downlink;

			bearer->s1u_sgw_gtpu_ipv4 = s1u_sgw_ip;
			set_s1u_sgw_gtpu_teid(bearer, context);
			bearer->s5s8_sgw_gtpu_ipv4 = s5s8_sgwu_ip;
			/* Note: s5s8_sgw_gtpu_teid based s11_sgw_gtpc_teid
			 * Computation same as s1u_sgw_gtpu_teid
			 */
			set_s5s8_sgw_gtpu_teid(bearer, context);
			bearer->pdn = pdn;

			/*
			if (create_session_request.s11u_mme_fteid) {
				bearer->s11u_mme_gtpu_ipv4 =
					IE_TYPE_PTR_FROM_GTPV2C_IE(fteid_ie,
							create_session_request.s11u_mme_fteid)->ip_u.ipv4;
				bearer->s11u_mme_gtpu_teid =
					IE_TYPE_PTR_FROM_GTPV2C_IE(fteid_ie,
							create_session_request.s11u_mme_fteid)->
					fteid_ie_hdr.teid_or_gre;
			}*/
		}

		if (spgw_cfg == SGWC) {
			ret =
				gen_sgwc_s5s8_create_session_request(gtpv2c_rx,
					gtpv2c_s5s8_tx, gtpv2c_rx->teid_u.has_teid.seq,
					pdn, bearer);
			RTE_LOG_DP(DEBUG, CP, "NGIC- create_session.c::"
					"\n\tprocess_create_session_request::case= %d;"
					"\n\tprocess_sgwc_s5s8_cs_req_cnt= %u;"
					"\n\tgen_create_s5s8_session_request= %d\n",
					spgw_cfg, process_sgwc_s5s8_cs_req_cnt++,
					ret);
			rte_free(csr);
			return ret;
		}

		cause_val = cause_res;
		/* Set create session response */
		resp_t.cause_val = cause_val;
		resp_t.gtpv2c_tx_t = *gtpv2c_s11_tx;
		resp_t.context_t = *context;
		resp_t.cp_context_ref = context;
		resp_t.pdn_t = *pdn;
		resp_t.bearer_t = *bearer;
		resp_t.gtpv2c_tx_t.teid_u.has_teid.seq = csr->header.teid.has_teid.seq;
		resp_t.msg_type = GTP_CREATE_SESSION_REQ;
		/* resp_t.msg_type = csr->header.gtpc.type;
		 * TODO: Revisit: Handle type received from message */

		RTE_LOG_DP(DEBUG, CP, "NGIC- create_session.c::"
				"\n\tprocess_create_session_request::case= %d;"
				"\n\tprocess_spgwc_s11_cs_res_cnt= %u;"
				"\n\tset_create_session_response::done...\n",
				spgw_cfg, process_spgwc_s11_cs_res_cnt++);

		/* session_info: Initialize - Provision */
		/* ASR- TMOPL VCCCCB-25:
		 * Charging integration on CP + Secure CDR transfer interface
		 * Allocate session_info on CP heap
		 */
		struct session_info *session;
		session = rte_zmalloc_socket(NULL, sizeof(struct session_info),
		    RTE_CACHE_LINE_SIZE, rte_socket_id());

		/* ASR- TMOPL VCCCCB-25
		 * Reference @DP session_info:: apn_idx, ue_context, pdn_connection
		 */
		/* session_info: CP CDR collation handle */
		context->dp_session = session;
		session->dp_session = context->dp_session;
		/* ue_context: CP CDR collation handle */
		session->ue_context = context;
		/* pdn_connection: CP CDR collation handle */
		session->pdn_context = pdn;

		/* ASR- TMOPL VCCCCB-21
		 * NGIC state info re-design for billing and LI
		 */
		/* apn_idx: Ref to DP for CDRs */
		session->apn_idx = apn_indx;
		/* tmr_trshld, vol_trshld: DP CDR triggers */
		session->ipcan_dp_bearer_cdr.tmr_trshld =
						*pdn->apn_in_use->tmr_trshld;
		session->ipcan_dp_bearer_cdr.vol_trshld =
						*pdn->apn_in_use->vol_trshld;

		session->ue_addr.iptype = IPTYPE_IPV4;
		session->ue_addr.u.ipv4_addr = pdn->ipv4.s_addr;

		/* s1u_sgw_gtpu_teid: Unique session identifier */
		session->ul_s1_info.sgw_teid =
			htonl(bearer->s1u_sgw_gtpu_teid);
		session->ul_s1_info.sgw_addr.iptype = IPTYPE_IPV4;
		session->ul_s1_info.sgw_addr.u.ipv4_addr =
			htonl(bearer->s1u_sgw_gtpu_ipv4.s_addr);

		if (bearer->s11u_mme_gtpu_teid) {
			/* If CIOT: [enb_addr,enb_teid] =
			 * s11u[mme_gtpu_addr, mme_gtpu_teid]
			 */
			session->ul_s1_info.enb_addr.iptype = IPTYPE_IPV4;
			session->ul_s1_info.enb_addr.u.ipv4_addr =
				htonl(bearer->s11u_mme_gtpu_ipv4.s_addr);
			session->dl_s1_info.enb_teid =
				htonl(bearer->s11u_mme_gtpu_teid);
			session->dl_s1_info.enb_addr.iptype = IPTYPE_IPV4;
			session->dl_s1_info.enb_addr.u.ipv4_addr =
				htonl(bearer->s11u_mme_gtpu_ipv4.s_addr);
		} else {
			session->ul_s1_info.enb_addr.iptype = IPTYPE_IPV4;
			session->ul_s1_info.enb_addr.u.ipv4_addr =
				htonl(bearer->s1u_enb_gtpu_ipv4.s_addr);
			session->dl_s1_info.enb_teid =
				htonl(bearer->s1u_enb_gtpu_teid);
			session->dl_s1_info.enb_addr.iptype = IPTYPE_IPV4;
			session->dl_s1_info.enb_addr.u.ipv4_addr =
				htonl(bearer->s1u_enb_gtpu_ipv4.s_addr);
		}

		session->dl_s1_info.sgw_addr.iptype = IPTYPE_IPV4;
		session->dl_s1_info.sgw_addr.u.ipv4_addr =
			htonl(bearer->s1u_sgw_gtpu_ipv4.s_addr);
		session->ul_apn_mtr_idx = ulambr_idx;
		session->dl_apn_mtr_idx = dlambr_idx;
		session->num_ul_pcc_rules = 1;
		session->num_dl_pcc_rules = 1;
		session->ul_pcc_rule_id[0] = FIRST_FILTER_ID;
		session->dl_pcc_rule_id[0] = FIRST_FILTER_ID;

		/* ue ipv4 addr is unique UE identifier.
		 * sess_id is combination of ue addr and bearer id.
		 * set sess_id = (ue_ipv4_addr << 4) | bearer_id
		 */
		session->sess_id = SESS_ID(context->s11_sgw_gtpc_teid,
							bearer->eps_bearer_id);

		struct dp_id dp_id = { .id = DPN_ID };

		if (session_create(dp_id, session) < 0)
			rte_exit(EXIT_FAILURE,"Bearer Session create fail !!!");
		if (bearer->s11u_mme_gtpu_teid) {
			session->num_dl_pcc_rules = 1;
			session->dl_pcc_rule_id[0] = FIRST_FILTER_ID;

			session->num_adc_rules = num_adc_rules;
			uint32_t i;
			for (i = 0; i < num_adc_rules; ++i)
				        session->adc_rule_id[i] = adc_rule_id[i];

			if (session_modify(dp_id, session) < 0)
				rte_exit(EXIT_FAILURE, "Bearer Session create CIOT implicit modify fail !!!");
		}
		rte_free(csr);
		return 0;
	} else {
		/* TMOPL VCCCCB-19: cause argument for s11 response */
		/* ASR- malloc temp ue_context elements
		 * cause_res != GTPV2C_CAUSE_REQUEST_ACCEPTED
		 * set_create_session_response(...) failure cause */
		context = rte_zmalloc_socket(NULL, sizeof(ue_context),
		    RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (context == NULL) {
			fprintf(stderr,
					"S11 cuase error- Failure to allocate temp ue context"
					"\nDropping packet\n");
			rte_free(csr);
			return -ENOMEM;
		}
		context->s11_sgw_gtpc_ipv4 = s11_sgw_ip;
		context->s11_mme_gtpc_teid = csr->sender_ftied.teid_gre;
		context->s11_mme_gtpc_ipv4 = csr->sender_ftied.ip.ipv4;

		/* ASR- malloc temp eps_bearer elements
		 * cause_res != GTPV2C_CAUSE_REQUEST_ACCEPTED
		 * set_create_session_response(...)::Bearer Context failure cause */
		bearer = rte_zmalloc_socket(NULL, sizeof(eps_bearer),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (bearer == NULL) {
			fprintf(stderr,
					"S11 cuase error- Failure to allocate temp eps_bearer"
					"\nDropping packet\n");
			rte_free(context);
			rte_free(csr);
			return -ENOMEM;
		}
		bearer->eps_bearer_id = csr->bearer_context.ebi.eps_bearer_id;
		set_create_session_response(
				gtpv2c_s11_tx, csr->header.teid.has_teid.seq,
				context, pdn, bearer, cause_res);
		uint16_t payload_length = ntohs(gtpv2c_s11_tx->gtpc.length)
				+ sizeof(gtpv2c_s11_tx->gtpc);
		gtpv2c_send(s11_fd, s11_tx_buf, payload_length,
				(struct sockaddr *) &s11_mme_sockaddr,
				s11_mme_sockaddr_len);

		/* ASR- free temp ue_context & eps_bearer */
		rte_free(context);
		rte_free(bearer);
		rte_free(csr);
		return cause_res;
	}
}

