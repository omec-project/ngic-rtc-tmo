/*
 * Copyright (c) 2020 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *		http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdint.h>
#include <arpa/inet.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_jhash.h>
#include <rte_cfgfile.h>

#include "interface.h"
#include "meter.h"
#include "common_ipc_api.h"
#include "gtpv2c_ie.h"

#ifdef SDN_ODL_BUILD
#include "zmqsub.h"
#include "zmqpub.h"
#ifdef CP_BUILD
#include "nb.h"
#endif /* SDN_ODL_BUILD && CP_BUILD */
#else /* !SDN_ODL_BUILD */
#include "zmq_push_pull.h"
#endif /* SDN_ODL_BUILD */

#ifdef CP_BUILD
#include "cp.h"
#include "cp_stats.h"
#endif /* CP_BUILD */

#include "main.h"
#include "../dp/perf_timer.h"

#if defined(CP_BUILD) && defined(SGX_BUILD)
#include "gtpv2c_set_ie.h"
#include "ssl_client.h"
#include "sctf.h"

#define DEALERIN_IP "dealer_in_ip"
#define DEALERIN_PORT "dealer_in_port"
#define DEALERIN_MRENCLAVE "dealer_in_mrenclave"
#define DEALERIN_MRSIGNER "dealer_in_mrsigner"
#define DEALERIN_ISVSVN "dealer_in_isvsvn"
#define DP_CERT_PATH "dp_cert_path"
#define DP_PKEY_PATH "dp_pkey_path"
#define SSL_MAX_CDR_QUEUE_SIZE 8192
#define SSL_RECONNECT_FREQ 1000

const char *dealer_in_ip;		/* dealerIn ip */
const char *dealer_in_port;		/* dealerIn port */
const char *dealer_in_mrenclave;	/* dealerIn mrenclave */
const char *dealer_in_mrsigner;		/* dealerIn mrsigner */
const char *dealer_in_isvsvn;		/* dealerIn isvsvn */
const char *dp_cert_path;			/* dp cert path */
const char *dp_pkey_path;			/* dp publickey path */
SSL *ssl_handle;
struct rte_ring *ssl_ring = NULL;
extern sctf_msg_t *sctf_msg;
extern uint8_t send_cdr;
#ifndef SDN_ODL_BUILD
extern uint8_t node_id[];
#endif /* !SDN_ODL_BUILD */
#endif /* defined(CP_BUILD) && defined(SGX_BUILD) */

#define NODE_ID_LEN 32
#define ASN1_DER_LEN 512

/* DP zmq_mbuf_push("cdr_ring", ...) over interface */
#ifdef DP_BUILD
extern struct rte_ring *cdr_ring;
#else /* CP_BUILD */
extern struct rte_hash *resp_op_id_hash;
#endif /* DP_BUILD */

/* VS: ROUTE DISCOVERY */
extern int netlink_sock;

#ifdef SDN_ODL_BUILD
struct in_addr fpc_ip;
uint16_t fpc_port;
uint16_t fpc_topology_port;

struct in_addr cp_nb_ip;
uint16_t cp_nb_port;
#endif /* SDN_ODL_BUILD */

#ifdef CP_BUILD
struct in_addr zmq_cp_ip;
uint16_t zmq_cp_pull_port;
uint16_t zmq_cp_push_port;
#else /* DP_BUILD */
struct in_addr zmq_dp_ip;
uint16_t zmq_dp_pull_port;
uint16_t zmq_dp_push_port;
#endif /* CP_BUILD */

#ifdef PERF_ANALYSIS
extern void print_perf_statistics(void);
#endif /* PERF_ANALYSIS */

extern struct ipc_node *basenode;

void register_comm_msg_cb(enum cp_dp_comm id,
			int (*init)(void),
			int (*send)(void *msg_payload, uint32_t size),
			int (*recv)(void *msg_payload, uint32_t size),
			int (*destroy)(void))
{
	struct comm_node *node;

	node = &comm_node[id];
	node->init = init;
	node->send = send;
	node->recv = recv;
	node->destroy = destroy;
	node->status = 0;
	node->init();
}

int set_comm_type(enum cp_dp_comm id)
{
	if (comm_node[id].status == 0 && comm_node[id].init != NULL) {
		active_comm_msg = &comm_node[id];
		comm_node[id].status = 1;
	} else {
		RTE_LOG_DP(ERR, DP,"Error: Cannot set communication type\n");
		return -1;
	}
	return 0;
}

int unset_comm_type(enum cp_dp_comm id)
{
	if (comm_node[id].status) {
		active_comm_msg->destroy();
		comm_node[id].status = 0;
	} else {
		RTE_LOG_DP(ERR, DP,"Error: Cannot unset communication type\n");
		return -1;
	}
	return 0;
}

#ifndef SDN_ODL_BUILD
#ifdef CP_BUILD
/**
 * Assemble Secure Charge Trigger Function (SCTF)  message
 * @param buf
 *	buf - message buffer.
 *
 * @return
 *	void
 */
void sctf_msg_assemble(struct resp_msgbuf *rbuf)
{
	uint64_t imsi;
	int apn_len = 0, apn_ni_len = 0, enc_apn_len = 0, ret = 0;
	/* Assemble cdr_report struct for sctf_send(...) */
	ue_context *context = rbuf->cdr_msg.ue_context;
	struct session_info *session = rbuf->cdr_msg.session_info;
	struct response_info *tmp = NULL;
	memset(sctf_msg, 0, sizeof(struct sctf_msg));

	if(!context || !session)
		return;

	sctf_msg->recordType = cdr_record_type;

	imsi = context->imsi ;
	*((uint8_t *)(&imsi) + APN_IMSI_KEY_POSTN) =
		*((uint8_t *)(&imsi) + APN_IMSI_KEY_POSTN) >> APN_IMSI_KEY_LEN | APN_IMSI_SHIFT_VAL;

	memcpy(sctf_msg->servedIMSI, &imsi, BINARY_IMSI_LEN);
	sctf_msg->p_GWAddress.s_addr = htonl(s5s8_pgwc_ip.s_addr);
	sctf_msg->servingNodeAddress = context->s11_mme_gtpc_ipv4;

	apn_len = strlen(session->pdn_context->apn_in_use->apn_name_label);
	/* If APN name contains op. identifier then reduce that length
	 * (APN_OI_LEN), otherwise copy the APN as it is. One byte indicates
	 * length of the APN name
	 */
	if (apn_len > APN_OI_LEN) {
		apn_ni_len = apn_len - APN_OI_LEN;
		if(apn_ni_len == session->pdn_context->apn_in_use->apn_name_label[0]) {
			//APN = internet.mnc022.mcc001.gprs
			memcpy(sctf_msg->accessPointNameNI,
					&session->pdn_context->apn_in_use->apn_name_label[1], apn_ni_len);
		} else {
			//APN = internet.lab.mnc022.mcc001.gprs
			while(enc_apn_len < apn_ni_len) {
				memcpy(&sctf_msg->accessPointNameNI[enc_apn_len],
						&session->pdn_context->apn_in_use->apn_name_label[enc_apn_len + 1],
						session->pdn_context->apn_in_use->apn_name_label[enc_apn_len]);
				enc_apn_len += session->pdn_context->apn_in_use->apn_name_label[enc_apn_len];
				if(enc_apn_len < apn_ni_len) {
					sctf_msg->accessPointNameNI[enc_apn_len] = ASC_VAL_FOR_DOT;
					enc_apn_len += 1;
				}
			}
		}
	} else {
		//APN = internet
		memcpy(sctf_msg->accessPointNameNI,
				&session->pdn_context->apn_in_use->apn_name_label[1], apn_len - 1);
	}

	sctf_msg->pdpPDNType.pdn_type =
					context->pdn_type.pdn_type;
	sctf_msg->pdpPDNType.spare =
					context->pdn_type.spare;
	sctf_msg->servedPDPPDNAddress.s_addr = htonl(context->paa.ip_type.ipv4.s_addr);
	sctf_msg->dynamicAddressFlag =
					context->paa.ip_type.ipv4.s_addr == 0? 0:1;
	sctf_msg->recordOpeningTime =
					rbuf->cdr_msg.recordOpeningTime;
	sctf_msg->duration = rbuf->cdr_msg.timeUsage;
	sctf_msg->causeForRecClosing =
			rbuf->cdr_msg.record_closure_cause;
	ret = rte_hash_lookup_data(resp_op_id_hash, (void *)&rbuf->op_id,
			(void **)&tmp);
	if (ret != -ENOENT) {
		if (tmp->cause_val ==
				GTPV2C_CAUSE_MULTIPLE_CONNECTIONS_ON_APN_NOT_ALLOWED) {
			sctf_msg->causeForRecClosing = CDR_REC_ABNORMAL_REL;
		}
	}
	strncpy((char *)sctf_msg->nodeID, (char *)node_id, strlen((char *)node_id));

	uint8_t slctn_md =
					context->seletion_mode.selec_mode &
							SLCTN_MODE_MASK;
	switch (slctn_md) {
		case MS_NETWORK_PROVIDED_SUBSCRIPTION_VERIFIED:
		slctn_md = MS_NETWORK_PROVIDED_SUBSCRIPTION_VERIFIED;
		break;

		case MS_PROVIDED_SUBSCRIPTION_NOTVERIFIED:
		slctn_md = MS_PROVIDED_SUBSCRIPTION_NOTVERIFIED;
		break;

		case NETWORK_PROVIDED_SUBSCRIPTION_NOTVERIFIED:
		slctn_md = NETWORK_PROVIDED_SUBSCRIPTION_NOTVERIFIED;
		break;

		default:
		slctn_md = MS_NETWORK_PROVIDED_SUBSCRIPTION_VERIFIED;
		break;
	}
	sctf_msg->apnSelectionMode = slctn_md;

	memcpy(sctf_msg->servedMSISDN, context->msisdn, BINARY_MSISDN_LEN);
	memcpy(sctf_msg->uli_info, context->uli_info.uli_info, ULI_LEN);

	sctf_msg->chargingCharacteristics =
					htons(context->charging_characteristics.value);
	sctf_msg->chChSelectionMode = chch_slctn_md;
	sctf_msg->servingNodePLMNIdentifier =
					context->serving_nw.mcc_mnc;

	memcpy(sctf_msg->servedIMEISV,
		&context->mei, BINARY_MEI_LEN);

	sctf_msg->rATType =
					context->rat_type.rat_type;
	sctf_msg->mSTimeZone.timezone =
					context->ue_timezone.timezone;
	sctf_msg->mSTimeZone.spare1 =
					context->ue_timezone.spare1;
	sctf_msg->mSTimeZone.ds_time =
					context->ue_timezone.ds_time;
	memcpy(&sctf_msg->tai, &context->tai, sizeof(tai_t));
	memcpy(&sctf_msg->ecgi, &context->ecgi, sizeof(ecgi_t));
	sctf_msg->chargingID =
					rbuf->cdr_msg.chargingID;
	sctf_msg->cdr_container.ratingGroup = RATING_GROUP_VOL;

	/* Hardcoding the below two values as per VCCCCB-25 */
	strcpy((char *)sctf_msg->cdr_container.chargingRuleBaseName, "defaultCRBN");
	sctf_msg->cdr_container.resultCode = 2001;

	sctf_msg->cdr_container.localSequenceNumber =
					rbuf->cdr_msg.localSequenceNumber;
	sctf_msg->cdr_container.timeOfFirstUsage =
					rbuf->cdr_msg.timeOfFirstUsage;
	sctf_msg->cdr_container.timeOfLastUsage =
					rbuf->cdr_msg.timeOfLastUsage;
	sctf_msg->cdr_container.timeUsage =
					rbuf->cdr_msg.timeUsage;

	switch (rbuf->cdr_msg.record_closure_cause) {
		case CDR_REC_DEL:
			sctf_msg->cdr_container.serviceConditionChange =
				(1 << RECORD_CLOSURE);
			break;
		case CDR_REC_TIME:
			sctf_msg->cdr_container.serviceConditionChange =
				(1 << TIMELIMIT);
			break;
		case CDR_REC_VOL:
			sctf_msg->cdr_container.serviceConditionChange =
				(1 << VOLUMELIMIT);
			break;
		default:
			sctf_msg->cdr_container.serviceConditionChange =
				(1 << RECORD_CLOSURE);
			break;
	}
	/* Bearer Negotiation not supported:
	 * Set qCI, UL/DL BW, UL/DL bitrate, ARP = 0 */
	sctf_msg->cdr_container.qCI = 0;
	sctf_msg->cdr_container.maxRequestedBandwithUL = 0;
	sctf_msg->cdr_container.maxRequestedBandwithDL = 0;
	sctf_msg->cdr_container.guaranteedBitrateUL = 0;
	sctf_msg->cdr_container.guaranteedBitrateDL = 0;
	sctf_msg->cdr_container.aRP = 0;

	sctf_msg->cdr_container.datavolumeFBCUplink =
					rbuf->cdr_msg.datavolumeFBCUplink;
	sctf_msg->cdr_container.datavolumeFBCDownlink =
					rbuf->cdr_msg.datavolumeFBCDownlink;
	sctf_msg->cdr_container.timeOfReport =
					rbuf->cdr_msg.timeOfReport;
}

/**
 * Process DP Response
 * @param buf
 *	buf - message buffer.
 *
 * @return
 *	0 - success
 *	-1 - fail
 */
int process_dp_resp(void *buf)
{
	int rc;
	uint8_t der[DER_LEN];
	/* Distinguished Encoding Rule (der) length */
	uint16_t der_length = 0;

	struct resp_msgbuf *rbuf = (struct resp_msgbuf *)buf;

	if (rbuf->mtype >= MSG_END)
		return -1;

	switch(rbuf->mtype) {
		case DPN_CREATE_RESP:
			ifistats.cups_csrsp++;
			del_resp_op_id(rbuf->op_id);
			break;

		case DPN_MODIFY_RESP:
			ifistats.cups_mbrsp++;
			del_resp_op_id(rbuf->op_id);
			break;

		case DPN_DELETE_RESP:
#ifdef FOR_REF
			printf("DPN_DELETE_RESP::%s::"
					"\n\tratingGroup:[%u]; localSequenceNumber:[%lu];"
					"\n\ttimeOfFirstUsage:[%lu]; timeOfLastUsage:[%lu]"
					"\n\trecordOpeningTime:[%lu]",
					__func__, rbuf->cdr_msg.ratingGroup, rbuf->cdr_msg.localSequenceNumber,
					rbuf->cdr_msg.timeOfFirstUsage, rbuf->cdr_msg.timeOfLastUsage,
					rbuf->cdr_msg.recordOpeningTime);
			printf("\n\ttimeUsage:[%lu]; record_closure_cause:[%x];"
					"\n\ttimeOfReport:[%lu];"
					"\n|tue_context:[%p]; apn_idx:[%u]",
					rbuf->cdr_msg.timeUsage, rbuf->cdr_msg.record_closure_cause,
					rbuf->cdr_msg.timeOfReport,
					rbuf->cdr_msg.ue_context, rbuf->cdr_msg.apn_idx);
			printf("\n\tdatavolumeFBCUplink:[%lu]",
					rbuf->cdr_msg.datavolumeFBCUplink);
			printf("\n\tdatavolumeFBCDownlink:[%lu]\n",
					rbuf->cdr_msg.datavolumeFBCDownlink);
#endif /* FOR_REF */
			sctf_msg_assemble(rbuf);
			der_length = sctf_to_asn1_encode(sctf_msg, der);
			if((der_length != 0) && send_cdr)
				write_sctf(der, der_length);
			ifistats.cups_dsrsp++;
			del_resp_op_id(rbuf->op_id);
			break;

		case DPN_DDN_REQ:
			/* DDN Callback API */
			rc= cb_ddn(rbuf->sess_id);
			if (rc < 0)
					return -1;
			break;

		case CDR_UPDATE:
#ifdef FOR_REF
			printf("CDR_UPDATE::%s::"
					"\n\tratingGroup:[%u]; localSequenceNumber:[%lu];"
					"\n\ttimeOfFirstUsage:[%lu]; timeOfLastUsage:[%lu]"
					"\n\trecordOpeningTime:[%lu]",
					__func__, rbuf->cdr_msg.ratingGroup, rbuf->cdr_msg.localSequenceNumber,
					rbuf->cdr_msg.timeOfFirstUsage, rbuf->cdr_msg.timeOfLastUsage,
					rbuf->cdr_msg.recordOpeningTime);
			printf("\n\ttimeUsage:[%lu]; record_closure_cause:[%x];"
					"\n\ttimeOfReport:[%lu];"
					"\n\tue_context:[%p]; apn_idx:[%u]",
					rbuf->cdr_msg.timeUsage, rbuf->cdr_msg.record_closure_cause,
					rbuf->cdr_msg.timeOfReport,
					rbuf->cdr_msg.ue_context, rbuf->cdr_msg.apn_idx);
			printf("\n\tdatavolumeFBCUplink:[%lu]",
					rbuf->cdr_msg.datavolumeFBCUplink);
			printf("\n\tdatavolumeFBCDownlink:[%lu]\n",
					rbuf->cdr_msg.datavolumeFBCDownlink);
#endif /* FOR_REF */
			sctf_msg_assemble(rbuf);
			der_length = sctf_to_asn1_encode(sctf_msg, der);
			if((der_length != 0) && send_cdr)
				write_sctf(der, der_length);
			break;

		default:
			break;
	}

	return 0;
}

#ifdef SGX_BUILD
static int ssl_connect(void)
{
	int sent = -1;

	ssl_handle = sgx_cdr_channel_init(dealer_in_ip, dealer_in_port,
				dp_cert_path, dp_pkey_path, dealer_in_mrenclave,
				dealer_in_mrsigner, dealer_in_isvsvn);

	if (ssl_handle == NULL) {
		printf("\nError in connecting to DealerIn.\n");
		return -1;
	}
	/* TODO: Add error handling for SSL_Write and reconnect*/

	if (ssl_handle != NULL) {
			printf("SSLWrite filename :%s\n",node_id);
			sent = SSL_write(ssl_handle, (char *)node_id, strlen((char *)node_id));

			if (sent <= 0) {
				rte_panic("Error in sending filename to SGX DealerIn. Error %d\n",
					SSL_get_error(ssl_handle, sent));
			}
	}
	return 0;
}
/* CP:: Initialize secure CTF interface */
void init_sctf(void) {

	sctf_msg = rte_malloc_socket(NULL, sizeof(sctf_msg_t),
						RTE_CACHE_LINE_SIZE, rte_socket_id());
	cdr_record_type = PGW_RECORD;
	/*ASR- TODO: Check/Close w/ TMOPL */
	chch_slctn_md = SERVINGNODE_SUPPLIED;
	/* ASR- TODO: Reflect from modify bearer pcap reference */
	svc_cond_chg = (1 << RECORD_CLOSURE);
	if (send_cdr) {
		signal(SIGPIPE, SIG_IGN);
		/* CDR Ring creation */
		ssl_ring = rte_ring_create("SSL_RING", SSL_MAX_CDR_QUEUE_SIZE,
				rte_socket_id(),
				RING_F_SP_ENQ | RING_F_SC_DEQ);

		if (ssl_ring == NULL) {
			rte_exit(EXIT_FAILURE, "Error in creating ssl ring!!!\n");
		}
		ssl_connect();
	}
}

void close_sctf(void)
{
	if (ssl_handle != NULL) {
		sgx_cdr_channel_close(ssl_handle);
	}
	if(sctf_msg)
		rte_free(sctf_msg);
}

static void queue_der_msg(uint8_t *der, uint16_t der_len)
{
	uint8_t *msg = NULL;
	msg = rte_zmalloc_socket(NULL, DER_LEN,
				RTE_CACHE_LINE_SIZE, rte_socket_id());
	if(!msg)
		rte_panic("Error in allocating memory, Exiting.");

	memcpy(msg, der, der_len);
	int ret = rte_ring_enqueue(ssl_ring, (void *)msg);
	if (ret == -ENOBUFS) {
		rte_free(msg);
		printf("CDR Message Queue full, dropping CDRs\n");
	}
}

void
write_sctf(uint8_t *der, uint16_t der_len)
{
	int sent = -1;
	uint16_t queued_msg_len = 0;
	uint8_t *msg = NULL;
	static uint64_t sctf_msg_cnt = 0;

	queue_der_msg(der, der_len);
	if (ssl_handle == NULL) {
		if((++sctf_msg_cnt%SSL_RECONNECT_FREQ) == 0)
			ssl_connect();
	}

	if(ssl_handle) { //SSL connected to dealer-in successfully
		while (!rte_ring_empty(ssl_ring)) {
			rte_ring_dequeue(ssl_ring, (void **) &msg);
			//The length is indicated by two bytes (fourth and fifth byte)
			queued_msg_len = msg[PGW_REC_HEADER_LEN-2] << 8 | msg[PGW_REC_HEADER_LEN-1];
			//Adding PGW RECORD HEADER length (five bytes)
			queued_msg_len += PGW_REC_HEADER_LEN;
			sent = SSL_write(ssl_handle, der, queued_msg_len);

			if (sent != queued_msg_len) {
				//TODO: check if q into head possible
				rte_ring_enqueue(ssl_ring, (void *)msg);

				//TODO:check SSL context set mode func for automatic SSL connection handling
				ssl_handle = NULL;
				break;
			} else {
				rte_free(msg);
			}
		}
	}
}
#endif /* SGX_BUILD */
#endif /* CP_BUILD */

#ifdef DP_BUILD
int process_comm_msg(void *buf)
{
	struct msgbuf *rbuf = (struct msgbuf *)buf;

	if (rbuf->mtype >= MSG_END)
		return -1;

	/* Callback APIs */
	struct ipc_node *cb;
	cb = &basenode[rbuf->mtype];

	struct resp_msgbuf resp = {0};

	/* ASR- Before message handler::cb->msg_cb(rbuf)
	 * get_session_data(...) > create_cdr_report(...) */
	if(rbuf->mtype == MSG_SESS_DEL) {
		struct dp_session_info *session;
		session = get_session_data(rbuf->msg_union.sess_entry.sess_id, SESS_MODIFY);
		if (session == NULL) {
			printf("Session id 0x%"PRIx64" not found\n", rbuf->msg_union.sess_entry.sess_id);
		} else {
			update_vol_on_rec_close(session, CDR_REC_DEL);
			create_cdr_report(&resp, rbuf->msg_union.sess_entry.sess_id);
		}
	}

	/* ASR- Callback msg handler registered
	 * @sess_table.c::iface_ipc_register_msg_cb(...)::
	 * msg_cb(MSG_SESS_CRE, cb_session_create); msg_cb(MSG_SESS_MOD, cb_session_modify);
	 * msg_cb(MSG_SESS_DEL, cb_session_delete); */
	int rc = cb->msg_cb(rbuf);
	if (rc == 0) {
		switch(rbuf->mtype) {
			/* ASR- Preserve::
			 * cp::session_info->op_id >> dp::resp_msgbuf.op_id */
			case MSG_SESS_CRE: {
				resp.op_id = rbuf->msg_union.sess_entry.op_id;
				resp.dp_id.id = DPN_ID;
				resp.mtype = DPN_CREATE_RESP;
				resp.sess_id = rbuf->msg_union.sess_entry.sess_id;
				zmq_mbuf_push((void *)&resp, sizeof(resp));
				break;
			}
			case MSG_SESS_MOD: {
				resp.op_id = rbuf->msg_union.sess_entry.op_id;
				resp.dp_id.id = DPN_ID;
				resp.mtype = DPN_MODIFY_RESP;
				resp.sess_id = rbuf->msg_union.sess_entry.sess_id;
				zmq_mbuf_push((void *)&resp, sizeof(resp));
				break;
			}
			case MSG_SESS_DEL: {
				resp.op_id = rbuf->msg_union.sess_entry.op_id;
				resp.dp_id.id = DPN_ID;
				resp.mtype = DPN_DELETE_RESP;
				resp.sess_id = rbuf->msg_union.sess_entry.sess_id;
				zmq_mbuf_push((void *)&resp, sizeof(resp));
				break;
			}
		default:
			break;
		}
	}
	return 0;
}

/* DP::process queued CDR records
 * DP::zmq_mbuf_push("cdr_ring", ...) over interface */
int process_cdr_queue(void)
{
		uint64_t sess_id;
		int ret = rte_ring_dequeue(cdr_ring, (void *)&sess_id);
		if (ret == 0) {
			struct resp_msgbuf resp = {0};
			resp.dp_id.id = DPN_ID;
			resp.mtype = CDR_UPDATE;
			create_cdr_report(&resp, sess_id);
			zmq_mbuf_push((void *)&resp, sizeof(resp));
		}
	return 0;
}
#endif /* DP_BUILD */

static int
zmq_init_socket(void)
{
	/*
	 * zmqpull/zmqpush init
	 */
	zmq_pull_create();
	return zmq_push_create();
}

static int
zmq_send_socket(void *zmqmsgbuf, uint32_t zmqmsgbufsz)
{
	/*
	 * zmqpush send
	 */
	return zmq_mbuf_push(zmqmsgbuf, zmqmsgbufsz);
}

static int
zmq_recv_socket(void *buf, uint32_t zmqmsgbufsz)
{
	/*
	 * zmqpull recv
	 */
	int zmqmsglen = zmq_mbuf_pull(buf, zmqmsgbufsz);

	if (zmqmsglen > 0) {
		RTE_LOG_DP(DEBUG, DP,
			"Rcvd zmqmsglen= %d:\t zmqmsgbufsz= %u\n",
			zmqmsglen, zmqmsgbufsz);
	}
	return zmqmsglen;
}

static int
zmq_destroy(void)
{
	/*
	 * zmqpush/zmqpull destroy
	 */
	zmq_push_pull_destroy();
	return 0;
}
#endif /* !SDN_ODL_BUILD */

#if defined(DP_BUILD) && defined(SDN_ODL_BUILD)
static int
zmq_init_socket(void)
{
	/*
	 * zmqsub init
	 */
	zmq_pubsocket_create();
	return zmq_subsocket_create();
}
static int
zmq_send_socket(void *zmqmsgbuf, uint32_t zmqmsgbufsz)
{
	/*
	 * zmqsub recv
	 */
	return zmq_mbuf_send(zmqmsgbuf, sizeof(struct zmqbuf));
}

static int
zmq_recv_socket(void *buf, uint32_t zmqmsgbufsz)
{
	/*
	 * zmqsub recv
	 */
	int zmqmsglen = zmq_mbuf_rcv(buf, zmqmsgbufsz);

	if (zmqmsglen > 0)	{
		RTE_LOG_DP(DEBUG, DP,
			"Rcvd zmqmsglen= %d:\t zmqmsgbufsz= %u\n",
			zmqmsglen, zmqmsgbufsz);
	}
	return zmqmsglen;
}

static int
zmq_destroy(void)
{
	/*
	 * zmqsub destroy
	 */
	zmq_subsocket_destroy();
	return 0;
}

int process_comm_msg(void *buf)
{
	struct msgbuf *rbuf = (struct msgbuf *)buf;
	struct ipc_node *cb;

	if (rbuf->mtype >= MSG_END)
		return -1;

	/* Callback APIs */
	cb = &basenode[rbuf->mtype];
	return cb->msg_cb(rbuf);
}

#ifdef PRINT_NEW_RULE_ENTRY
/**
 * @Name : print_sel_type_val
 * @arguments : [In] pointer to adc rule structure element
 * @return : void
 * @Description : Function to print ADC rules values.
 */
static void print_sel_type_val(struct adc_rules *adc)
{
	if (NULL != adc) {
		switch (adc->sel_type) {
		case DOMAIN_NAME:
			RTE_LOG_DP(DEBUG, DP, " ---> Domain Name :%s\n",
				adc->u.domain_name);
			break;

		case DOMAIN_IP_ADDR:
			RTE_LOG_DP(DEBUG, DP, " ---> Domain Ip :%d\n",
				(adc->u.domain_ip.u.ipv4_addr));
			break;

		case DOMAIN_IP_ADDR_PREFIX:
			RTE_LOG_DP(DEBUG, DP, " ---> Domain Ip :%d\n",
				(adc->u.domain_ip.u.ipv4_addr));
			RTE_LOG_DP(DEBUG, DP, " ---> Domain Prefix :%d\n",
				adc->u.domain_prefix.prefix);
			break;

		default:
			RTE_LOG_DP(ERR, DP, "UNKNOWN Selector Type: %d\n",
				adc->sel_type);
			break;
		}
	}
}

/**
 * @Name : print_adc_val
 * @arguments : [In] pointer to adc rule structure element
 * @return : void
 * @Description : Function to print ADC rules values.
 */
static void print_adc_val(struct adc_rules *adc)
{
	if (NULL != adc) {
		RTE_LOG_DP(DEBUG, DP, "=========================================\n");
		RTE_LOG_DP(DEBUG, DP, " ---> ADC Rule Method ::\n");
		RTE_LOG_DP(DEBUG, DP, "=========================================\n");
		RTE_LOG_DP(DEBUG, DP, " ---> Rule id : %d\n", adc->rule_id);

		print_sel_type_val(adc);

		RTE_LOG_DP(DEBUG, DP, "=========================================\n\n");
	}
}

/**
 * @Name : print_pcc_val
 * @arguments : [In] pointer to pcc rule structure element
 * @return : void
 * @Description : Function to print PCC rules values.
 */
static void print_pcc_val(struct pcc_rules *pcc)
{
	if (NULL != pcc) {
		RTE_LOG_DP(DEBUG, DP, "=========================================\n");
		RTE_LOG_DP(DEBUG, DP, " ---> PCC Rule Method ::\n");
		RTE_LOG_DP(DEBUG, DP, "=========================================\n");
		RTE_LOG_DP(DEBUG, DP, " ---> Rule id : %d\n", pcc->rule_id);
		RTE_LOG_DP(DEBUG, DP, " ---> metering_method :%d\n",
			pcc->metering_method);
		RTE_LOG_DP(DEBUG, DP, " ---> charging_mode :%d\n",
			pcc->charging_mode);
		RTE_LOG_DP(DEBUG, DP, " ---> rating_group :%d\n",
			pcc->rating_group);
		RTE_LOG_DP(DEBUG, DP, " ---> rule_status :%d\n",
			pcc->rule_status);
		RTE_LOG_DP(DEBUG, DP, " ---> gate_status :%d\n",
			pcc->gate_status);
		RTE_LOG_DP(DEBUG, DP, " ---> session_cont :%d\n",
			pcc->session_cont);
		RTE_LOG_DP(DEBUG, DP, " ---> monitoring_key :%d\n",
			pcc->monitoring_key);
		RTE_LOG_DP(DEBUG, DP, " ---> precedence :%d\n",
			pcc->precedence);
		RTE_LOG_DP(DEBUG, DP, " ---> level_of_report :%d\n",
			pcc->report_level);
		RTE_LOG_DP(DEBUG, DP, " ---> mute_status :%d\n",
			pcc->mute_notify);
		RTE_LOG_DP(DEBUG, DP, " ---> drop_pkt_count :%ld\n",
			pcc->drop_pkt_count);
		RTE_LOG_DP(DEBUG, DP, " ---> redirect_info :%d\n",
			pcc->redirect_info.info);
		RTE_LOG_DP(DEBUG, DP, " ---> ul_mbr_mtr_profile_idx :%d\n",
			pcc->qos.ul_mtr_profile_index);
		RTE_LOG_DP(DEBUG, DP, " ---> dl_mbr_mtr_profile_idx :%d\n",
			pcc->qos.dl_mtr_profile_index);
		RTE_LOG_DP(DEBUG, DP, " ---> ADC Index :%d\n",
			pcc->adc_idx);
		RTE_LOG_DP(DEBUG, DP, " ---> SDF Index count:%d\n",
			pcc->sdf_idx_cnt);
		for(int i =0; i< pcc->sdf_idx_cnt; ++i)
			RTE_LOG_DP(DEBUG, DP, " ---> SDF IDx [%d]:%d\n",
				i, pcc->sdf_idx[i]);
		RTE_LOG_DP(DEBUG, DP, " ---> rule_name:%s\n", pcc->rule_name);
		RTE_LOG_DP(DEBUG, DP, " ---> sponsor_id:%s\n", pcc->sponsor_id);
		RTE_LOG_DP(DEBUG, DP, "=========================================\n\n");
	}
}

/**
 * @Name : print_mtr_val
 * @arguments : [In] pointer to mtr entry structure element
 * @return : void
 * @Description : Function to print METER rules values.
 */
static void print_mtr_val(struct mtr_entry *mtr)
{
	if (NULL != mtr) {
		RTE_LOG_DP(DEBUG, DP, "=========================================\n");
		RTE_LOG_DP(DEBUG, DP, " ---> Meter Rule Method ::\n");
		RTE_LOG_DP(DEBUG, DP, "=========================================\n");
		RTE_LOG_DP(DEBUG, DP, " ---> Meter profile index :%d\n",
				mtr->mtr_profile_index);
		RTE_LOG_DP(DEBUG, DP, " ---> Meter CIR :%ld\n",
			mtr->mtr_param.cir);
		RTE_LOG_DP(DEBUG, DP, " ---> Meter CBS :%ld\n",
			mtr->mtr_param.cbs);
		RTE_LOG_DP(DEBUG, DP, " ---> Meter EBS :%ld\n",
			mtr->mtr_param.ebs);
		RTE_LOG_DP(DEBUG, DP, " ---> Metering Method :%d\n",
				mtr->metering_method);
		RTE_LOG_DP(DEBUG, DP, "=========================================\n\n");
	}
}

/**
 * @Name : print_sdf_val
 * @arguments : [In] pointer to pkt_filter structure element
 * @return : void
 * @Description : Function to print SDF rules values.
 */
static void print_sdf_val(struct pkt_filter *sdf)
{
	if (NULL != sdf) {
		RTE_LOG_DP(DEBUG, DP, "==========================================\n");
		RTE_LOG_DP(DEBUG, DP, " ---> SDF Rule Method ::\n");
		RTE_LOG_DP(DEBUG, DP, "==========================================\n");

		switch (sdf->sel_rule_type) {
		case RULE_STRING:
			RTE_LOG_DP(DEBUG, DP, " ---> pcc_rule_id :%d\n",
				sdf->pcc_rule_id);
			RTE_LOG_DP(DEBUG, DP, " ---> rule_type :%d\n",
				sdf->sel_rule_type);
			RTE_LOG_DP(DEBUG, DP, " ---> rule_str : %s\n",
				sdf->u.rule_str);
			RTE_LOG_DP(DEBUG, DP, "====================================\n\n");
			break;

		case FIVE_TUPLE:
			/*TODO: rule should be in struct
			 * five_tuple_rule
			 * This field is currently not used
			 */
			break;

		default:
			RTE_LOG_DP(ERR, DP, "UNKNOWN Rule Type: %d\n",
				sdf->sel_rule_type);
			break;
		}
	}
}
#endif /*PRINT_NEW_RULE_ENTRY*/

/**
 * Name : parse_adc_val
 * argument :
 * selctor type pointed to adc rule type
 * [In] pointer (arm) to zmq rcv structure element
 * [Out] pointer (adc) to adc rules structure element
 * @return
 * 0 - success
 * -1 - fail
 * Description : Function to parse adc rules values into
 * adc_rules struct.
 * Here parse values as per selector type (DOMAIN_NAME,
 * DOMAIN_IP_ADDR, and DOMAIN_IP_ADDR_PREFIX), domain name,
 * domain ip addr, domain prefix parameters values from recv buf and
 * stored into adc_rules struct.
 * ref.doc: message_sdn.docx
 * section : Table No.11 ADC Rules
 */
static int parse_adc_buf(int sel_type, char *arm, struct adc_rules *adc)
{
	if (arm != NULL) {
		switch (sel_type) {
		case DOMAIN_NAME:
			strncpy(adc->u.domain_name, (char *)((arm)+1),
					*(uint8_t *)(arm));

#ifdef PRINT_NEW_RULE_ENTRY
				print_adc_val(adc);
#endif
			return 0;

		case DOMAIN_IP_ADDR_PREFIX:
			adc->u.domain_ip.u.ipv4_addr =
				ntohl(*(uint32_t *)(arm));
			adc->u.domain_prefix.prefix =
				rte_bswap16(*(uint16_t *)((arm) + 4));
#ifdef PRINT_NEW_RULE_ENTRY
				print_adc_val(adc);
#endif	/* PRINT_NEW_RULE_ENTRY */
			return 0;

		case DOMAIN_IP_ADDR:
			adc->u.domain_ip.u.ipv4_addr =
				ntohl(*(uint32_t *)(arm));
#ifdef PRINT_NEW_RULE_ENTRY
				print_adc_val(adc);
#endif	/* PRINT_NEW_RULE_ENTRY */
			return 0;

		default:
			RTE_LOG_DP(ERR, DP, "UNKNOWN Selector Type: %d\n",
				sel_type);
			return -1;
		}
	}
	return -1;
}

/**
 * @Name : get_sdf_indices
 * @argument :
 *	[IN] sdf_idx : String containing comma separater SDF index values
 *	[OUT] out_sdf_idx : Array of integers converted from sdf_idx
 * @return : 0 - success, -1 fail
 * @Description : Convert sdf_idx array in to array of integers for SDF index
 * values.
 * Sample input : "[0, 1, 2, 3]"
 */
static uint32_t
get_sdf_indices(char *sdf_idx, uint32_t *out_sdf_idx)
{
	char *tmp = strtok (sdf_idx,",");
	int i = 0;

	while ((NULL != tmp) && (i < MAX_SDF_IDX_COUNT)) {
		out_sdf_idx[i++] = atoi(tmp);
		tmp = strtok (NULL, ",");
	}
	return i;
}

/**
 * @Name : zmq_buf_process
 * @argument :
 *	[IN] zmqmsgbuf_rx : Pointer to received zmq buffer
 *	[IN] zmqmsglen : Length of the zmq buffer
 * @return : 0 - success
 * @Description : Converts zmq message type to session_info or
 * respective rules info
 */

int
zmq_mbuf_process(struct zmqbuf *zmqmsgbuf_rx, int zmqmsglen)
{
	int ret;
	struct msgbuf buf = {0};
	struct zmqbuf zmqmsgbuf_tx;
	struct msgbuf *rbuf = &buf;
	struct session_info *sess = &rbuf->msg_union.sess_entry;

	memset(sess, 0, sizeof(*sess));

	rbuf->mtype = MSG_END;

	switch (zmqmsgbuf_rx->type) {
	case CREATE_SESSION: {
		struct create_session_t *csm =
			&zmqmsgbuf_rx->msg_union.create_session_msg;

		rbuf->mtype = MSG_SESS_CRE;
		rbuf->dp_id.id = DPN_ID;

		sess->ue_addr.iptype = IPTYPE_IPV4;
		sess->ue_addr.u.ipv4_addr = ntohl(csm->ue_ipv4);
		sess->ul_s1_info.enb_addr.u.ipv4_addr = 0;
		sess->ul_s1_info.sgw_addr.iptype = IPTYPE_IPV4;
		sess->ul_s1_info.sgw_addr.u.ipv4_addr =
			ntohl(csm->s1u_sgw_ipv4);
		sess->ul_s1_info.sgw_teid = csm->s1u_sgw_teid;
		sess->dl_s1_info.enb_addr.u.ipv4_addr = 0;
		sess->dl_s1_info.sgw_addr.iptype = IPTYPE_IPV4;
		sess->dl_s1_info.sgw_addr.u.ipv4_addr =
			ntohl(csm->s1u_sgw_ipv4);
		sess->dl_s1_info.enb_teid = 0;

		switch(app.spgw_cfg) {
		case SGWU:
			/* Configure PGWU IP addr */
			sess->ul_s1_info.s5s8_pgwu_addr.iptype = IPTYPE_IPV4;
			sess->ul_s1_info.s5s8_pgwu_addr.u.ipv4_addr = ntohl(csm->s5s8_ipv4);
			break;

		case PGWU:
			/* Configure SGWU IP addr */
			sess->dl_s1_info.s5s8_sgwu_addr.iptype = IPTYPE_IPV4;
			sess->dl_s1_info.s5s8_sgwu_addr.u.ipv4_addr = ntohl(csm->s5s8_ipv4);
			sess->dl_s1_info.enb_teid = csm->s1u_sgw_teid;

			/* Add default pcc rule entry for dl */
			sess->num_dl_pcc_rules = 1;
			sess->dl_pcc_rule_id[0] = 1;
			break;

		default:
			break;
		}

		sess->num_ul_pcc_rules = 1;
		sess->ul_pcc_rule_id[0] = 1;

		sess->sess_id = rte_bswap64(csm->session_id);
		sess->client_id = csm->client_id;
		zmqmsgbuf_tx.msg_union.dpn_response.client_id = csm->client_id;
		zmqmsgbuf_tx.msg_union.dpn_response.op_id = csm->op_id;
		zmqmsgbuf_tx.topic_id = csm->controller_topic;
		break;
	}

	case MODIFY_BEARER: {
		struct modify_bearer_t *mbm =
			&zmqmsgbuf_rx->msg_union.modify_bearer_msg;
		rbuf->mtype = MSG_SESS_MOD;
		rbuf->dp_id.id = DPN_ID;

		sess->ue_addr.u.ipv4_addr = 0;
		sess->ul_s1_info.enb_addr.iptype = IPTYPE_IPV4;
		sess->ul_s1_info.enb_addr.u.ipv4_addr =
			ntohl(mbm->s1u_enodeb_ipv4);
		sess->ul_s1_info.sgw_addr.u.ipv4_addr = 0;
		sess->ul_s1_info.sgw_teid = 0;
		sess->dl_s1_info.enb_addr.iptype = IPTYPE_IPV4;
		sess->dl_s1_info.enb_addr.u.ipv4_addr =
			ntohl(mbm->s1u_enodeb_ipv4);
		sess->dl_s1_info.sgw_addr.u.ipv4_addr = 0;
		sess->dl_s1_info.enb_teid = mbm->s1u_enodeb_teid;

		sess->num_ul_pcc_rules = 1;
		sess->ul_pcc_rule_id[0] = 1;
		sess->num_dl_pcc_rules = 1;
		sess->dl_pcc_rule_id[0] = 1;

		sess->sess_id = rte_bswap64(mbm->session_id);
		zmqmsgbuf_tx.msg_union.dpn_response.client_id = mbm->client_id;
		zmqmsgbuf_tx.msg_union.dpn_response.op_id = mbm->op_id;
		zmqmsgbuf_tx.topic_id = mbm->controller_topic;
		break;
	}

	case DELETE_SESSION: {
		struct delete_session_t *dsm =
			&zmqmsgbuf_rx->msg_union.delete_session_msg;
		rbuf->mtype = MSG_SESS_DEL;
		rbuf->dp_id.id = DPN_ID;

		sess->ue_addr.u.ipv4_addr = 0;
		sess->ul_s1_info.enb_addr.u.ipv4_addr = 0;
		sess->ul_s1_info.sgw_addr.u.ipv4_addr = 0;
		sess->ul_s1_info.sgw_teid = 0;
		sess->dl_s1_info.enb_addr.u.ipv4_addr = 0;
		sess->dl_s1_info.sgw_addr.u.ipv4_addr = 0;
		sess->dl_s1_info.enb_teid = 0;

		sess->sess_id = rte_bswap64(dsm->session_id);

		zmqmsgbuf_tx.msg_union.dpn_response.client_id = dsm->client_id;
		zmqmsgbuf_tx.msg_union.dpn_response.op_id = dsm->op_id;
		zmqmsgbuf_tx.topic_id = dsm->controller_topic;
		break;
	}

	case ADC_RULE: {
		/*
		 * @brief Coverts zmq message into ADC Rules info
		 * ref.Doc : message_sdn_dp.docx
		 * section : Table No.11 ADC Table
		 */
		static uint8_t rule_num = 1;
		uint8_t *buf = (uint8_t *)&(zmqmsgbuf_rx->msg_union.adc_rule_m);
		struct adc_rules *adc =
			&(rbuf->msg_union.adc_filter_entry);

		rbuf->mtype = MSG_ADC_TBL_ADD;
		rbuf->dp_id.id = DPN_ID;

		adc->sel_type = *(uint8_t *)(buf);

		adc->rule_id = rule_num++;

		ret = parse_adc_buf(adc->sel_type, (((char *)(buf) + 1)), adc);

		if (ret < 0){
			RTE_LOG_DP(ERR, DP, "Failed to filled adc structure\n");
		}
		break;
	}

	case PCC_RULE: {
		/**
		 * @brief Coverts zmq message into PCC Rules info
		 * ref.Doc : message_sdn_dp.docx
		 * section : Table No.12 PCC Table
		 */
		static uint8_t rule_id_t = 1;
		struct pcc_rules_t *pcc_t =
			&(zmqmsgbuf_rx->msg_union.pcc_rules_m);
		struct pcc_rules *pcc = &(rbuf->msg_union.pcc_entry);
		char sdf_idx[MAX_SDF_STR_LEN]={0};
		uint8_t offset = 0;

		rbuf->mtype = MSG_PCC_TBL_ADD;
		rbuf->dp_id.id = DPN_ID;

		pcc->rule_id = rule_id_t++;
		pcc->metering_method = pcc_t->metering_method;
		pcc->charging_mode = pcc_t->charging_mode;
		pcc->rating_group = rte_bswap16(pcc_t->rating_group);
		pcc->rule_status = pcc_t->rule_status;
		pcc->gate_status = pcc_t->gate_status;
		pcc->session_cont = pcc_t->session_cont;
		pcc->monitoring_key = rte_bswap32(pcc_t->monitoring_key);
		pcc->precedence = rte_bswap32(pcc_t->precedence);
		pcc->report_level = pcc_t->level_of_report;
		pcc->mute_notify = pcc_t->mute_status;
		pcc->drop_pkt_count = rte_bswap64(pcc_t->drop_pkt_count);
		pcc->qos.ul_mtr_profile_index = rte_bswap16(pcc_t->ul_mtr_profile_idx);
		pcc->qos.dl_mtr_profile_index = rte_bswap16(pcc_t->dl_mtr_profile_idx);
		pcc->redirect_info.info = pcc_t->redirect_info;
		pcc->adc_idx = rte_bswap32(pcc_t->adc_idx);

		/**
		 * ref.table no 12 PCC table info will help know the code
		 * len(SDF_FILTER_IDX), 0 : [0-4]
		 * SDF_FILTER_IDX, 5: [5 - len1]
		 * len(RULE_NAME), 5 + len1 :
		 * RULE_NAME, [5+len1] + 5
		 * len(SPONSOR_ID),  [5+len1] + [ 5 + len2]
		 * SPONSOR_ID) [5+len1] + [5+len2] + 5
		 */
		strncpy(sdf_idx, ((char *)(&(pcc_t->adc_idx))+5),
					*(uint8_t *)(&(pcc_t->adc_idx)+1));

		offset = *(uint8_t *)((char *)(&(pcc_t->adc_idx))+ 5 +
							*(uint8_t *)(&(pcc_t->adc_idx)+1));

		strncpy(pcc->rule_name, ((char *)(&(pcc_t->adc_idx)) + 6 +
					*(uint8_t *)(&(pcc_t->adc_idx)+1)), offset);

		strncpy(pcc->sponsor_id, ((char *)(&(pcc_t->adc_idx)) + 7 +
					offset + *(uint8_t *)(&(pcc_t->adc_idx)+1)), MAX_LEN);

		/**sdf indices are present only if adc is not present*/
		if(-1 == pcc->adc_idx){
			/* Convert array of sdf index value to integers */
			pcc->sdf_idx_cnt = get_sdf_indices(sdf_idx, pcc->sdf_idx);
		}
#ifdef PRINT_NEW_RULE_ENTRY
		print_pcc_val(pcc);
#endif	/* PRINT_NEW_RULE_ENTRY */
		break;
	}

	case METER_RULE: {
		/**
		 * @brief Coverts zmq message into Meter Rules info
		 * ref.Doc : message_sdn_dp.docx
		 * section : Table No.13 Meter Table
		 */
		struct mtr_entry_t *mtr_t =
			&(zmqmsgbuf_rx->msg_union.mtr_entry_m);
		struct mtr_entry *mtr = &(rbuf->msg_union.mtr_entry);

		rbuf->mtype = MSG_MTR_ADD;
		rbuf->dp_id.id = DPN_ID;

		mtr->mtr_profile_index =
			rte_bswap16(mtr_t->meter_profile_index);
		mtr->mtr_param.cir = rte_bswap64(mtr_t->cir);
		mtr->mtr_param.cbs = rte_bswap64(mtr_t->cbs);
		mtr->mtr_param.ebs = rte_bswap64(mtr_t->ebs);
		mtr->metering_method = mtr_t->metering_method;
#ifdef PRINT_NEW_RULE_ENTRY
		print_mtr_val(mtr);
#endif	/* PRINT_NEW_RULE_ENTRY */
		break;
	}

	case SDF_RULE: {
		/**
		 * @brief Coverts zmq message into SDF Rules info
		 * ref.Doc : Message_sdn.docx
		 * section : Table No.14 SDF Table
		 */
		static uint8_t rule_id_t = 1;
		struct sdf_entry_t *sdf_t =
			&(zmqmsgbuf_rx->msg_union.sdf_entry_m);
		struct pkt_filter *sdf = &(rbuf->msg_union.pkt_filter_entry);

		rbuf->mtype = MSG_SDF_ADD;
		rbuf->dp_id.id = DPN_ID;

		sdf->pcc_rule_id = rule_id_t++;
		sdf->sel_rule_type = sdf_t->rule_type;

		switch (sdf->sel_rule_type) {
		case RULE_STRING:
			strncpy(sdf->u.rule_str,
					(char *)(&(sdf_t->rule_type) + 5),
					MAX_LEN);
			break;

		case FIVE_TUPLE:
			/*TODO: rule should be in struct five_tuple_rule
			 * This field is currently not used
			 */
			break;

		default:
			RTE_LOG_DP(ERR, DP, "UNKNOWN Rule Type: %d\n",
				sdf_t->rule_type);
			break;
		}
#ifdef PRINT_NEW_RULE_ENTRY
			print_sdf_val(sdf);
#endif	/* PRINT_NEW_RULE_ENTRY */
			break;
	}

	case DDN_ACK: {
		rbuf->mtype = MSG_DDN_ACK;
		rbuf->dp_id.id = DPN_ID;

		printf("ACK received from FPC..\n");
		break;
	}

	default:
		RTE_LOG_DP(ERR, DP, "UNKNOWN Message Type: %d\n", zmqmsgbuf_rx->type);
		break;

	}

	ret = process_comm_msg((void *)rbuf);
	if (ret < 0)
		zmqmsgbuf_tx.msg_union.dpn_response.cause =
			GTPV2C_CAUSE_SYSTEM_FAILURE;
	else
		zmqmsgbuf_tx.msg_union.dpn_response.cause =
			GTPV2C_CAUSE_REQUEST_ACCEPTED;

	zmqmsgbuf_tx.type = DPN_RESPONSE;
	ret = do_zmq_mbuf_send(&zmqmsgbuf_tx);

	if (ret < 0)
		printf("do_zmq_mbuf_send failed for type: %"PRIu8"\n",
				zmqmsgbuf_rx->type);

	return ret;
}
#endif /* defined(DP_BUILD) && define(SDN_ODL_BUILD) */

#define IFACE_FILE "../config/interface.cfg"
#define SET_CONFIG_IP(ip, file, section, entry) \
	do {\
		entry = rte_cfgfile_get_entry(file, section, #ip);\
		if (entry == NULL)\
			rte_panic("%s not found in %s", #ip, IFACE_FILE);\
		if (inet_aton(entry, &ip) == 0)\
			rte_panic("Invalid %s in %s", #ip, IFACE_FILE);\
	} while (0)
#define SET_CONFIG_PORT(port, file, section, entry) \
	do {\
		entry = rte_cfgfile_get_entry(file, section, #port);\
		if (entry == NULL)\
			rte_panic("%s not found in %s", #port, IFACE_FILE);\
		if (sscanf(entry, "%"SCNu16, &port) != 1)\
			rte_panic("Invalid %s in %s", #port, IFACE_FILE);\
	} while (0)

static void read_interface_config(void)
{
	struct rte_cfgfile *file = rte_cfgfile_load(IFACE_FILE, 0);
	const char *file_entry;

	if (file == NULL)
		rte_exit(EXIT_FAILURE, "Cannot load configuration profile %s\n",
				IFACE_FILE);

	const char *zmq_proto = "tcp";
#ifdef CP_BUILD
	SET_CONFIG_IP(zmq_cp_ip, file, "0", file_entry);
	SET_CONFIG_PORT(zmq_cp_push_port, file, "0", file_entry);
	SET_CONFIG_PORT(zmq_cp_pull_port, file, "0", file_entry);

	snprintf(zmq_pull_ifconnect, sizeof(zmq_pull_ifconnect),
		"%s://%s:%u", zmq_proto, inet_ntoa(zmq_cp_ip), zmq_cp_pull_port);

	snprintf(zmq_push_ifconnect, sizeof(zmq_push_ifconnect),
		"%s://%s:%u", zmq_proto, inet_ntoa(zmq_cp_ip), zmq_cp_push_port);
#else /* DP_BUILD */
	SET_CONFIG_IP(zmq_dp_ip, file, "0", file_entry);
	SET_CONFIG_PORT(zmq_dp_pull_port, file, "0", file_entry);
	SET_CONFIG_PORT(zmq_dp_push_port, file, "0", file_entry);

	snprintf(zmq_pull_ifconnect, sizeof(zmq_pull_ifconnect),
		"%s://%s:%u", zmq_proto, inet_ntoa(zmq_dp_ip), zmq_dp_pull_port);

	snprintf(zmq_push_ifconnect, sizeof(zmq_push_ifconnect),
		"%s://%s:%u", zmq_proto, inet_ntoa(zmq_dp_ip), zmq_dp_push_port);
#endif /* CP_BUILD */

#if defined SDN_ODL_BUILD
	struct in_addr zmq_sub_ip;
	struct in_addr zmq_pub_ip;
	uint16_t zmq_sub_port;
	uint16_t zmq_pub_port;

	SET_CONFIG_IP(fpc_ip, file, "0", file_entry);
	SET_CONFIG_PORT(fpc_port, file, "0", file_entry);
	SET_CONFIG_PORT(fpc_topology_port, file, "0", file_entry);

	SET_CONFIG_IP(cp_nb_ip, file, "0", file_entry);
	SET_CONFIG_PORT(cp_nb_port, file, "0", file_entry);

	SET_CONFIG_IP(zmq_sub_ip, file, "0", file_entry);
	SET_CONFIG_PORT(zmq_sub_port, file, "0", file_entry);

	SET_CONFIG_IP(zmq_pub_ip, file, "0", file_entry);
	SET_CONFIG_PORT(zmq_pub_port, file, "0", file_entry);

	snprintf(zmq_sub_ifconnect, sizeof(zmq_sub_ifconnect),
		"%s://%s:%u", zmq_proto, inet_ntoa(zmq_sub_ip), zmq_sub_port);
	snprintf(zmq_pub_ifconnect, sizeof(zmq_pub_ifconnect),
		"%s://%s:%u", zmq_proto, inet_ntoa(zmq_pub_ip), zmq_pub_port);
#endif /* SDN_ODL_BUILD */

#if defined(CP_BUILD) && defined(SGX_BUILD)
	dealer_in_ip = rte_cfgfile_get_entry(file, "0",
			DEALERIN_IP);
	dealer_in_port = rte_cfgfile_get_entry(file, "0",
			DEALERIN_PORT);
	dealer_in_mrenclave = rte_cfgfile_get_entry(file, "0",
			DEALERIN_MRENCLAVE);
	dealer_in_mrsigner = rte_cfgfile_get_entry(file, "0",
			DEALERIN_MRSIGNER);
	dealer_in_isvsvn = rte_cfgfile_get_entry(file, "0",
			DEALERIN_ISVSVN);
	dp_cert_path = rte_cfgfile_get_entry(file, "0",
			DP_CERT_PATH);
	dp_pkey_path = rte_cfgfile_get_entry(file, "0",
			DP_PKEY_PATH);
#endif /* defined(CP_BUILD) && defined(SGX_BUILD) */
}

/**
 * @brief Initialize iface message passing
 *
 * This function is not thread safe and should only be called once by DP.
 */
void iface_module_constructor(void)
{
	/* Read and store ip and port for socket communication between cp and
	 * dp*/
	read_interface_config();
	read_interface_config();

#ifdef CP_BUILD
	char command[100];
	snprintf(command, sizeof(command),
			 "%s %s%s%s%u%s", "timeout 1 bash -c",
			 "'cat < /dev/null > /dev/tcp/",
			 inet_ntoa(zmq_cp_ip), "/", zmq_cp_push_port,
			 "' > /dev/null 2>&1");
	printf("IFACE: CP Initialization\n");
#if defined SDN_ODL_BUILD
	/* ASR- BUILD-PROBE::SDN_ODL_BUILD::Replace
	 * udp_init_cp_socket(), udp_send_socket() w/
	 * zmq interfaces
	 * */
//	register_comm_msg_cb(COMM_SOCKET,
//				udp_init_cp_socket,
//				udp_send_socket,
//				NULL,
//				NULL);
//	set_comm_type(COMM_SOCKET);
#else /* !SDN_ODL_BUILD */
	register_comm_msg_cb(COMM_ZMQ,
			zmq_init_socket,
			zmq_send_socket,
			zmq_recv_socket,
			zmq_destroy);
	set_comm_type(COMM_ZMQ);
#endif /* SDN_ODL_BUILD */
	if((system(command)) > 0) {
		rte_exit(EXIT_FAILURE, "ZMQ Streamer not running!!!"
				"\n\tStart DP Process && ZMQ Streamer service...\n");
	} else {
		printf("ZMQ Streamer >> DP running::"
				"\n\tCUPS Channel opened....\n");
	}
#elif defined(DP_BUILD) && !defined(SIMU_CP)
	char command[100];
	snprintf(command, sizeof(command),
			"%s %s%s%s%u%s", "timeout 1 bash -c",
			"'cat < /dev/null > /dev/tcp/",
			inet_ntoa(zmq_dp_ip), "/", zmq_dp_push_port,
			"' > /dev/null 2>&1");
	RTE_LOG_DP(NOTICE, DP, "IFACE: DP Initialization\n");
	register_comm_msg_cb(COMM_ZMQ,
			zmq_init_socket,
			zmq_send_socket,
			zmq_recv_socket,
			zmq_destroy);
	set_comm_type(COMM_ZMQ);
#if defined SDN_ODL_BUILD
	/* Code Rel. Jan 30, 2017
	* Note: PCC, ADC, Session table initial creation on the DP sent over UDP by CP
	* Needs to be from SDN controller as code & data models evolve
	* For Jan 30, 2017 release, for flow updates over SDN controller
	* register ZMQSUB socket after dp_session_table_create.
	*/
	register_comm_msg_cb(COMM_ZMQ,
			zmq_init_socket,
			zmq_send_socket,
			zmq_recv_socket,
			zmq_destroy);
#endif /* SDN_ODL_BUILD */
	if((system(command)) > 0) {
		rte_exit(EXIT_FAILURE, "DP ZMQ Streamer trigger Failed!!!"
				"\n\tCheck DP ZMQ Streamer trigger...\n");
	} else {
		printf("ZMQ Streamer >> CP running::"
				"\n\tCUPS response channel opened....\n");
	}
#endif /* CP_BUILD */
}

void sig_handler(int signo)
{
	if (signo == SIGINT) {
#ifdef SDN_ODL_BUILD
#ifdef CP_BUILD
		close_nb();
#else /* DP_BUILD */
		zmq_status_goodbye();
#endif /* CP_BUILD */
#endif /* SDN_ODL_BUILD */

#ifdef CP_BUILD
#ifdef SYNC_STATS
		retrive_stats_entry();
		close_stats();
#endif /* SYNC_STATS */
#if defined(SGX_BUILD) && !defined(SDN_ODL_BUILD)
		close_sctf();
#endif /* defined(SGX_BUILD) && !defined(SDN_ODL_BUILD) */
#else /* DP_BUILD */
		close(netlink_sock);
#endif /* CP_BUILD */

#ifdef PERF_ANALYSIS
		print_perf_statistics();
#endif /* PERF_ANALYSIS */
		rte_exit(EXIT_SUCCESS, "received SIGINT\n");
	}
}

