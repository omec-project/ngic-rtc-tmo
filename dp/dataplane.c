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

#ifdef PCAP_GEN
#include <pcap.h>
#endif /* PCAP_GEN */

#include <rte_cycles.h>
#include <rte_ip.h>
#include <rte_ip_frag.h>
#include <rte_errno.h>

#include "main.h"
#include "ngic_rtc_framework.h"
#include "gtpu.h"
#include "ipv4.h"
#include "ether.h"
#include "util.h"
#include "meter.h"
#include "acl_dp.h"
#include <sponsdn.h>
#include <stdbool.h>

extern struct rte_ring *cdr_ring;

struct rte_hash *rte_uplink_hash;
struct rte_hash *rte_downlink_hash;
struct rte_hash *rte_adc_hash;
struct rte_hash *rte_adc_ue_hash;
struct rte_hash *rte_pcc_hash;
struct rte_hash *rte_sess_hash;
struct rte_hash *rte_ue_hash;
struct rte_hash *rte_sdf_pcc_hash;
struct rte_hash *rte_adc_pcc_hash;
struct rte_hash *rte_sess_cli_hash;

#ifdef PCAP_GEN
pcap_dumper_t *pcap_dumper_east;
pcap_dumper_t *pcap_dumper_west;
#endif /* PCAP_GEN */

void
gtpu_decap(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask)
{
	uint32_t i;
	int ret = 0;
	struct ipv4_hdr *ipv4_hdr;
	struct udp_hdr *udp_hdr;
	struct gtpu_hdr *gtpu_hdr;
	struct epc_meta_data *meta_data;

	for (i = 0; i < n; i++) {
		/* Skip previously marked packets to drop */
		if (!ISSET_BIT(*pkts_mask, i)) {
			--epc_app.ul_params[S1U_PORT_ID].pkts_in;
			//wr_pkts++;
			continue;
		}

		/* reject if not with s1u ip */
		ipv4_hdr = get_mtoip(pkts[i]);
		uint32_t ip = 0; //GCC_Security flag

		switch(app.spgw_cfg) {
			case SPGWU:
				ip = app.s1u_ip;
				break;

			case PGWU:
				ip = app.s5s8_pgwu_ip;
				break;

			default:
				break;
		}

		if (ipv4_hdr->dst_addr != ip) {
			/* ASR-Probe:: Log(bad pkts[i]->data_len || pkt_len) */
			epc_app.ul_params[S1U_PORT_ID].bad_pkt_idx = i;
			epc_app.ul_params[S1U_PORT_ID].bad_data_len = pkts[i]->data_len;
			epc_app.ul_params[S1U_PORT_ID].bad_data_len = pkts[i]->pkt_len;
			RESET_BIT(*pkts_mask, i);
			continue;
		}

		/* reject un-tunneled packet */
		udp_hdr = get_mtoudp(pkts[i]);
		if (ntohs(udp_hdr->dst_port) != UDP_PORT_GTPU) {
			/* ASR-Probe:: Log(bad pkts[i]->data_len || pkt_len) */
			epc_app.ul_params[S1U_PORT_ID].bad_pkt_idx = i;
			epc_app.ul_params[S1U_PORT_ID].bad_data_len = pkts[i]->data_len;
			epc_app.ul_params[S1U_PORT_ID].bad_data_len = pkts[i]->pkt_len;
			RESET_BIT(*pkts_mask, i);
			continue;
		}

		gtpu_hdr = get_mtogtpu(pkts[i]);
		if (gtpu_hdr->teid == 0 || gtpu_hdr->msgtype != GTP_GPDU) {
			--epc_app.ul_params[S1U_PORT_ID].pkts_in;
#ifdef EXSTATS
			++epc_app.ul_params[S1U_PORT_ID].pkts_echo;
#endif /* EXSTATS */
			/* ASR-Probe:: Log(bad pkts[i]->data_len || pkt_len) */
			epc_app.ul_params[S1U_PORT_ID].bad_pkt_idx = i;
			epc_app.ul_params[S1U_PORT_ID].bad_data_len = pkts[i]->data_len;
			epc_app.ul_params[S1U_PORT_ID].bad_data_len = pkts[i]->pkt_len;
			RESET_BIT(*pkts_mask, i);
			continue;
		}

		meta_data =
		(struct epc_meta_data *)RTE_MBUF_METADATA_UINT8_PTR(pkts[i],
						META_DATA_OFFSET);
		meta_data->teid = ntohl(gtpu_hdr->teid);
		meta_data->enb_ipv4 = ntohl(ipv4_hdr->src_addr);
		RTE_LOG_DP(DEBUG, DP, "Received tunneled packet with teid 0x%X\n",
				ntohl(meta_data->teid));
		RTE_LOG_DP(DEBUG, DP, "From Ue IP " IPV4_ADDR "\n",
				IPV4_ADDR_FORMAT(GTPU_INNER_SRC_IP(pkts[i])));

		/* ASR-Probe:: Log(ref pkts[i]->data_len) */
		epc_app.ul_params[S1U_PORT_ID].ref_len = pkts[i]->data_len;
		ret = DECAP_GTPU_HDR(pkts[i]);

		if (ret < 0){
			RESET_BIT(*pkts_mask, i);
			--epc_app.ul_params[S1U_PORT_ID].pkts_in;
		}
	}
}

void
gtpu_encap(struct dp_session_info **sess_info, struct rte_mbuf **pkts,
		uint32_t n, uint64_t *pkts_mask, uint64_t *pkts_queue_mask)
{
	uint32_t i;
	struct dp_session_info *si;
	struct rte_mbuf *m;
	uint16_t len;
	uint32_t src_addr;
	uint32_t dst_addr;

	for (i = 0; i < n; i++) {
		si = sess_info[i];
		m = pkts[i];

		/* Skip previously marked packets to drop */
		if (!ISSET_BIT(*pkts_mask, i)) {
			--epc_app.dl_params[SGI_PORT_ID].pkts_in;
			continue;
		}

		if (si == NULL) {
			--epc_app.dl_params[SGI_PORT_ID].pkts_in;
			RESET_BIT(*pkts_mask, i);
			continue;
		}

/** Check downlink bearer is ACTIVE or IDLE */
#ifdef DP_DDN
		if (si->sess_state != CONNECTED) {
			--epc_app.dl_params[SGI_PORT_ID].pkts_in;
			++epc_app.dl_params[SGI_PORT_ID].ddn;
			RESET_BIT(*pkts_mask, i);
			SET_BIT(*pkts_queue_mask, i);
			continue;
		}
#endif /* DP_DDN */

		if (!si->dl_s1_info.enb_teid) {
			--epc_app.dl_params[SGI_PORT_ID].pkts_in;
			/* ASR-Probe:: Log(bad pkts[i]->data_len || pkt_len) */
			epc_app.dl_params[SGI_PORT_ID].bad_pkt_idx = i;
			epc_app.dl_params[SGI_PORT_ID].bad_data_len = pkts[i]->data_len;
			epc_app.dl_params[SGI_PORT_ID].bad_data_len = pkts[i]->pkt_len;
			RESET_BIT(*pkts_mask, i);
			SET_BIT(*pkts_queue_mask, i);
			continue;
		}

		/* ASR-Probe:: Log(ref pkts[i]->data_len) */
		epc_app.dl_params[SGI_PORT_ID].ref_len = pkts[i]->data_len;
		if (ENCAP_GTPU_HDR(m, si->dl_s1_info.enb_teid) < 0) {
			--epc_app.dl_params[SGI_PORT_ID].pkts_in;
			RESET_BIT(*pkts_mask, i);
			continue;
		}

		len = rte_pktmbuf_data_len(m);
		len = len - ETH_HDR_SIZE;

		if (app.spgw_cfg == PGWU)
			dst_addr = si->dl_s1_info.s5s8_sgwu_addr.u.ipv4_addr;
		else
			dst_addr = si->dl_s1_info.enb_addr.u.ipv4_addr;

		/* construct iphdr */
		switch(app.spgw_cfg) {
			case SPGWU:
				src_addr = app.s1u_ip;
				break;

			case PGWU:
				src_addr = app.s5s8_pgwu_ip;
				break;

			default:
				break;
		}

		construct_ipv4_hdr(m, len, IP_PROTO_UDP, ntohl(src_addr),
					dst_addr);

		len = len - IPv4_HDR_SIZE;
		/* construct udphdr */
		construct_udp_hdr(m, len, UDP_PORT_GTPU, UDP_PORT_GTPU);
	}
}

void
ul_sess_info_get(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, struct dp_sdf_per_bearer_info **sess_info)
{
	uint32_t j;
	struct ul_bm_key key[MAX_BURST_SZ];
	void *key_ptr[MAX_BURST_SZ];
	struct epc_meta_data *meta_data;
	uint64_t hit_mask = 0;

	/* TODO: uplink hash is created based on values pushed from CP.
	 * CP always sends rule-id = 1 while creation.
	 * After new implementation of ADC-PCC relation lookup will fail.
	 * Hard coding rule id to 1. (temporary fix)
	 */
	for (j = 0; j < n; j++) {
		key[j].rid =1;
		key[j].s1u_sgw_teid = 0;
		key_ptr[j] = &key[j];

		switch (app.spgw_cfg) {
			case SPGWU: {
				meta_data =
					(struct epc_meta_data *)RTE_MBUF_METADATA_UINT8_PTR(pkts[j],
					META_DATA_OFFSET);
				key[j].s1u_sgw_teid = meta_data->teid;
				break;
			}

			case SGWU: {
				struct ipv4_hdr *ipv4_hdr = NULL;
				struct udp_hdr *udp_hdr = NULL;
				struct gtpu_hdr *gtpu_hdr = NULL;

				/* reject if not with s1u ip */
				ipv4_hdr = get_mtoip(pkts[j]);
				if (ipv4_hdr->dst_addr != app.s1u_ip) {
					RESET_BIT(*pkts_mask, j);
					continue;
				}

				/* reject un-tunneled packet */
				udp_hdr = get_mtoudp(pkts[j]);
				if (ntohs(udp_hdr->dst_port) != UDP_PORT_GTPU) {
					RESET_BIT(*pkts_mask, j);
					continue;
				}

				gtpu_hdr = get_mtogtpu(pkts[j]);
				if (gtpu_hdr->teid == 0 || gtpu_hdr->msgtype != GTP_GPDU) {
					RESET_BIT(*pkts_mask, j);
					continue;
				}

				key[j].s1u_sgw_teid = ntohl(gtpu_hdr->teid);
				break;
			}

			default:
				break;
		}
	}

	if ((iface_lookup_uplink_bulk_data((const void **)&key_ptr[0], n,
			&hit_mask, (void **)sess_info)) < 0) {
		hit_mask = 0;
	}

	if (app.spgw_cfg != PGWU) {
		for (j = 0; j < n; j++) {
			if (!ISSET_BIT(hit_mask, j)) {
				RESET_BIT(*pkts_mask, j);
				RTE_LOG_DP(DEBUG, DP, "SDF BEAR LKUP:FAIL!! UL_KEY "
					"teid:%u, rid:%u\n",
					key[j].s1u_sgw_teid, key[j].rid);
				sess_info[j] = NULL;
			}
		}
	}
}

void
adc_ue_info_get(struct rte_mbuf **pkts, uint32_t n, uint32_t *res,
		void **adc_ue_info, uint32_t flow)
{
	uint32_t j;
	struct dl_bm_key key[MAX_BURST_SZ];
	struct ipv4_hdr *ipv4_hdr;
	void *key_ptr[MAX_BURST_SZ];
	uint64_t hit_mask = 0;

	for (j = 0; j < n; j++) {
		ipv4_hdr = get_mtoip(pkts[j]);
		key[j].rid = res[j];
		if (flow == UL_FLOW)
			key[j].ue_ipv4 = ntohl(ipv4_hdr->src_addr);
		else
			key[j].ue_ipv4 = ntohl(ipv4_hdr->dst_addr);

		key_ptr[j] = &key[j];
	}

	if ((rte_hash_lookup_bulk_data(rte_adc_ue_hash,
		(const void **)&key_ptr[0], n, &hit_mask, adc_ue_info)) < 0)
		RTE_LOG_DP(ERR, DP, "ADC UE Bulk LKUP:FAIL!!\n");

	for (j = 0; j < n; j++)
		if (!ISSET_BIT(hit_mask, j))
			adc_ue_info[j] = NULL;
}

void
dl_sess_info_get(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, struct dp_sdf_per_bearer_info **sess_info,
		struct dp_session_info **si)
{
	uint32_t j;
	struct dl_bm_key key[MAX_BURST_SZ];
	void *key_ptr[MAX_BURST_SZ];
	struct ipv4_hdr *ipv4_hdr = NULL;
	uint32_t dst_addr = 0;
	uint64_t hit_mask = 0;

	/* TODO: downlink hash is created based on values pushed from CP.
	 * CP always sends rule-id = 1 while creation.
	 * After new implementation of ADC-PCC relation lookup will fail.
	 * Hard coding rule id to 1. (temporary fix)
	 */
	for (j = 0; j < n; j++) {
		/* Skip previously marked packets to drop */
		if (!ISSET_BIT(*pkts_mask, j)) {
			continue;
		}

		key[j].rid =1;
		key[j].ue_ipv4 = 0;
		key_ptr[j] = &key[j];

		switch (app.spgw_cfg) {
			case SGWU: {
				struct udp_hdr *udp_hdr = NULL;
				struct gtpu_hdr *gtpu_hdr = NULL;

				/* reject if not with s1u ip */
				ipv4_hdr = get_mtoip(pkts[j]);
				if (ipv4_hdr->dst_addr != app.s5s8_sgwu_ip) {
					RESET_BIT(*pkts_mask, j);
					continue;
				}

				/* reject un-tunneled packet */
				udp_hdr = get_mtoudp(pkts[j]);
				if (ntohs(udp_hdr->dst_port) != UDP_PORT_GTPU) {
					RESET_BIT(*pkts_mask, j);
					continue;
				}

				gtpu_hdr = get_mtogtpu(pkts[j]);
				if (gtpu_hdr->teid == 0 || gtpu_hdr->msgtype != GTP_GPDU) {
					RESET_BIT(*pkts_mask, j);
					continue;
				}

				uint8_t *pkt_ptr = (uint8_t *) gtpu_hdr;
				pkt_ptr += GPDU_HDR_SIZE_DYNAMIC(*pkt_ptr);
				ipv4_hdr = (struct ipv4_hdr *)pkt_ptr;
				dst_addr = ntohl(ipv4_hdr->dst_addr);
				break;
			}

			case PGWU: {
				/* Values are same as SPGWU.*/
			}

			case SPGWU: {
				ipv4_hdr = get_mtoip(pkts[j]);
				dst_addr = ntohl(ipv4_hdr->dst_addr);
				break;
			}

			default:
				break;
		}


		key[j].ue_ipv4 = dst_addr;
		struct epc_meta_data *meta_data =
		(struct epc_meta_data *)RTE_MBUF_METADATA_UINT8_PTR(pkts[j],
							META_DATA_OFFSET);
		meta_data->key.ue_ipv4 = key[j].ue_ipv4;
		meta_data->key.rid = key[j].rid;
		RTE_LOG_DP(DEBUG, DP, "BEAR_SESS LKUP:DL_KEY ue_addr:"IPV4_ADDR
				", rid:%u\n",
				IPV4_ADDR_HOST_FORMAT(meta_data->key.ue_ipv4),
				meta_data->key.rid);
		key_ptr[j] = &key[j];
	}

	if ((iface_lookup_downlink_bulk_data((const void **)&key_ptr[0], n,
			&hit_mask, (void **)sess_info)) < 0)
		RTE_LOG_DP(ERR, DP, "SDF BEAR Bulk LKUP:FAIL!!\n");

	for (j = 0; j < n; j++) {
		if (!ISSET_BIT(hit_mask, j)) {
			RESET_BIT(*pkts_mask, j);
			RTE_LOG_DP(DEBUG, DP, "SDF BEAR LKUP FAIL!! DL_KEY "
					"ue_addr:"IPV4_ADDR", rid:%u\n",
				IPV4_ADDR_HOST_FORMAT((key[j]).ue_ipv4),
				key[j].rid);
			sess_info[j] = NULL;
			si[j] = NULL;
		} else {
			si[j] = sess_info[j]->bear_sess_info;
		}
	}
}

void
get_pcc_info(void **sess_info, uint32_t n, void **pcc_info)
{
	uint32_t i;
	struct dp_sdf_per_bearer_info *psdf;

	for (i = 0; i < n; i++) {
		psdf = (struct dp_sdf_per_bearer_info *)sess_info[i];
		if (psdf == NULL) {
			pcc_info[i] = NULL;
			continue;
		}
		pcc_info[i] = &psdf->pcc_info;
	}
}

void
pcc_gating(struct pcc_id_precedence *sdf_info, struct pcc_id_precedence *adc_info,
	uint32_t n, uint64_t *pkts_mask, uint32_t *pcc_id)
{
	uint32_t i;

	for (i = 0; i < n; i++) {
		/* Skip previously marked packets to drop */
		if (!ISSET_BIT(*pkts_mask, i)) {
			continue;
		}

		/* Lowest value, highest precedance. ref: 29.212 */
		if (sdf_info[i].precedence < adc_info[i].precedence) {
			if (sdf_info[i].gate_status == CLOSE) {
				RESET_BIT(*pkts_mask, i);
			}
			pcc_id[i] = sdf_info[i].pcc_id;
		} else {
			if (adc_info[i].gate_status == CLOSE) {
				RESET_BIT(*pkts_mask, i);
			}
			pcc_id[i] = adc_info[i].pcc_id;
		}
	}
}

/**
 * To map rating group value to index
 * @param rg_val
 * rating group.
 * @param  rg_idx_map
 * index map structure.
 *
 * @return
 * rating group index
 */
static uint8_t
get_rg_idx(uint32_t rg_val, struct rating_group_index_map *rg_idx_map)
{
	uint32_t i;
	if (rg_val == 0)
		return MAX_RATING_GRP;
	for (i = 0; i < MAX_RATING_GRP; i++)
		if (rg_idx_map[i].rg_val == rg_val)
			return i;
	return MAX_RATING_GRP;
}

void
get_rating_grp(void **adc_ue_info, void **sdf_info,
		uint32_t **rgrp, uint32_t n)
{
	uint32_t i;
	struct dp_adc_ue_info *adc_ue;
	struct dp_sdf_per_bearer_info *psdf;
	struct dp_pcc_rules *pcc;

	for (i = 0; i < n; i++) {
			adc_ue = adc_ue_info[i];
			if (adc_ue && adc_ue->adc_info.rating_group) {
					rgrp[i] = &adc_ue->adc_info.rating_group;
					continue;
			}
			psdf = (struct dp_sdf_per_bearer_info *)sdf_info[i];
			if (psdf == NULL)
					continue;
			pcc = &psdf->pcc_info;
			if (pcc && pcc->rating_group)
					rgrp[i] = &pcc->rating_group;
			else
					rgrp[i] = NULL;
	}
}

static void
update_cdr(struct ipcan_dp_bearer_cdr *cdr, struct rte_mbuf *pkt,
				uint32_t flow, enum pkt_action_t action)
{
	uint32_t charged_len;
	struct ipv4_hdr *ip_h = NULL;

	ip_h = rte_pktmbuf_mtod_offset(pkt, struct ipv4_hdr *,
			sizeof(struct ether_hdr));

	charged_len =
			RTE_MIN(rte_pktmbuf_pkt_len(pkt) -
					sizeof(struct ether_hdr),
					ntohs(ip_h->total_length));

	if (action == CHARGED) {
		if (flow == UL_FLOW) {
			cdr->data_vol.ul_cdr.bytes += charged_len;
			/* VCCCCB-34 Statistics - add current number of active sessions and RXbytes,
			 * TXbytes */
			epc_app.ul_params[S1U_PORT_ID].tot_ul_bytes += charged_len;
			cdr->data_vol.ul_cdr.pkt_count++;
		} else {
			cdr->data_vol.dl_cdr.bytes += charged_len;
			/* VCCCCB-34 Statistics - add current number of active sessions and RXbytes,
			 * TXbytes */
			epc_app.dl_params[SGI_PORT_ID].tot_dl_bytes += charged_len;
			cdr->data_vol.dl_cdr.pkt_count++;
		}	/* if (flow == UL_FLOW) */
	} else {
		if (flow == UL_FLOW) {
			cdr->data_vol.ul_drop.bytes += charged_len;
			cdr->data_vol.ul_drop.pkt_count++;
		} else {
			cdr->data_vol.dl_drop.bytes += charged_len;
			cdr->data_vol.dl_drop.pkt_count++;
		}	/* if (flow == UL_FLOW) */
	}
}

void
update_adc_cdr(void **adc_ue_info,
		struct rte_mbuf **pkts, uint32_t n,
		uint64_t *adc_pkts_mask, uint64_t *pkts_mask,
		uint32_t flow)
{
	uint32_t i;
	struct dp_adc_ue_info *adc_ue;

	for (i = 0; i < n; i++) {
		adc_ue = (struct dp_adc_ue_info *)adc_ue_info[i];
		if (adc_ue == NULL)
			continue;

		/* record cdr counts if ADC rule is open and pkt is not dropped
		 * due to pcc rule of metering.*/
		if ((ISSET_BIT(*adc_pkts_mask, i))
				&& (ISSET_BIT(*pkts_mask, i)))
			update_cdr(&adc_ue->adc_cdr, pkts[i], flow, CHARGED);

		/* record drop counts if ADC rule is hit but gate is closed*/
		if (!(ISSET_BIT(*adc_pkts_mask, i)))
			update_cdr(&adc_ue->adc_cdr, pkts[i], flow, DROPPED);
	}	/* for (i = 0; i < n; i++)*/
}

void
update_sdf_cdr(void **adc_ue_info,
		struct dp_sdf_per_bearer_info **sdf_bear_info,
		struct rte_mbuf **pkts, uint32_t n,
		uint64_t *adc_pkts_mask, uint64_t *pkts_mask,
		uint32_t flow)
{
	uint32_t i;
	struct dp_sdf_per_bearer_info *psdf;
	struct dp_adc_ue_info *adc_ue;

	for (i = 0; i < n; i++) {
		psdf = sdf_bear_info[i];
		if (psdf == NULL)
			continue;
		/* if ADC rule is hit, but gate is closed
		 * then don't update PCC cdr. */
		adc_ue = (struct dp_adc_ue_info *)adc_ue_info[i];
		if ((adc_ue != NULL)
				&& !ISSET_BIT(*adc_pkts_mask, i))
			continue;

		/* if ADC CDR is updated, then no need to
		 * update PCC cdr */
		if (ISSET_BIT(*adc_pkts_mask, i))
			continue;

		if (ISSET_BIT(*pkts_mask, i))
			update_cdr(&psdf->sdf_cdr, pkts[i], flow, CHARGED);
		else
			update_cdr(&psdf->sdf_cdr, pkts[i], flow, DROPPED);
	}	/* for (i = 0; i < n; i++)*/
}

void
update_pcc_cdr(struct dp_sdf_per_bearer_info **sdf_bear_info,
		struct rte_mbuf **pkts, uint32_t n, uint64_t *pkts_mask,
		uint32_t *pcc_rule, uint32_t flow)
{
	uint32_t i;
	uint64_t bytes;
	struct dp_sdf_per_bearer_info *psdf = NULL;

	for (i = 0; i < n; i++) {
		/* Skip previously marked packets to drop */
		if (!ISSET_BIT(*pkts_mask, i)) {
			continue;
		}

		psdf = sdf_bear_info[i];
		if (NULL == psdf)
			continue;

		if (psdf->sdf_cdr.charging_rule_id == 0) {
			psdf->sdf_cdr.charging_rule_id = pcc_rule[i];
		}

		if (!psdf->bear_sess_info->ipcan_dp_bearer_cdr.data_vol.ul_cdr.bytes &&
				!psdf->bear_sess_info->ipcan_dp_bearer_cdr.data_vol.dl_cdr.bytes)
		{
			time((time_t *)&psdf->bear_sess_info->ipcan_dp_bearer_cdr.time_of_first_use);
		}

		if (ISSET_BIT(*pkts_mask, i))
			update_cdr(&psdf->bear_sess_info->ipcan_dp_bearer_cdr, pkts[i], flow, CHARGED);
		else
			update_cdr(&psdf->bear_sess_info->ipcan_dp_bearer_cdr, pkts[i], flow, DROPPED);

		bytes = ((psdf->bear_sess_info->ipcan_dp_bearer_cdr.data_vol.ul_cdr.bytes -
				psdf->bear_sess_info->ipcan_dp_bearer_cdr.data_vol.ul_cdr_last.bytes) +
				(psdf->bear_sess_info->ipcan_dp_bearer_cdr.data_vol.dl_cdr.bytes -
				 psdf->bear_sess_info->ipcan_dp_bearer_cdr.data_vol.dl_cdr_last.bytes));

		if ((bytes >= psdf->bear_sess_info->ipcan_dp_bearer_cdr.vol_trshld) &&
			(psdf->bear_sess_info->ipcan_dp_bearer_cdr.vol_trshld)) {
			update_vol_on_rec_close(psdf->bear_sess_info, CDR_REC_VOL);

			int ret = rte_ring_enqueue(cdr_ring, (void *)psdf->bear_sess_info->sess_id);
			if (ret == -ENOBUFS) {
				RTE_LOG_DP(DEBUG, DP, "update_pcc_cdr:Enqueu failed in cdr_ring\n");
			}
		}
	}
}

void
update_bear_cdr(struct dp_sdf_per_bearer_info **sdf_bear_info,
		struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, uint32_t flow)
{
	uint32_t i;
	struct dp_session_info *si;
	struct dp_sdf_per_bearer_info *psdf;

	for (i = 0; i < n; i++) {
		psdf = sdf_bear_info[i];
		if (psdf == NULL)
			continue;

		si = psdf->bear_sess_info;
		if (si == NULL)
			continue;

		if (ISSET_BIT(*pkts_mask, i))
			update_cdr(&si->ipcan_dp_bearer_cdr, pkts[i],
					flow, CHARGED);
		else
			update_cdr(&si->ipcan_dp_bearer_cdr, pkts[i],
					flow, DROPPED);
	}	/* for (i = 0; i < n; i++)*/
}

void
update_rating_grp_cdr(void **sess_info, uint32_t **rgrp,
		struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, uint32_t flow)
{
	uint32_t i;
	struct dp_session_info *si;
	struct dp_sdf_per_bearer_info *psdf;
	uint8_t rg_idx;

	for (i = 0; i < n; i++) {
		psdf = (struct dp_sdf_per_bearer_info *)sess_info[i];
		if (psdf == NULL)
			continue;

		si = psdf->bear_sess_info;
		if (si == NULL)
			continue;

		if (rgrp[i] == NULL)
			continue;

		rg_idx = get_rg_idx(*rgrp[i], si->ue_info_ptr->rg_idx_map);
		if (rg_idx >= MAX_RATING_GRP)
			continue;

		if (ISSET_BIT(*pkts_mask, i))
			update_cdr(&si->ue_info_ptr->rating_grp[rg_idx],
					pkts[i], flow, CHARGED);
		else
			update_cdr(&si->ue_info_ptr->rating_grp[rg_idx],
					pkts[i], flow, DROPPED);
	}	/* for (i = 0; i < n; i++)*/
}

void
adc_hash_lookup(struct rte_mbuf **pkts, uint32_t n, uint32_t *rid, uint8_t flow)
{
	uint32_t j;
	uint32_t key32[MAX_BURST_SZ];
	uint32_t *key_ptr[MAX_BURST_SZ];
	uint64_t hit_mask = 0;
	struct msg_adc *data[MAX_BURST_SZ];
	struct ipv4_hdr *ipv4_hdr;

	for (j = 0; j < n; j++) {
		ipv4_hdr = get_mtoip(pkts[j]);
		key32[j] = (flow == UL_FLOW) ? ipv4_hdr->dst_addr :
				ipv4_hdr->src_addr;
		key_ptr[j] = &key32[j];
	}

	if (iface_lookup_adc_bulk_data((const void **)key_ptr,
			n, &hit_mask, (void **)data) < 0)
		hit_mask = 0;

	for (j = 0; j < n; j++) {
		if (ISSET_BIT(hit_mask, j)) {
			RTE_LOG_DP(DEBUG, DP, "ADC_DNS_LKUP: rid[%d]:%u\n", j,
					data[j]->rule_id);
			rid[j] = data[j]->rule_id;
		} else {
			rid[j] = 0;
		}
	}
}

static inline bool is_dns_pkt(struct rte_mbuf *m, uint32_t rid)
{
	struct ipv4_hdr *ip_hdr;
	struct ether_hdr *eth_hdr;

	eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
	ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);

	if (rte_ipv4_frag_pkt_is_fragmented(ip_hdr))
		return false;

	if (rid != DNS_RULE_ID)
		return false;

	return true;
}

void
update_dns_meta(struct rte_mbuf **pkts, uint32_t n, uint32_t *rid)
{
	uint32_t i;
	struct epc_meta_data *meta_data;
	for (i = 0; i < n; i++) {

		meta_data =
			(struct epc_meta_data *)RTE_MBUF_METADATA_UINT8_PTR(
					pkts[i], META_DATA_OFFSET);

		if (likely(!is_dns_pkt(pkts[i], rid[i]))) {
			meta_data->dns = 0;
			continue;
		}

		meta_data->dns = 1;
	}
}

#ifdef HYPERSCAN_DPI
void
clone_dns_pkts(struct rte_mbuf **pkts, uint32_t n, uint64_t pkts_mask)
{
	uint32_t i;
	struct epc_meta_data *meta_data;

	for (i = 0; i < n; i++) {
		if (ISSET_BIT(pkts_mask, i)) {
			meta_data =
			(struct epc_meta_data *)RTE_MBUF_METADATA_UINT8_PTR(
						pkts[i], META_DATA_OFFSET);
			if (meta_data->dns) {
				push_dns_ring(pkts[i]);
				/* ASR- TODO HYPERSCAN clone_dns_pkt to be tested */
				++(epc_app.dl_params[SGI_PORT_ID].num_dns_packets);
			}
		}
	}
}
#endif /* HYPERSCAN_DPI */

void
update_nexthop_info(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, uint8_t portid,
		struct dp_sdf_per_bearer_info **sess_info)
{
	uint32_t i;
	for (i = 0; i < n; i++) {
		if (ISSET_BIT(*pkts_mask, i)) {
			if (construct_ether_hdr(pkts[i], portid, &sess_info[i]) < 0) {
				RESET_BIT(*pkts_mask, i);
				continue;
			}

#ifdef FRAG
			if (RTE_ETH_IS_IPV4_HDR(pkts[i]->packet_type) &&
			    unlikely(SGI_ETHER_MTU < pkts[i]->pkt_len)) {

				volatile int32_t res;
				struct ether_hdr *ethh, ethh_copy;
				struct ipv4_hdr *iph;
				register uint32_t j;
				struct rte_mbuf *m;
				struct rte_mbuf *frag_tbl[EPC_DEFAULT_BURST_SZ];
				unsigned char *orig_ip_payload;
				uint16_t orig_data_offset;

				if (portid == SGI_PORT_ID)
					rte_panic("Packets coming from S1U_PORT_ID can't"
						  "have > MTU packet sizes!\n");
				/* retrieve Ethernet header */
				ethh = rte_pktmbuf_mtod(pkts[i], struct ether_hdr *);
				rte_memcpy(&ethh_copy, ethh, sizeof(struct ether_hdr));

				/* remove the Ethernet header and trailer from the input packet */
				rte_pktmbuf_adj(pkts[i], (uint16_t)sizeof(struct ether_hdr));

				/* retrieve orig ip payload for later re-use in ip frags */
				orig_ip_payload =
					rte_pktmbuf_mtod_offset(pkts[i], unsigned char *, sizeof(struct ipv4_hdr));
				orig_data_offset = 0;

				/* fragment the IPV4 packet */
				res = rte_ipv4_fragment_packet(pkts[i],
								&frag_tbl[0],
								EPC_DEFAULT_BURST_SZ,
								SGI_ETHER_MTU - ETHER_HDR_LEN,
								user_dlmp,
								sgi_indirect_pktmbuf_pool);

				if (unlikely(res < 0)) {
					RTE_LOG_DP(DEBUG, DP, "Failed to fragment packet: %p (errno: %d)!\n ",
						   pkts[i], res);
				} else {

					/* now copy the Ethernet header + IP payload to each frag */
					for (j = 0; j < res; j++) {
						m = frag_tbl[j];
						ethh = (struct ether_hdr *)
							rte_pktmbuf_prepend(m, (uint16_t)sizeof(struct ether_hdr));
						if (ethh == NULL)
							rte_panic("No headroom in mbuf.\n");
						/* remove chained mbufs (as they are not needed) */
						struct rte_mbuf *del_mbuf = m->next;
						while (del_mbuf != NULL) {
							rte_pktmbuf_free_seg(del_mbuf);
							del_mbuf = del_mbuf->next;
						}

						/* setting mbuf metadata */
						m->l2_len = sizeof(struct ether_hdr);
						m->data_len = m->pkt_len;
						m->nb_segs = 1;
						m->next = NULL;
						rte_memcpy(ethh, &ethh_copy, sizeof(struct ether_hdr));

						ethh = (struct ether_hdr *)rte_pktmbuf_mtod(m, struct ether_hdr *);
						iph = (struct ipv4_hdr *)(ethh + 1);

						/* copy ip payload */
						unsigned char *ip_payload = (unsigned char *)((unsigned char *)iph +
											      ((iph->version_ihl & IPV4_HDR_IHL_MASK) << 2));
						uint16_t ip_payload_len = m->pkt_len - sizeof(struct ether_hdr) -
							((iph->version_ihl & IPV4_HDR_IHL_MASK) << 2);

						/* if total frame size is less than minimum transmission unit, add IP padding */
						if (unlikely(ip_payload_len + sizeof(struct ipv4_hdr) +
							     sizeof(struct ether_hdr) + ETHER_CRC_LEN < ETHER_MIN_LEN)) {
							/* update ip->ihl first */
							iph->version_ihl &= 0xF0;
							iph->version_ihl |= (IPV4_HDR_IHL_MASK & (PADDED_IPV4_HDR_SIZE>>2));
							/* update ip->tot_len */
							iph->total_length = ntohs(ip_payload_len + PADDED_IPV4_HDR_SIZE);
							/* update l3_len */
							m->l3_len = PADDED_IPV4_HDR_SIZE;
							/* update data_len & pkt_len */
							m->data_len = m->pkt_len = m->pkt_len + IP_PADDING_LEN;
							/* ip_payload is currently the place you would add 0s */
							memset(ip_payload, 0, IP_PADDING_LEN);

							/* re-set ip_payload to the right `offset` (location) now */
							ip_payload += IP_PADDING_LEN;
						}
						rte_memcpy(ip_payload,
							   orig_ip_payload + orig_data_offset,
							   ip_payload_len);
						orig_data_offset += ip_payload_len;

						update_ckcum(m);
#ifdef PCAP_GEN
						dump_pcap(&frag_tbl[j], 1, pcap_dumper_east);
#endif /* !PCAP_GEN */
					}

					/* Don't have access to tx_buf, will this work? */
					int ret;
					int cnt = res;
					struct rte_mbuf **out_pkts = frag_tbl;

					do {
						ret = rte_eth_tx_burst(portid, 0, out_pkts, cnt);
						out_pkts += ret;
						cnt -= ret;
					} while (cnt > 0);
				}

				/* un-set the bit */
				RESET_BIT(*pkts_mask, i);
			}
#endif /* FRAG */
		}
		/* TODO: Set checksum offload.*/
	}
}

void
update_nexts5s8_info(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, struct dp_sdf_per_bearer_info **sdf_bear_info)
{
	/*TODO: Do we need to update TEID in GTP header?*/
	uint16_t len;
	uint32_t i;

	for (i = 0; i < n; i++) {
		if (ISSET_BIT(*pkts_mask, i)) {
			len = rte_pktmbuf_data_len(pkts[i]);
			len = len - ETH_HDR_SIZE;

			if (app.spgw_cfg == SGWU) {
				/*TODO : Make readable*/
				uint32_t s5s8_pgwu_addr =
					sdf_bear_info[i]->bear_sess_info->ul_s1_info.s5s8_pgwu_addr.u.ipv4_addr;
				construct_ipv4_hdr(pkts[i], len, IP_PROTO_UDP,
						ntohl(app.s5s8_sgwu_ip), s5s8_pgwu_addr);
			}else if (app.spgw_cfg == PGWU) {
				uint32_t s5s8_sgwu_addr =
					sdf_bear_info[i]->bear_sess_info->dl_s1_info.s5s8_sgwu_addr.u.ipv4_addr;
				construct_ipv4_hdr(pkts[i], len, IP_PROTO_UDP,
						ntohl(app.s5s8_pgwu_ip), s5s8_sgwu_addr);
			}
		}
	}
}

void
update_enb_info(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, struct dp_sdf_per_bearer_info **sess_info)
{
	uint16_t len;
	uint32_t i;

	for (i = 0; i < n; i++) {
		if (ISSET_BIT(*pkts_mask, i)) {
			len = rte_pktmbuf_data_len(pkts[i]);
			len = len - ETH_HDR_SIZE;

			uint32_t enb_addr =
					sess_info[i]->bear_sess_info->dl_s1_info.enb_addr.u.ipv4_addr;
			construct_ipv4_hdr(pkts[i], len, IP_PROTO_UDP,
					ntohl(app.s1u_ip), enb_addr);

			/*Update tied in GTP U header*/
			((struct gtpu_hdr *)get_mtogtpu(pkts[i]))->teid  =
					ntohl(sess_info[i]->bear_sess_info->dl_s1_info.enb_teid);
		}
	}
}

void
update_adc_rid_from_domain_lookup(uint32_t *rb, uint32_t *rc, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		if (rc[i] != 0)
			rb[i] = rc[i];
}

/**
 * @brief create hash table.
 *
 */
int
hash_create(const char *name, struct rte_hash **rte_hash,
		uint32_t entries, uint32_t key_len)
{
	struct rte_hash_parameters rte_hash_params = {
		.name = name,
		.entries = entries,
		.key_len = key_len,
		.hash_func = DEFAULT_HASH_FUNC,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id(),
	};

	*rte_hash = rte_hash_create(&rte_hash_params);
	if (*rte_hash == NULL)
		rte_exit(EXIT_FAILURE, "%s hash create failed: %s (%u)\n",
			rte_hash_params.name,
			rte_strerror(rte_errno), rte_errno);
	return 0;
}

void dp_table_init(void)
{
	int ret;

	/*
	 * Create Uplink DB
	 */
	hash_create("iface_uplink_db", &rte_uplink_hash,
				LDB_ENTRIES_DEFAULT * HASH_SIZE_FACTOR,
				sizeof(struct ul_bm_key));
	/*
	 * Create Downlink DB
	 */
	hash_create("iface_downlink_db", &rte_downlink_hash,
				LDB_ENTRIES_DEFAULT * HASH_SIZE_FACTOR,
				sizeof(struct dl_bm_key));

	/*
	 * Create ADC Domain Hash table
	 */
	hash_create("adc_domain_hash", &rte_adc_hash, LDB_ENTRIES_DEFAULT,
			sizeof(uint32_t));

	/*
	 * Create ADC UE info Hash table
	 */
	hash_create("adc_ue_info", &rte_adc_ue_hash, LDB_ENTRIES_DEFAULT,
			sizeof(struct dl_bm_key));

	/*
	 * Create UE Sess Hash table
	 */
	hash_create("ue_sess_info", &rte_ue_hash, LDB_ENTRIES_DEFAULT,
			sizeof(uint32_t));

	/*
	 * Create CLI Sess Hash table
	 */
	hash_create("sess_info_cli", &rte_sess_cli_hash, MAX_SESSIONS,
			sizeof(uint32_t));

#ifdef HYPERSCAN_DPI
	/* Create table for sponsored domain names */
	ret = epc_sponsdn_create(DEFAULT_DN_NUM);
	if (ret)
		rte_exit(EXIT_FAILURE,
			"error allocating sponsored DN context %d\n", ret);
#endif
	/*
	 * Init callback APIs
	 */
	app_sess_tbl_init();
	app_pcc_tbl_init();
	app_mtr_tbl_init();
	app_filter_tbl_init();
	app_adc_tbl_init();

	struct dp_id dp_id = { .id = DPN_ID };
	sprintf(dp_id.name, SDF_FILTER_TABLE);
	ret = dp_sdf_filter_table_create(dp_id, SDF_FILTER_TABLE_SIZE);
	if (ret)
		rte_exit(EXIT_FAILURE,
			"error in creating SDF filter table %d\n", ret);

	sprintf(dp_id.name, ADC_TABLE);
	ret = dp_adc_table_create(dp_id, ADC_TABLE_SIZE);
	if (ret)
		rte_exit(EXIT_FAILURE,
			"error in creating ADC table %d\n", ret);

	sprintf(dp_id.name, PCC_TABLE);
	ret = dp_pcc_table_create(dp_id, PCC_TABLE_SIZE);
	if (ret)
		rte_exit(EXIT_FAILURE,
			"error in creating PCC table %d\n", ret);

	sprintf(dp_id.name, METER_PROFILE_SDF_TABLE);
	ret = dp_meter_profile_table_create(dp_id,
				METER_PROFILE_SDF_TABLE_SIZE);
	if (ret)
		rte_exit(EXIT_FAILURE,
			"error in creating Meter profile table %d\n", ret);

	sprintf(dp_id.name, SESSION_TABLE);
	ret = dp_session_table_create(dp_id, LDB_ENTRIES_DEFAULT);
	if (ret)
		rte_exit(EXIT_FAILURE,
			"error in creating session table %d\n", ret);

	if (dp_sdf_default_entry_add(dp_id, SDF_DEFAULT_DROP_RULE_ID) < 0)
		rte_exit(EXIT_FAILURE,
			"error in adding default entry to"
			" sdf filter table %d\n", ret);

	if (dp_adc_filter_default_entry_add(dp_id) < 0)
		rte_exit(EXIT_FAILURE,
			"error in adding default entry to"
			" adc filter table %d\n", ret);

	/*
	 * Create SDF-PCC Hash table
	 */
	hash_create("sdf_pcc_hash", &rte_sdf_pcc_hash, SDF_FILTER_TABLE_SIZE,
			sizeof(uint32_t));

	/*
	 * Create ADC-PCC Hash table
	 */
	hash_create("adc_pcc_hash", &rte_adc_pcc_hash, SDF_FILTER_TABLE_SIZE,
			sizeof(uint32_t));

#ifdef PCAP_GEN
	printf("\n\npcap files will be overwritten. Press ENTER to continue...\n");
	getchar();

	char east_file[PCAP_FILENAME_LEN] = {0};
	char west_file[PCAP_FILENAME_LEN] = {0};

	switch(app.spgw_cfg) {
		case SPGWU:
			strncpy(east_file, SPGW_SGI_PCAP_FILE,
					sizeof(SPGW_SGI_PCAP_FILE));
			strncpy(west_file, SPGW_S1U_PCAP_FILE,
					sizeof(SPGW_S1U_PCAP_FILE));
			break;

		case SGWU:
			strncpy(east_file, SGW_S5S8_PCAP_FILE,
					sizeof(SGW_S5S8_PCAP_FILE));
			strncpy(west_file, SGW_S1U_PCAP_FILE,
					sizeof(SGW_S1U_PCAP_FILE));
			break;

		case PGWU:
			strncpy(east_file, PGW_SGI_PCAP_FILE,
					sizeof(PGW_SGI_PCAP_FILE));
			strncpy(west_file, PGW_S5S8_PCAP_FILE,
					sizeof(PGW_S5S8_PCAP_FILE));
			break;

		default:
		break;
	}

	pcap_dumper_east = init_pcap(east_file);
	pcap_dumper_west = init_pcap(west_file);
#endif /* PCAP_GEN */

}

#ifdef PCAP_GEN
/**
 * initialize pcap dumper.
 * @param pcap_filename
 *  pointer to pcap output filename.
 */
pcap_dumper_t *
init_pcap(char* pcap_filename)
{
	pcap_dumper_t *pcap_dumper = NULL;
	pcap_t *pcap = NULL;
	pcap = pcap_open_dead(DLT_EN10MB, UINT16_MAX);

	if ((pcap_dumper = pcap_dump_open(pcap, pcap_filename)) == NULL) {
		RTE_LOG_DP(ERR, DP, "Error in opening pcap file.\n");
		return NULL;
	}
	return pcap_dumper;
}

/**
 * write into pcap file.
 * @param pkts
 *  pointer to mbuf of packets.
 * @param n
 *  number of pkts.
 * @param pcap_dumper
 *  pointer to pcap dumper.
 */
void dump_pcap(struct rte_mbuf **pkts, uint32_t n,
pcap_dumper_t *pcap_dumper)
{
	uint32_t i;

	for (i = 0; i < n; i++) {
		struct pcap_pkthdr pcap_hdr;
		uint8_t *pkt = rte_pktmbuf_mtod(pkts[i], uint8_t *);

		pcap_hdr.len = pkts[i]->pkt_len;
		pcap_hdr.caplen = pcap_hdr.len;
		gettimeofday(&(pcap_hdr.ts), NULL);

		pcap_dump((u_char *)pcap_dumper, &pcap_hdr, pkt);
		pcap_dump_flush((pcap_dumper_t *)pcap_dumper);
	}
	return;
}
#endif /* PCAP_GEN */
