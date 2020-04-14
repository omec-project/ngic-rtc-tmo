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

#include <string.h>
#include <sched.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

#include <rte_string_fns.h>
#include <rte_ring.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_port_ring.h>
#include <rte_port_ethdev.h>
#include <rte_table_hash.h>
#include <rte_table_stub.h>
#include <rte_byteorder.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_jhash.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_udp.h>
#include <rte_mbuf.h>
#include <rte_hash_crc.h>
#include <rte_port_ring.h>
#include <rte_kni.h>
#include <rte_arp.h>

#include "ngic_rtc_framework.h"
#include "mngtplane_handler.h"
#include "main.h"
#include "gtpu.h"
#ifdef UNIT_TEST
#include "pkt_proc.h"
#endif

#ifdef PERF_ANALYSIS
#include "perf_timer.h"
_timer_t _init_time = 0;
#endif /* PERF_ANALYSIS */

extern struct kni_port_params *kni_port_params_array[RTE_MAX_ETHPORTS];
/* Generate new pcap for sgi port. */
#ifdef PCAP_GEN
extern pcap_dumper_t *pcap_dumper_east;
#endif /* PCAP_GEN */

static inline void dl_set_flow_id(struct rte_mbuf *m)
{
	uint8_t *m_data = rte_pktmbuf_mtod(m, uint8_t *);
	struct ipv4_hdr *ipv4_hdr =
		(struct ipv4_hdr *)&m_data[sizeof(struct ether_hdr)];
	struct ether_hdr *eth_h = (struct ether_hdr *)&m_data[0];
	/* Host Order ipv4_hdr->dst_addr */
	uint32_t ho_addr;

	/* Flag BAD Checksum packets */
	if (unlikely(
		     (m->ol_flags & PKT_RX_IP_CKSUM_MASK) == PKT_RX_IP_CKSUM_BAD ||
		     (m->ol_flags & PKT_RX_L4_CKSUM_MASK) == PKT_RX_L4_CKSUM_BAD)) {
		RTE_LOG_DP(ERR, DP, "UL Bad checksum: %lu\n", m->ol_flags);
		sgi_pktyp = BAD_PKT;
		return;
	}

	/* Check if IPv4 packet */
	if (likely(eth_h->ether_type == htons(ETHER_TYPE_IPv4))) {
		/* Flag fragmented packets:
		 * check for unfragmented packets and packets with don't fragment
		 * bit set (0x40) */
		if(unlikely(ipv4_hdr->fragment_offset != 0 &&
					ipv4_hdr->fragment_offset != 64))
		{
			sgi_pktyp = JUMBO_PKT;
			return;
		}

		ho_addr = ntohl(ipv4_hdr->dst_addr);
		/* Flag pkt destined to SGI_IP for linux handling */
		if (app.sgi_ip == ipv4_hdr->dst_addr)
		{
			RTE_LOG_DP(DEBUG, DP, "epc_dl.c:%s::"
					"\n\t@SGI:app.sgi_ip==ipv4_hdr->dst_addr= %s\n",
					__func__,
					inet_ntoa(*(struct in_addr *)&ho_addr));
			sgi_pktyp = KNI_PKT;
			return;
		}

		/* Flag MCAST pkt for linux handling */
		if (IS_IPV4_MCAST(ho_addr))
		{
			RTE_LOG_DP(DEBUG, DP, "epc_dl.c:%s::"
					"\n\t@SGI:IPV$_MCAST==ipv4_hdr->dst_addr= %s\n",
					__func__,
					inet_ntoa(*(struct in_addr *)&ho_addr));
			sgi_pktyp = KNI_PKT;
			return;
		}

		/* Flag BCAST pkt for linux handling */
		if (app.sgi_bcast_addr == ipv4_hdr->dst_addr)
		{
			RTE_LOG_DP(DEBUG, DP, "epc_dl.c:%s::"
					"\n\t@SGI:app.sgi_bcast_addr==ipv4_hdr->dst_addr= %s\n",
					__func__,
					inet_ntoa(*(struct in_addr *)&ho_addr));
			sgi_pktyp = KNI_PKT;
			return;
		}

		/* Flag all other pkts for epc_dl proc handling */
		RTE_LOG_DP(DEBUG, DP, "SGI packet\n");
		sgi_pktyp = DL_PKT;
		return;
	} /* IPv4 packet */

	/* Flag packets destined to UL interface */
	if ((is_same_ether_addr(&eth_h->d_addr, &app.sgi_ether_addr)) ||
		(is_multicast_ether_addr(&eth_h->d_addr)) ||
		(is_universal_ether_addr(&eth_h->d_addr)) ||
		(is_broadcast_ether_addr(&eth_h->d_addr))) {
			sgi_pktyp = KNI_PKT;
		return;
	}
	sgi_pktyp = UNKNOWN_PKT;
}

static dl_handler dl_pkt_handler[NUM_SPGW_PORTS];
/**
 * DL ngic input action handler function
 * @param pkts
 *   The address of an array of pointers to *rte_mbuf* structures that
 *   must be large enough to store *n* pointers in it.
 * @param n
 *   The maximum number of packets to retrieve.
 * @param pkts_mask
 *   pointer to pkts_mask for received burst
 * @param pid
 *   port_id of function called
 * @param data_pkts
 *   The address of an array of pointers to *rte_mbuf* data packets
 * @param dpkts_mask
 *   pointer to data pkts mask in received burst
 * @return
 *   number of data pkts
 */
static int dl_in_ah(struct rte_mbuf **pkts,
		uint32_t n, uint64_t *pkts_mask,
		struct rte_mbuf **data_pkts, uint64_t *dpkts_mask,
		uint8_t pid)
{
#ifdef PERF_ANALYSIS
	TIMER_GET_CURRENT_TP(_init_time);
#endif /* PERF_ANALYSIS */

	uint32_t i, j;
	uint32_t nb_data_pkts = 0;

	for (i = 0, j=0; i < n; i++) {
		struct rte_mbuf *m = pkts[i];
		dl_set_flow_id(m);
		switch (sgi_pktyp) {
			case DL_PKT:
				nb_data_pkts++;
				data_pkts[j] = m;
				j++;
			break;
#ifndef STATIC_ARP /* !STATIC_ARP == KNI Mode */
			case KNI_PKT:
				RESET_BIT(*pkts_mask, i);
				RTE_LOG(DEBUG, DP, "KNI: UL send pkts to kni\n");
				kni_ingress(kni_port_params_array[pid], pid,
						&pkts[i], 1);
				/* Update KNI alloc DL count */
				epc_app.dl_params[pid].dl_mbuf_rtime.kni++;
				break;
#endif /* !STATIC_ARP == KNI mode */
			/* RESET_BIT::
			 * !STATIC_ARP: BAD_PKT | UNKNOWN_PKT
			 * */
			default:
				RESET_BIT(*pkts_mask, i);
				/* Update BAD_PKT alloc DL count */
				epc_app.dl_params[pid].dl_mbuf_rtime.bad_pkt++;
				RTE_LOG(DEBUG, DP, "sgi_pktyp::"
						"\n\tBAD_PKT | UNKNOWN_PKT\n");
		}
	}

	/* Update DL fastpath packets count */
	epc_app.dl_params[SGI_PORT_ID].pkts_in += nb_data_pkts;
	/* Update DL_PKT alloc DL mbuf count */
	epc_app.dl_params[pid].dl_mbuf_rtime.dl_pkt += nb_data_pkts;

/* Capture packets on sgi port. */
#ifdef PCAP_GEN
	dump_pcap(pkts, n, pcap_dumper_east);
#endif /* PCAP_GEN */

	if (nb_data_pkts) {
		*dpkts_mask = (~0LLU) >> (64 - nb_data_pkts);
		dl_handler f = dl_pkt_handler[pid];
		f(data_pkts, nb_data_pkts, dpkts_mask);
	}

#ifdef PERF_ANALYSIS
	dl_stat_info.port_in_out_delta = TIMER_GET_ELAPSED_NS(_init_time);
#ifdef TIMER_STATS
	/* Export stats into file. */
	dl_timer_stats(nb_data_pkts, &dl_stat_info);
#endif /* TIMER_STATS */

	/* calculate min time, max time, min_burst_sz, max_burst_sz
	 * perf_stats.op_time[13] = port_in_out_time */
	SET_PERF_MAX_MIN_TIME(dl_perf_stats.op_time[13], _init_time, nb_data_pkts, 1);
#endif /* PERF_ANALYSIS */

	return nb_data_pkts;
}

/**
 * DL ngic_rtc function
 *
 * @param arg
 *	Argument to ngic_rtc function
 * @param ip_op
 *	Input-Outport[ports, queues] for function called
 */
void epc_dl(void *args, port_pairs_t ip_op)
{
	uint16_t i, nb_dlrx, nb_dltx, nb_sent, nb_burst, pkt_rx, pkt_tx;
	uint32_t nb_data_pkts = 0;
	struct rte_mbuf *dl_procmbuf[PKT_BURST_SZ];
	struct rte_mbuf *data_pkts[PKT_BURST_SZ] = {NULL};
	struct rte_mbuf *pkt_rxburst[PKT_BURST_SZ] = {NULL};
	uint64_t pkts_mask =0, dpkts_mask = 0;

/* rte_eth_rx_burst(uint16_t port_id, uint16_t queue_id,
		 struct rte_mbuf **rx_pkts, const uint16_t nb_pkts)::
 * - Allocate & Initialize *rte_mbuf* data structure associated w/ RX Descriptors
 * - Store *rte_mbuf* into the next entry of *rx_pkts* array.
 * - Return number of packets actually retrieved
 * - Replenish RX descriptor w/ new *rte_mbuf* buffer
 *	 allocated from memory pool associated w/ receive queue by init.c
 */
	nb_dlrx = rte_eth_rx_burst(ip_op.in_pid, ip_op.in_qid,
							dl_procmbuf, PKT_BURST_SZ);

	if (nb_dlrx > 0) {
#ifdef UNIT_TEST
		/* Manipulate mixed packets */
		create_mixed_bursts(dl_procmbuf, nb_dlrx, ip_op.in_pid);
#endif
		pkts_mask = (~0LLU) >> (64 - nb_dlrx);
		/* Update allocated DL mbuf count */
		epc_app.dl_params[ip_op.in_pid].dl_mbuf_rtime.rx_alloc += nb_dlrx;
		nb_data_pkts=
			dl_in_ah(dl_procmbuf, nb_dlrx, &pkts_mask,
					data_pkts, &dpkts_mask, ip_op.in_pid);

		/* rte_eth_tx_burst(uint16_t port_id, uint16_t queue_id,
				 struct rte_mbuf **tx_pkts, uint16_t nb_pkts)::
		 * - Initialize *rte_mbuf* data structure associated w/ TX Descriptors
		 * - *tx_pkts* allocated from memory pool associated w/ receive queue by init.c
		 * - Free the network buffer previously sent with that descriptor, if any.
		 * - Return number of packets actually sent.
		 * - Transparently free memory buffers of packets sent based on *tx_free_thresh*
		 */

		nb_sent = 0;
		while (nb_sent < nb_data_pkts) {
			/* Find the position of the first fastpath pkt to be freed.
			 * i.e find the first invalid fastpath packet */
			nb_burst = __builtin_ffsl(~dpkts_mask);

			/* If all packets are marked to be sent in dpkts_mask, i.e no
			 * intermediate pkts in the fastpath burst are marked to be freed */
			if ((nb_burst == 0) || (nb_burst > nb_data_pkts)) {
				nb_dltx = rte_eth_tx_burst(ip_op.out_pid, ip_op.out_qid,
								&data_pkts[nb_sent], nb_data_pkts);
				/* Update TX+FREE DL mbuf count */
				epc_app.dl_params[ip_op.in_pid].dl_mbuf_rtime.tx_free += nb_dltx;
				for (i = nb_dltx; i < nb_data_pkts; i++) {
						rte_pktmbuf_free(data_pkts[i]);
					/* Update TX+FREE DL mbuf count */
					epc_app.dl_params[ip_op.in_pid].dl_mbuf_rtime.tx_free++;
				}
				if (nb_dltx < nb_data_pkts) {
					printf("ASR- Probe::%s::"
						"\n\teth_tx descriptors/tx_ring full!!!"
						"\n\tnb_ulrx= %u; nb_ultx= %u\n",
						__func__, nb_data_pkts, nb_dltx);
				}
				break;
			}

			/* If fastpath packets are marked to be sent, but there is atleast one
			 * intermediate pkt in the fastpath burst marked to be freed in dpkts_mask */
			if ((nb_burst > 1) && (nb_burst <= nb_data_pkts)) {
				nb_dltx = rte_eth_tx_burst(ip_op.out_pid, ip_op.out_qid,
								&data_pkts[nb_sent], nb_burst - 1);
				/* Update TX+FREE DL mbuf count */
				epc_app.dl_params[ip_op.in_pid].dl_mbuf_rtime.tx_free += nb_dltx;
				for (i = nb_dltx; i < (nb_burst -1); i++) {
						rte_pktmbuf_free(data_pkts[i]);
					/* Update TX+FREE DL mbuf count */
					epc_app.dl_params[ip_op.in_pid].dl_mbuf_rtime.tx_free++;
				}
				if (nb_dltx < (nb_burst - 1)) {
					printf("ASR- Probe::%s::"
						"\n\teth_tx descriptors/tx_ring full!!!"
						"\n\tnb_ulrx= %u; nb_ultx= %u\n",
						__func__, (nb_burst - 1), nb_dltx);
				}
			}

			nb_sent += nb_burst;

			/* Free intermediate pkts in the fastpath burst marked
			 * to be freed in dpkts_mask */
			if (nb_sent <= nb_data_pkts) {
				rte_pktmbuf_free(data_pkts[nb_sent - 1]);
					/* Update TX+FREE DL mbuf count */
					epc_app.dl_params[ip_op.in_pid].dl_mbuf_rtime.tx_free++;
				dpkts_mask >>= nb_burst ;
			}
		}

		/* Free all non-fastpath packets */
		for (i = 0; i < nb_dlrx; i++) {
			if (ISSET_BIT(pkts_mask, i))
				continue;
			rte_pktmbuf_free(dl_procmbuf[i]);
		}
	}

	/* Process mngt_req pkts received on UL port */
	pkt_rx = mngt_egress(&ip_op, pkt_rxburst);
	/* Send mngt_rsp pkts on DL path */
	pkt_tx = rte_eth_tx_burst(ip_op.out_pid, ip_op.out_qid, pkt_rxburst, pkt_rx);
	/* Update TX+FREE DL mbuf count */
	epc_app.dl_params[ip_op.in_pid].dl_mbuf_rtime.tx_free += pkt_tx;
	for (i = pkt_tx; i < pkt_rx; i++) {
		rte_pktmbuf_free(pkt_rxburst[i]);
		/* Update TX+FREE DL mbuf count */
		epc_app.dl_params[ip_op.in_pid].dl_mbuf_rtime.tx_free++;
	}
	if (pkt_tx < pkt_rx) {
		printf("ASR- Probe::%s::"
				"\n\teth_tx descriptors/tx_ring full!!!"
				"\n\tpkt_rx= %u; pkt_tx= %u\n",
				__func__, pkt_rx, pkt_tx);
	}

#ifndef STATIC_ARP
	/** Handle the request mbufs sent from kernel space,
	 *  Then analyzes it and calls the specific actions for the specific requests.
	 *  Finally constructs the response mbuf and puts it back to the resp_q.
	 */
	rte_kni_handle_request(kni_port_params_array[ip_op.in_pid]->kni[0]);

	pkt_rx = kni_egress(kni_port_params_array[ip_op.out_pid],
					pkt_rxburst);
#ifdef PCAP_GEN
	dump_pcap(pkt_rxburst, pkt_rx, pcap_dumper_east);
#endif /* PCAP_GEN */
	pkt_tx = rte_eth_tx_burst(ip_op.out_pid, ip_op.out_qid,
						pkt_rxburst, pkt_rx);
	/* Update TX+FREE DL mbuf count */
	epc_app.ul_params[ip_op.in_pid].ul_mbuf_rtime.tx_free += pkt_tx;
	for (i = pkt_tx; i < pkt_rx; i++) {
		rte_pktmbuf_free(pkt_rxburst[i]);
		/* Update TX+FREE DL mbuf count */
		epc_app.ul_params[ip_op.in_pid].ul_mbuf_rtime.tx_free++;
	}
	if (pkt_tx < pkt_rx) {
		printf("ASR- Probe::%s::"
				"\n\teth_tx descriptors/tx_ring full!!!"
				"\n\tpkt_rx= %u; pkt_tx= %u\n",
				__func__, pkt_rx, pkt_tx);
	}
#endif /* !STATIC_ARP */

#ifdef DP_DDN
	uint32_t count = rte_ring_count(notify_ring);
	if (count) {
		struct rte_mbuf *pkts[count];
		uint32_t rx_cnt = rte_ring_dequeue_bulk(notify_ring,
				(void**)pkts, count, NULL);
		int ret  = notification_handler(pkts, rx_cnt);
		if (ret < 0)
			printf("ERROR: notification handler failed..\n");
	}
#endif /* DP_DDN */
}

void register_dl_worker(dl_handler f, int port)
{
	dl_pkt_handler[port] = f;
}

