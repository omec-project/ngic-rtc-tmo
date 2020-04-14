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

#include <stdio.h>
#include <stdlib.h>

#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <unistd.h>
#ifdef FRAG
#include <rte_cycles.h>
#endif /* FRAG */
#include "main.h"

#ifdef FRAG
/**
 * pointer to frag table (for re-assembly) on s1u side
 */
struct rte_ip_frag_tbl *s1u_frag_tbl;

/**
 * for retiring outdated frags on s1u side (internal bookkeeping)
 */
struct rte_ip_frag_death_row s1u_death_row;

/**
 * for calculating retiring time
 */
uint64_t s1u_cur_tsc = 0;

/**
 * for holding fragged mbufs in linked list style
 */
struct rte_mempool *sgi_indirect_pktmbuf_pool = NULL;
#endif /* FRAG */

/* memory pool for userplane pkts */
struct rte_mempool *user_ulmp;
struct rte_mempool *user_dlmp;
/* memory pool for KNI pkts */
struct rte_mempool *kni_ulmp;
struct rte_mempool *kni_dlmp;
/* memory pool for mngt pkts */
struct rte_mempool *mngt_ulmp;
struct rte_mempool *mngt_dlmp;

struct kni_port_params *kni_port_params_array[RTE_MAX_ETHPORTS];
extern struct rte_ring *cdr_ring;

#ifdef DP_DDN
struct rte_ring *dl_ring_container = NULL;
uint32_t num_dl_rings = 0;
struct rte_ring *notify_ring = NULL;
struct rte_mempool *notify_msg_pool = NULL;
#endif /* DP_DDN */

/* VS: Route table Discovery */
/**
 * Routing table hash params.
 */
static struct rte_hash_parameters route_hash_params = {
	.name = "ROUTE_TABLE",
	.entries = 64*64,
	.reserved = 0,
	.key_len = sizeof(uint32_t),
	.hash_func = rte_jhash,
	.hash_func_init_val = 0,
};

/**
 * Route rte hash handler.
 */
struct rte_hash *route_hash_handle;

uint32_t nb_ports = 0 ;

/**
 * default port config structure .
 */
const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .max_rx_pkt_len = ETHER_MAX_LEN,
        .offloads =
            DEV_RX_OFFLOAD_IPV4_CKSUM |
            DEV_RX_OFFLOAD_UDP_CKSUM |
            DEV_RX_OFFLOAD_TCP_CKSUM |
            DEV_RX_OFFLOAD_OUTER_IPV4_CKSUM |
            DEV_RX_OFFLOAD_CRC_STRIP,
        /* Enable hw_crc_strip for PF/VF drivers */
        .hw_strip_crc = 1}
};

/**
 * Function to Initialize a given port using global settings and with the rx
 * buffers coming from the mbuf_pool passed as parameter
 * @param port
 *	port number.
 * @param mbuf_pool
 *	memory pool pointer.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
static inline int port_init(uint8_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf *txconf;
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;  //tx_rings = rte_lcore_count() - 1;
	int retval;
	uint16_t q;


	if (port >= rte_eth_dev_count())
		return -1;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	/* Allocate and set up RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, RX_NUM_DESC,
				rte_eth_dev_socket_id(port),
				NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}


	/* Allocate and set up TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		/* Get Default txconf */
		retval = rte_eth_tx_queue_setup(port, q, TX_NUM_DESC,
				rte_eth_dev_socket_id(port),
				NULL);
		rte_eth_dev_info_get(port, &dev_info);
		txconf = &dev_info.default_txconf;
		printf("ASR- Probe::%s::"
				"\n\tdefault tx_conf->tx_free_thresh= %u;"
				"\n\tNUM_MBUFS= %u; Set tx_conf->tx_free_thresh=default tx_conf= %u\n",
				__func__, txconf->tx_free_thresh, NUM_MBUFS, txconf->tx_free_thresh);
		/* ASR- Probe: Option to vary tx_free_thresh to modulate rte_eth_tx_burst()
		 * freeing memory buffers of packets sent */
//		txconf->tx_free_thresh = (NUM_MBUFS)/4;
//		retval = rte_eth_tx_queue_setup(port, q, TX_NUM_DESC,
//				rte_eth_dev_socket_id(port),
//				txconf);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	rte_eth_macaddr_get(port, &ports_eth_addr[port]);
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			" %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			(unsigned)port,
			ports_eth_addr[port].addr_bytes[0],
			ports_eth_addr[port].addr_bytes[1],
			ports_eth_addr[port].addr_bytes[2],
			ports_eth_addr[port].addr_bytes[3],
			ports_eth_addr[port].addr_bytes[4],
			ports_eth_addr[port].addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	/* rte_eth_promiscuous_enable(port); */
	rte_eth_promiscuous_disable(port);

	return 0;
}

void dp_port_init(void)
{
	uint8_t port_id;
#ifdef FRAG
	uint64_t frag_cycles;
	int rxlcore_id;
#endif /* FRAG */

	enum {
		S1U_PORT = 0,
		SGI_PORT = 1
	};
	int i = 0, j; //GCC_Security flag

	nb_ports = rte_eth_dev_count();
	printf ("nb_ports cnt is %u\n", nb_ports);
	if (nb_ports < 2 || (nb_ports & 1))
		rte_exit(EXIT_FAILURE, "Error: number of ports must be two\n");

	/* Create user UL mempool to hold the mbufs. */
	user_ulmp = rte_pktmbuf_pool_create("user_ulmp", NUM_MBUFS,
			MBUF_CACHE_SIZE, 0,
			RTE_MBUF_DEFAULT_BUF_SIZE,
			rte_socket_id());
	if (user_ulmp == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create user_ulmp !!!\n");

	/* Create user DL mempool to hold the mbufs. */
	user_dlmp = rte_pktmbuf_pool_create("user_dlmp", NUM_MBUFS,
			MBUF_CACHE_SIZE, 0,
			RTE_MBUF_DEFAULT_BUF_SIZE,
			rte_socket_id());
	if (user_dlmp == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create user_dlmp !!!\n");

	/* Create UL management mempool */
	mngt_ulmp = rte_pktmbuf_pool_create("mngt_ulmp", NUM_MBUFS,
			MBUF_CACHE_SIZE, 0,
			RTE_MBUF_DEFAULT_BUF_SIZE,
			rte_socket_id());
	if (mngt_ulmp == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mngt_ulmp !!!\n");

	/* Create DL management mempool */
	mngt_dlmp = rte_pktmbuf_pool_create("mngt_dlmp", NUM_MBUFS,
				MBUF_CACHE_SIZE, 0,
				RTE_MBUF_DEFAULT_BUF_SIZE,
				rte_socket_id());
	if (mngt_dlmp == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mngt_dlmp !!!\n");

	/* Create KNI UL mempool to hold the kni pkts mbufs. */
	kni_ulmp = rte_pktmbuf_pool_create("kni_ulmp", NUM_MBUFS,
			MBUF_CACHE_SIZE, 0,
			RTE_MBUF_DEFAULT_BUF_SIZE,
			rte_socket_id());
	if (kni_ulmp == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create kni_ulmp !!!\n");

	/* Create KNI DL mempool to hold the kni pkts mbufs. */
	kni_dlmp = rte_pktmbuf_pool_create("kni_dlmp", NUM_MBUFS,
			MBUF_CACHE_SIZE, 0,
			RTE_MBUF_DEFAULT_BUF_SIZE,
			rte_socket_id());
	if (kni_dlmp == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create kni_dlmp !!!\n");

#ifdef FRAG
	rxlcore_id = rte_lcore_id();
	frag_cycles = (rte_get_tsc_hz() + MS_PER_S - 1)
		/ MS_PER_S * MAX_SESSIONS;

	if ((s1u_frag_tbl = rte_ip_frag_table_create(MAX_SESSIONS,
						     IP_FRAG_TBL_BUCKET_ENTRIES,
						     MAX_SESSIONS,
						     frag_cycles,
						     rte_socket_id())) == NULL) {
		RTE_LOG(ERR, IP_RSMBL, "frag_tbl_create(%u) on "
			"lcore: %u for queue: %u failed\n",
			MAX_SESSIONS, rxlcore_id, rxlcore_id);
		rte_panic("Reassembly ip frag table creation failed!!!\n");
	}

	sgi_indirect_pktmbuf_pool = rte_pktmbuf_pool_create("sgi_indirect_mbuf_pool",
						       NUM_MBUFS,
						       MBUF_CACHE_SIZE, 0,
						       RTE_MBUF_DEFAULT_BUF_SIZE,
						       rte_socket_id());
	if (sgi_indirect_pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create sgi_indirect_mbuf_pool !!!\n");
#endif /* FRAG */

	/* Initialize KNI interface on s1u and sgi port */
	/* Check if the configured port ID is valid */
	for (port_id = 0; port_id < nb_ports; port_id++) {
		if (kni_port_params_array[port_id] && port_id >= nb_ports)
			rte_exit(EXIT_FAILURE, "Configured invalid "
					"port ID %u\n", port_id);
		kni_port_params_array[port_id] =
			rte_zmalloc("KNI_port_params",
					sizeof(struct kni_port_params), RTE_CACHE_LINE_SIZE);

		kni_port_params_array[port_id]->port_id = port_id;

		if (port_id == 0) {
			kni_port_params_array[port_id]->lcore_rx =
				(uint8_t)epc_app.core_ul[S1U_PORT_ID];
			kni_port_params_array[port_id]->lcore_tx = (uint8_t)epc_app.core_mct;
			printf("KNI lcore on port :%u rx :%u tx :%u\n", port_id,
					kni_port_params_array[port_id]->lcore_rx,
					kni_port_params_array[port_id]->lcore_tx);
		} else if (port_id == 1) {
			kni_port_params_array[port_id]->lcore_rx =
				(uint8_t)epc_app.core_dl[SGI_PORT_ID];
			kni_port_params_array[port_id]->lcore_tx = (uint8_t)epc_app.core_mct;
			printf("KNI lcore on port :%u rx :%u tx :%u\n", port_id,
					kni_port_params_array[port_id]->lcore_rx,
					kni_port_params_array[port_id]->lcore_tx);
		}

		for (j = 0; i < 3 && j < KNI_MAX_KTHREAD; i++, j++) {
			kni_port_params_array[port_id]->lcore_k[j] = 0;
		}
		kni_port_params_array[port_id]->nb_lcore_k = 0;

	}

	/* Check that options were parsed ok */
	if (validate_parameters(app.ports_mask) < 0) {
		rte_exit(EXIT_FAILURE, "Invalid portmask\n");
	}

	/* Initialize KNI subsystem */
	init_kni();

	/* Initialize & Alloc:: KNI S1U & SGi ports */
	if (port_init(S1U_PORT, user_ulmp) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init s1u port %" PRIu8 "\n",
				S1U_PORT);
	kni_alloc(S1U_PORT);
	if (port_init(SGI_PORT, user_dlmp) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init s1u port %" PRIu8 "\n",
				SGI_PORT);
	kni_alloc(SGI_PORT);

	/* CDR Ring creation */
	cdr_ring = rte_ring_create("CDR_RING", CDR_RING_SIZE,
			rte_socket_id(),
			RING_F_SP_ENQ | RING_F_SC_DEQ);

	if (cdr_ring == NULL) {
		rte_exit(EXIT_FAILURE, "Error in creating cdr ring!!!\n");
	}
	/* Routing Discovery : Create route hash for s1u and sgi port */
	route_hash_params.socket_id = rte_socket_id();
	route_hash_handle = rte_hash_create(&route_hash_params);
	if (!route_hash_handle)
		rte_panic("%s hash create failed: %s (%u)\n.",
				route_hash_params.name, rte_strerror(rte_errno),
				rte_errno);

	check_all_ports_link_status(nb_ports, app.ports_mask);
	printf("KNI: DP Port Mask:%u\n", app.ports_mask);
	printf("DP Port initialization completed.\n");
}

#ifdef DP_DDN
void
dp_ddn_init(void)
{
	/** For notification of modify_session so that buffered packets
	 * can be dequeued
	 */
	notify_ring = rte_ring_create("NOTIFY_RING", NOTIFY_RING_SIZE,
			rte_socket_id(),
			RING_F_SP_ENQ | RING_F_SC_DEQ);

	if (notify_ring == NULL) {
		rte_exit(EXIT_FAILURE, "Error in creating notify ring!!!\n");
	}

	/** Holds a set of rings to be used for downlink data buffering */
	dl_ring_container = rte_ring_create("RING_CONTAINER", DL_RING_CONTAINER_SIZE,
			rte_socket_id(),
			RING_F_SC_DEQ);

	if (dl_ring_container == NULL) {
		rte_exit(EXIT_FAILURE, "Error in creating dl ring container!!!\n");
	}

	/** Create mempool for notification to hold pkts mbufs. */
	notify_msg_pool = rte_pktmbuf_pool_create("NOTIFY_MPOOL", NUM_MBUFS,
			MBUF_CACHE_SIZE, 0,
			RTE_MBUF_DEFAULT_BUF_SIZE,
			rte_socket_id());

	if (notify_msg_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create notify_msg_pool !!!\n");


}
#endif /* DP_DDN */
