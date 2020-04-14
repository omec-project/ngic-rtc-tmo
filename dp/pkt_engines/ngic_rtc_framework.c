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
#include <unistd.h>

#include <rte_ring.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_port_ring.h>
#include <rte_port_ethdev.h>
#include <rte_table_hash.h>
#include <rte_table_stub.h>
#include <rte_byteorder.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_jhash.h>
#include <rte_cycles.h>
#include <rte_port_ring.h>
#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_timer.h>
#include <rte_debug.h>
#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_socket.h>
#include <cmdline.h>

#include "main.h"
#include "ngic_rtc_framework.h"
#include "meter.h"
#include "acl_dp.h"
#include "dp_commands.h"

struct rte_ring *epc_mct_spns_dns_rx;
/* Rings for management messages (ARP, GTP ECHO) */
struct rte_ring *mngt_ul_ring = NULL;
struct rte_ring *mngt_dl_ring = NULL;

struct epc_app_params epc_app = {
	.core_mct = -1,
	.core_iface = -1,
	.core_spns_dns = -1,
	.core_ul[S1U_PORT_ID] = -1,
	.core_dl[SGI_PORT_ID] = -1,
};

static void *dp_zmq_thread(__rte_unused void *arg)
{
	while (1)
		iface_remove_que(COMM_ZMQ);
	return NULL; //GCC_Security flag
}

/**
 * ngic_rtc util handler
 */
static void epc_util_handler(__rte_unused void *arg,
			__rte_unused port_pairs_t ip_op)
{
	epc_stats_core();
}

/**
 * ngic_rtc CP <Sxa|ZMQ> interface function
 */
static void epc_iface_core(__rte_unused void *args,
						__rte_unused port_pairs_t ip_op)
{
	static int timer_mask;
	if (timer_mask == 0) {
		sigset_t mask;
		sigemptyset(&mask);
		sigaddset(&mask, SIGRTMIN);
		if (sigprocmask(SIG_UNBLOCK, &mask, NULL) == -1)
			RTE_LOG_DP(ERR, API, "sigprocmask error\n");
		timer_mask = 1;
	}
#ifdef SIMU_CP /* SIMU_CP::Built-in session injection */
	static int simu_call;

	if (simu_call == 0) {
		simu_cp();
		simu_call = 1;
	}
#else /* !SIMU_CP::Live session injection */
	uint32_t lcore;

	lcore = rte_lcore_id();
	RTE_LOG_DP(NOTICE, API, "RTE NOTICE enabled on lcore %d\n", lcore);
	RTE_LOG_DP(INFO, API, "RTE INFO enabled on lcore %d\n", lcore);
	RTE_LOG_DP(DEBUG, API, "RTE DEBUG enabled on lcore %d\n", lcore);

#ifdef SDN_ODL_BUILD
	pthread_t t;
	int err;

	err = pthread_create(&t, NULL, &dp_zmq_thread, NULL);
	if (err != 0)
		RTE_LOG_DP(INFO, API, "\ncan't create ZMQ read thread :[%s]", strerror(err));
	else
		RTE_LOG_DP(INFO, API, "\n ZMQ read thread created successfully\n");
#else /* !SDN_ODL_BUILD */

	/*
	 * Poll message que. Populate hash table from que.
	 */
	while (1) {
		iface_remove_que(COMM_ZMQ);
		/* Process CDR messages */
		process_cdr_queue();
#ifdef HYPERSCAN_DPI
		scan_dns_ring();
#endif /* HYPERSCAN_DPI */
	}
#endif /* SDN_ODL_BUILD */
#endif /* SIMU_CP */
}

/*
 * ngic-rtc stats init
 */
static void epc_stats_init(void)
{
	epc_app.ul_params[S1U_PORT_ID].pkts_in = 0,
	epc_app.ul_params[S1U_PORT_ID].pkts_out = 0,
	epc_app.ul_params[S1U_PORT_ID].tot_ul_bytes = 0,

	epc_app.ul_params[S1U_PORT_ID].ul_mbuf_rtime.rx_alloc = 0;
	epc_app.ul_params[S1U_PORT_ID].ul_mbuf_rtime.gtpu = 0;
	epc_app.ul_params[S1U_PORT_ID].ul_mbuf_rtime.gtp_echo = 0;
	epc_app.ul_params[S1U_PORT_ID].ul_mbuf_rtime.kni = 0;
	epc_app.ul_params[S1U_PORT_ID].ul_mbuf_rtime.bad_pkt = 0;
	epc_app.ul_params[S1U_PORT_ID].ul_mbuf_rtime.tx_free = 0;

	epc_app.dl_params[SGI_PORT_ID].pkts_in = 0,
	epc_app.dl_params[SGI_PORT_ID].pkts_out = 0,
	epc_app.dl_params[SGI_PORT_ID].tot_dl_bytes = 0,
	epc_app.dl_params[SGI_PORT_ID].ddn = 0,

	epc_app.dl_params[SGI_PORT_ID].dl_mbuf_rtime.rx_alloc = 0;
	epc_app.dl_params[SGI_PORT_ID].dl_mbuf_rtime.dl_pkt = 0;
	epc_app.dl_params[SGI_PORT_ID].dl_mbuf_rtime.kni = 0;
	epc_app.dl_params[SGI_PORT_ID].dl_mbuf_rtime.bad_pkt = 0;
	epc_app.dl_params[SGI_PORT_ID].dl_mbuf_rtime.tx_free = 0;
}

/**
 * ngic-rtc map function to: Cores | Ports | Queues
 */
static void epc_init_lcores(void)
{
	/* ASR- Note: No port or queue associated w/ core_mct, core_iface
	 * Set:: Input-Outport[ports, queues] = -1; */
	port_pairs_t null_port_pair = {
		.in_pid = -1,
		.in_qid =-1,
		.out_pid = -1,
		.out_qid = -1
	};

	epc_alloc_lcore(epc_util_handler, NULL, epc_app.core_mct,
					null_port_pair);
	epc_alloc_lcore(epc_iface_core, NULL, epc_app.core_iface,
					null_port_pair);

	/* UL Port Pair */
	port_pairs_t ul_port_pair = {
		.in_pid = S1U_PORT_ID,
		.in_qid = DEFAULT_QID,
		.out_pid = SGI_PORT_ID,
		.out_qid = DEFAULT_QID
	};
	epc_alloc_lcore(epc_ul, &epc_app.ul_params[S1U_PORT_ID],
						epc_app.core_ul[S1U_PORT_ID],
						ul_port_pair);
	/* DL Port Pair */
	port_pairs_t dl_port_pair = {
		.in_pid = SGI_PORT_ID,
		.in_qid = DEFAULT_QID,
		.out_pid = S1U_PORT_ID,
		.out_qid = DEFAULT_QID
	};
	epc_alloc_lcore(epc_dl, &epc_app.dl_params[SGI_PORT_ID],
						epc_app.core_dl[SGI_PORT_ID],
						dl_port_pair);
}

/* initialize rings common to all ngic-rtc flows */
static void epc_init_rings(void)
{
	uint32_t port;
	char name[32];

	port = epc_app.ports[1];
	snprintf(name, sizeof(name), "rx_to_mct_spns_dns%u", port);
	epc_mct_spns_dns_rx = rte_ring_create(name,
				EPC_DEFAULT_RING_SZ * 16,
				rte_socket_id(),
				RING_F_SC_DEQ);
	if (epc_mct_spns_dns_rx == NULL)
		rte_panic("Cannot create RX ring %u\n", port);

	mngt_ul_ring = rte_ring_create("UL_MNGT_ring", RXTX_RING_SIZE,
			rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (mngt_ul_ring == NULL) {
		rte_exit(EXIT_FAILURE, "Error in creating mngt_ul_ring!!!\n");
	}
	mngt_dl_ring = rte_ring_create("DL_MNGT_ring", RXTX_RING_SIZE,
			rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (mngt_dl_ring == NULL) {
		rte_exit(EXIT_FAILURE, "Error in creating mngt_dl_ring!!!\n");
	}

}

static inline void ngic_rtc_run(void)
{
	struct epc_lcore_config *config;
	int i;
	unsigned lcore;

	lcore = rte_lcore_id();
	config = &epc_app.lcores[lcore];
	for (i = 0; i < config->allocated; i++) {
		config->launch.func(config->launch.arg,
							config->launch.ip_op_ports);
	}
}

static int epc_lcore_main_loop(__attribute__ ((unused))
		void *arg)
{
	struct epc_lcore_config *config;
	uint32_t lcore;

	lcore = rte_lcore_id();
	config = &epc_app.lcores[lcore];

	if (config->allocated == 0)
		return 0;

	RTE_LOG_DP(NOTICE, DP, "RTE NOTICE enabled on lcore %d\n", lcore);
	RTE_LOG_DP(INFO, DP, "RTE INFO enabled on lcore %d\n", lcore);
	RTE_LOG_DP(DEBUG, DP, "RTE DEBUG enabled on lcore %d\n", lcore);

	while (1)
		ngic_rtc_run();

	return 0;
}

void init_ngic_rtc_framework(uint8_t east_port_id, uint8_t west_port_id)
{

	/* SM- TODO: Why did you remove the generalization WEST_PORT, EAST_PORT?
	 * And since yu did, why di you not consider port_pairs_t? */
	epc_app.ports[S1U_PORT_ID] = west_port_id;
	epc_app.ports[SGI_PORT_ID] = east_port_id;
	printf("ARP-ICMP Core on:\t\t%d\n", epc_app.core_mct);
	printf("CP-DP IFACE Core on:\t\t%d\n", epc_app.core_iface);
	epc_app.core_spns_dns = epc_app.core_iface;
	printf("SPNS DNS Core on:\t\t%d\n", epc_app.core_spns_dns);
	printf("STATS-Timer Core on:\t\t%d\n", epc_app.core_mct);
	/*
	 * Initialize ngic-rtc rings
	 */
	epc_init_rings();

	/*
	 * Initialize arp & spns_dns cores
	 */
	mngtplane_init();
#ifdef HYPERSCAN_DPI
	epc_spns_dns_init();
#endif

	printf("Uplink Core on:\t\t\t%d\n", epc_app.core_ul[S1U_PORT_ID]);
	printf("Downlink Core on:\t\t%d\n", epc_app.core_dl[SGI_PORT_ID]);

	/*
	 * ngic-rtc map function to: Cores | Ports | Queues
	 */
	epc_init_lcores();

	/*
	 * ngic-rtc stats init
	 */
	epc_stats_init();

	/* Init IPC msgs */
	iface_init_ipc_node();
}

void launch_ngic_rtc_framework(void)
{
	if (rte_eal_mp_remote_launch(epc_lcore_main_loop, NULL, CALL_MASTER) < 0)
		rte_exit(EXIT_FAILURE,"launch_ngic_rtc_framework FAIL !!!");
}

/**
 * ngic-rtc allocate cores to functions
 *
 * @param func
 *	Function to run
 * @param arg
 *	Argument to ngic_rtc function
 * @param core
 *	Core to run ngic-rtc function on
 * @param ip_op
 *	Input-Outport[ports, queues] for function called
 */
/* ASR- Note: ngic-rtclnx::ngic-rtc wide scope::void epc_alloc_lcore */
void epc_alloc_lcore(ngic_rtc_func_t func, void *arg,
		int core, port_pairs_t ip_op)
{
	struct epc_lcore_config *lcore;

	if (core >= DP_MAX_LCORE)
		rte_exit(EXIT_FAILURE,"%s: Core %d exceed Max core %d\n", __func__, core,
				DP_MAX_LCORE);

	lcore = &epc_app.lcores[core];
	lcore->launch.func = func;
	lcore->launch.arg = arg;
	lcore->launch.ip_op_ports = ip_op;
	lcore->allocated++;
}
