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

#include <unistd.h>
#include <locale.h>
#include <signal.h>

#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_branch_prediction.h>

#include "main.h"

struct rte_ring *cdr_ring;

/**
 * Main function.
 */
int main(int argc, char **argv)
{
	int ret;
	sigset_t mask;

	/* ASR- Initialize global vars */
	cdr_ring = NULL;

	sigemptyset(&mask);
	sigaddset(&mask, SIGRTMIN);
	if (sigprocmask(SIG_SETMASK, &mask, NULL) == -1)
		RTE_LOG_DP(ERR, DP, "sigprocmask error\n");

	/* Initialize the Environment Abstraction Layer */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	if (signal(SIGINT, sig_handler) == SIG_ERR)
		rte_exit(EXIT_FAILURE, "Error:can't catch SIGINT\n");
	argc -= ret;
	argv += ret;

	/* DP Init */
	dp_init(argc, argv);

#ifndef PERFORMANCE
	/* Add support for dpdk-18.02 */
	/* enable DP log level */
	if (app.log_level == DEBUG) {
		/*Enable DEBUG log level*/
		rte_log_set_level(RTE_LOGTYPE_DP, RTE_LOG_DEBUG);
		rte_log_set_level(RTE_LOGTYPE_KNI, RTE_LOG_DEBUG);
		rte_log_set_level(RTE_LOGTYPE_API, RTE_LOG_DEBUG);
		rte_log_set_level(RTE_LOGTYPE_EPC, RTE_LOG_DEBUG);
		RTE_LOG_DP(DEBUG, DP, "LOG_LEVEL=LOG_DEBUG::"
				"\n\trte_log_get_global_level()= %u\n\n",
				rte_log_get_global_level());
	} else if (app.log_level == NOTICE) {
		/*Enable NOTICE log level*/
		rte_log_set_global_level(RTE_LOG_NOTICE);
		printf("LOG_LEVEL=LOG_NOTICE::"
				"\n\trte_log_get_global_level()= %u\n\n",
				rte_log_get_global_level());
	} else {
		/*Enable INFO log level*/
		rte_log_set_global_level(RTE_LOG_INFO);
		printf("LOG_LEVEL=LOG_INFO::"
				"\n\trte_log_get_global_level()= %u\n\n",
				rte_log_get_global_level());
	}
#endif

	/* Initialize DP PORTS and membufs */
	dp_port_init();

#ifdef DP_DDN
	/* Init Downlink data notification ring, container and mempool  */
	dp_ddn_init();
#endif

	switch (app.spgw_cfg) {
		case SGWU:
			/**
			 *UE <--S1U-->[SGW]<--S5/8-->[PGW]<--SGi-->
			 */
			RTE_LOG_DP(INFO, DP, "SPGW_CFG=SGWU::"
					"\n\tWEST_PORT=S1U <> EAST_PORT=S5/S8\n");
			/* Pipeline Init */
			init_ngic_rtc_framework(app.s5s8_sgwu_port,
					app.s1u_port);
			/*S1U port handler*/
			register_ul_worker(s1u_pkt_handler, app.s1u_port);
			/*S5/8 port handler*/
			register_dl_worker(sgw_s5_s8_pkt_handler, app.s5s8_sgwu_port);
			break;

		case PGWU:
			/**
			 *UE <--S1U-->[SGW]<--S5/8-->[PGW]<--SGi-->
			 */
			RTE_LOG_DP(INFO, DP, "SPGW_CFG=PGWU::"
					"\n\tWEST_PORT=S5/S8 <> EAST_PORT=SGi\n");
			/* Pipeline Init */
			init_ngic_rtc_framework(app.sgi_port, app.s5s8_pgwu_port);
			/*S5/8 port handler*/
			register_ul_worker(pgw_s5_s8_pkt_handler, app.s5s8_pgwu_port);
			/*SGi port handler*/
			register_dl_worker(sgi_pkt_handler, app.sgi_port);

		case SPGWU:
			/**
			 * UE <--S1U--> [SPGW] <--SGi-->
			 */
			RTE_LOG_DP(INFO, DP, "SPGW_CFG=SPGWU::"
					"\n\tWEST_PORT=S1U <> EAST_PORT=SGi\n");
			/* Pipeline Init */
			init_ngic_rtc_framework(app.sgi_port, app.s1u_port);
			/*S1U port handler*/
			register_ul_worker(s1u_pkt_handler, app.s1u_port);
			/*SGi port handler*/
			register_dl_worker(sgi_pkt_handler, app.sgi_port);
			break;

		default:
			rte_exit(EXIT_FAILURE, "Invalid DP type(SPGW_CFG).\n");
	}

	iface_module_constructor();
	dp_table_init();

	launch_ngic_rtc_framework();

	rte_eal_mp_wait_lcore();

	return 0;
}
