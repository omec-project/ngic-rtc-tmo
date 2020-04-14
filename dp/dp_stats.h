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

#ifndef DP_STATS_H
#define DP_STATS_H
/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes of ngic_rtc dataplane and nic stats.
 */

#define TIMER_RESOLUTION_CYCLES 20000000ULL	/* around 10ms at 2 Ghz */
#define DP_STATS_TIMER_INTERVAL 4 /* sec */

#define STAT_DISPSIZE 20
/* Timestamp Buffer length */
#define TIMESTAMP_BUF_LEN 32
/* DP Stats filename length */
#define STAT_FILE_NAME_LEN 64
/* Maximum display len */
#define MAX_DPDSP_LEN 108

#define ONE_BILLION 1000000000
#define ONE_MILLION 1000000

/**
 * Enumeration of pkt stat display parameters
 */
enum pktstat_param {
	UL_IFMISPKTS,
	UL_IFPKTS,
	UL_RX,
	UL_TX,
	UL_DFF,
	DL_IFMISPKTS,
	DL_IFPKTS,
	DL_RX,
	DL_TX,
	DL_DFF,
	PKTSTAT_PARAM_MAX
};
struct ul_pkt_stats {
	uint64_t IfPKTS;
	uint64_t IfMisPKTS;
	uint64_t ULRX;
	uint64_t ULTX;
	uint64_t GTP_ECHO;
	uint64_t UL_BYTES;
};
struct dl_pkt_stats {
	uint64_t IfPKTS;
	uint64_t IfMisPKTS;
	uint64_t DLRX;
	uint64_t DLTX;
	uint64_t ddn_pkts;
	uint64_t DL_BYTES;
};

/**
 * Enumeration of mbuf stat display parameters
 */
enum mbfstat_param {
	UL_RX_ALLOC,
	UL_GTPU,
	UL_GTPE,
	UL_KNI,
	UL_BPKT,
	UL_TX_FREE,
	DL_RX_ALLOC,
	DL_DPKT,
	DL_KNI,
	DL_BPKT,
	DL_TX_FREE,
	MBFSTAT_PARAM_MAX
};
struct ul_mbuf_stats {
	uint64_t rx_alloc;
	uint64_t gtpu;
	uint64_t gtp_echo;
	uint64_t kni;
	uint64_t bad_pkt;
	uint64_t tx_free;
};
struct dl_mbuf_stats {
	uint64_t rx_alloc;
	uint64_t dl_pkt;
	uint64_t kni;
	uint64_t bad_pkt;
	uint64_t tx_free;
};

/**
 * Function to display session stats headers
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
void
prn_sesstat_hdrs(void);

/**
 * Function to display DP session stats
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
void disp_sesstats(void);

/**
 * Function to display pkt stats headers
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
void prn_pktstat_hdrs(void);

/**
 * Function to display end to end UL-DL stats
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
void disp_pktstats(void);

/**
 * Function to display traffic stats headers
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
void
prn_trfstat_hdrs(void);

/**
 * Function to display DP traffic stats
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
void disp_trfstats(void);

/**
 * Function to display memory stats headers
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
void prn_mbfstat_hdrs(void);

/**
 * Function to display DP memory stats
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
void disp_mbfstats(void);

/**
 * Function to fill OUT stats for dp memory struct.
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
void dp_mbf_stats(void);

/**
 * Core to print the ngic_rtc stats.
 *
 * @param
 *	Unused
 *
 * @return
 *	None
 */
void epc_stats_core(void);

#endif /* DP_STATS_H */
