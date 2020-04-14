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

#ifndef CP_STATS_H
#define CP_STATS_H
/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes of ngic_rtc controlplane stats.
 */

#include <rte_cycles.h>
#include <rte_timer.h>

#include "gtpv2c.h"

/**
 * @file
 *
 * Control Plane statistic declarations
 */
#define TIMER_RESOLUTION_CYCLES 20000000ULL	/* around 10ms at 2 Ghz */
/* Stats Display Timer Interval */
#define CP_STATS_TIMER_INTERVAL 4

#define STAT_DISPSIZE 20
/* Timestamp Buffer length */
#define TIMESTAMP_BUF_LEN 32
/* CP Stats filename length */
#define STAT_FILE_NAME_LEN 64
/* Maximum CP display len */
#define MAX_CPDSP_LEN 119

#define ONE_BILLION 1000000000
#define ONE_MILLION 1000000

/**
 * Enumeration of Interface Interaction stat display parameters
 */
enum ifistat_param {
	S11_CSREQ,
	S11_CSRSP,
	S11_MBREQ,
	S11_MBRSP,
	S11_RABREQ,
	S11_RABRSP,
	S11_DSREQ,
	S11_DSRSP,
	CUPS_CSREQ,
	CUPS_CSRSP,
	CUPS_MBREQ,
	CUPS_MBRSP,
	CUPS_DSREQ,
	CUPS_DSRSP,
	CUPS_OPID,
	IFISTAT_PARAM_MAX
};

/**
 * @brief counters used to display CP Interface Interaction Statistics
 */
struct ifistats_t {
	uint64_t s11_csreq;
	uint64_t s11_csrsp;
	uint64_t s11_mbreq;
	uint64_t s11_mbrsp;
	uint64_t s11_rabreq;
	uint64_t s11_rabrsp;
	uint64_t s11_dsreq;
	uint64_t s11_dsrsp;
	uint64_t cups_csreq;
	uint64_t cups_csrsp;
	uint64_t cups_mbreq;
	uint64_t cups_mbrsp;
	uint64_t cups_dsreq;
	uint64_t cups_dsrsp;
	uint64_t cups_opid;
};
extern struct ifistats_t ifistats;
extern uint64_t cups_opid_rsp;

/**
 * @brief counters used to display statistics on the control plane
 */
struct cp_stats_t {
	uint64_t time;
	uint64_t create_session;
	uint64_t delete_session;
	uint64_t modify_bearer;
	uint64_t rel_access_bearer;
	uint64_t bearer_resource;
	uint64_t create_bearer;
	uint64_t delete_bearer;
	uint64_t ddn;
	uint64_t ddn_ack;
	uint64_t echo;
	uint64_t rx;
	uint64_t tx;
	uint64_t rx_last;
	uint64_t tx_last;
#ifdef SDN_ODL_BUILD
	uint64_t nb_sent;
	uint64_t nb_ok;
	uint64_t nb_cnr;
#endif /* SDN_ODL_BUILD */
};
extern struct cp_stats_t cp_stats;

/**
 * Prints control plane signaling message statistics
 *
 * @return
 *   Never returns/value ignored
 */
int
do_stats(__rte_unused void *ptr);

/**
 * @brief clears the control plane statistic counters
 */
void
reset_cp_stats(void);

/**
 * Function to display CP session stats
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
void disp_sesstats(void);

/**
 * Function to display end to end Interface Interaction stats
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
void
disp_ifistats(void);

#endif /* CP_STATS_H */
