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

#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <cmdline_socket.h>

#include <rte_cycles.h>
#include <rte_timer.h>

#include "main.h"
#include "dp_stats.h"
#include "dp_commands.h"

#define DEBUG_DDN 0
#define DEFAULT_DP_STATS_PATH "./stats/"

extern struct rte_mempool *user_ulmp;
extern struct rte_mempool *user_dlmp;

char *dp_stats_path = DEFAULT_DP_STATS_PATH;
FILE *stats_file;

struct ul_pkt_stats ul_pkts_dsp = { 0 };
struct dl_pkt_stats dl_pkts_dsp = { 0 };
uint64_t pkt_cnt_quo[PKTSTAT_PARAM_MAX] = {0};
uint64_t pkt_cnt_rem[PKTSTAT_PARAM_MAX] = {0};

struct ul_mbuf_stats ul_mbuf_dsp = { 0 };
struct dl_mbuf_stats dl_mbuf_dsp = { 0 };
uint64_t mbuf_cnt_quo[MBFSTAT_PARAM_MAX] = {0};
uint64_t mbuf_cnt_rem[MBFSTAT_PARAM_MAX] = {0};

uint8_t dp_pstat_cnt = 0, dp_mstat_cnt = 0;
extern struct rte_hash *rte_sess_hash;
extern struct rte_hash *rte_sess_cli_hash;

static struct rte_timer timer0;
uint64_t dp_pvtsc = 0, dp_crtsc, dp_dftsc;

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
prn_sesstat_hdrs(void)
{
	printf("\n\n");
	printf("%s\n", "##NGIC_RTC_DRCT DP Session Stats");
	printf("%9s %9s %9s \n",
			"nb_sess", "ue_addr", "sess_id");

}

/**
 * Function to display DP session stats
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
void
disp_sesstats(void)
{
	const void *next_key;
	void *next_data;
	uint32_t iter = 0, i = 1;
	uint32_t ue_ip;

	while (rte_hash_iterate(rte_sess_cli_hash, &next_key, &next_data, &iter) >= 0) {

			ue_ip = htonl(((dp_sess_strct *)next_data)->ue_addr.u.ipv4_addr);
			printf("%9u %18s %#20lX \n",
					i++,
					inet_ntoa(*(struct in_addr *)(&ue_ip)),
					((dp_sess_strct *)next_data)->sess_id);
	}
}

/**
 * Function to fill IN stats
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
static void
nic_in_stats(void)
{
	struct rte_eth_stats stats0;
	struct rte_eth_stats stats1;
	int ret;

	ret = rte_eth_stats_get(app.s1u_port, &stats0);
	if (ret != 0)
		fprintf(stderr, "Packets are not read from s1u port\n");
	ret = rte_eth_stats_get(app.sgi_port, &stats1);
	if (ret != 0)
		fprintf(stderr, "Packets are not read from sgi port\n");
	{
		ul_pkts_dsp.IfPKTS = stats0.ipackets;
		ul_pkts_dsp.IfMisPKTS = stats0.imissed;

	}
	{
		dl_pkts_dsp.IfPKTS = stats1.ipackets;
		dl_pkts_dsp.IfMisPKTS = stats1.imissed;

	}
}

/**
 * Function to fill IN stats
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
static void
ngic_rtc_in_stats(void)
{

	ul_pkts_dsp.ULRX = epc_app.ul_params[S1U_PORT_ID].pkts_in;
	dl_pkts_dsp.DLRX = epc_app.dl_params[SGI_PORT_ID].pkts_in;
	/* VCCCCB-34 Statistics- Add #of active sessions, RX & TX bytes */
	ul_pkts_dsp.UL_BYTES = epc_app.ul_params[S1U_PORT_ID].tot_ul_bytes;
	dl_pkts_dsp.DL_BYTES = epc_app.dl_params[SGI_PORT_ID].tot_dl_bytes;
#ifdef DP_DDN
	dl_pkts_dsp.ddn_pkts = epc_app.dl_params[SGI_PORT_ID].ddn;
#endif  /* DP_DDN */
#ifdef EXSTATS
	ul_pkts_dsp.GTP_ECHO = epc_app.ul_params[S1U_PORT_ID].pkts_echo;
#endif /* EXSTATS */
}

/**
 * Function to fill OUT stats
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
static void
ngic_rtc_out_stats(void)
{
	ul_pkts_dsp.ULTX = epc_app.ul_params[S1U_PORT_ID].pkts_out;
	dl_pkts_dsp.DLTX = epc_app.dl_params[SGI_PORT_ID].pkts_out;
}

/**
 * Function to display pkt stats headers
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
void
prn_pktstat_hdrs(void)
{
	char buf[MAX_DPDSP_LEN];
	printf("\n\n");
	printf("%s\n", "##NGIC_RTC_DRCT DP Pkt Stats");

#ifdef EXSTATS
	printf("%30s %32s %24s\n", "UPLINK", "||", "DOWNLINK");
	printf("%9s %9s %9s %9s %9s %9s %4s %9s %9s %9s %9s %9s \n",
			"IfMisPKTS", "IfPKTS", "UL-RX", "UL-TX", "UL-DFF", "GTP-ECHO", "||",
			"IfMisPKTS", "IfPKTS", "DL-RX", "DL-TX", "DL-DFF");
#elif DEBUG_DDN
	printf("%24s %29s %24s\n", "UPLINK", "||", "DOWNLINK");
	printf("%9s %9s %9s %9s %9s %4s %9s %9s %9s %9s %9s %9s \n",
			"IfMisPKTS", "IfPKTS", "UL-RX", "UL-TX", "UL-DFF", "||",
			"IfMisPKTS", "IfPKTS", "DL-RX", "DL-TX", "DL-DFF", "DDN");
#else /* !EXSTATS && !DEBUG_DDN */
	printf("%.*s\n",MAX_DPDSP_LEN, (char *) memset(buf, '-', MAX_DPDSP_LEN));
	printf("%30s %19s %32s %17s %6s\n", "UPLINK", "||", "DOWNLINK", "||", "SESS's");
	printf("%9s %9s %9s %9s %6s %3s %9s %9s %9s %9s %6s %3s %6s\n",
			"IfMisPKTS", "IfPKTS", "UL-RX", "UL-TX", "UL-DFF", "||",
			"IfMisPKTS", "IfPKTS", "DL-RX", "DL-TX", "DL-DFF", "||", "Active");
	printf("%7luBn %7luBn %7luBn %7luBn %5luM %3s %7luBn %7luBn %7luBn %7luBn %5luM %3s\n",
			pkt_cnt_quo[UL_IFMISPKTS], pkt_cnt_quo[UL_IFPKTS],
			pkt_cnt_quo[UL_RX], pkt_cnt_quo[UL_TX], pkt_cnt_quo[UL_DFF], "||",
			pkt_cnt_quo[DL_IFMISPKTS], pkt_cnt_quo[DL_IFPKTS],
			pkt_cnt_quo[DL_RX], pkt_cnt_quo[DL_TX], pkt_cnt_quo[DL_DFF], "||");
	printf("%.*s\n",MAX_DPDSP_LEN, (char *) memset(buf, '-', MAX_DPDSP_LEN));
#endif /* (EXSTATS | DEBUG_DDN) */
}

/**
 * Function to update quotient/reminder for UL-DL pkt stats
 *
 * @param
 * type - pkt stats type
 *
 * @return
 * None
 */
static void pktstats_quo_rem(enum pktstat_param type)
{
	uint64_t divisor = ((type == UL_DFF) || (type == DL_DFF)) ?
									ONE_MILLION : ONE_BILLION;
	uint64_t val = 0, quo = 0;

	switch (type) {
		case UL_IFMISPKTS:
			val = ul_pkts_dsp.IfMisPKTS;
			break;
		case UL_IFPKTS:
			val = ul_pkts_dsp.IfPKTS;
			break;
		case UL_RX:
			val = ul_pkts_dsp.ULRX;
			break;
		case UL_TX:
			val = ul_pkts_dsp.ULTX;
			break;
		case UL_DFF:
			val = ul_pkts_dsp.ULRX - ul_pkts_dsp.ULTX;
			break;
		case DL_IFMISPKTS:
			val = dl_pkts_dsp.IfMisPKTS;
			break;
		case DL_IFPKTS:
			val = dl_pkts_dsp.IfPKTS;
			break;
		case DL_RX:
			val = dl_pkts_dsp.DLRX;
			break;
		case DL_TX:
			val = dl_pkts_dsp.DLTX;
			break;
		case DL_DFF:
			val = dl_pkts_dsp.DLRX - dl_pkts_dsp.DLTX;
			break;
		default:
			printf("Invalid Disp Params\n");
			break;
	}
	quo = val/divisor;
	if (quo != pkt_cnt_quo[type])
		dp_pstat_cnt=0;
	pkt_cnt_quo[type] = quo;
	pkt_cnt_rem[type] = val%divisor;
}

/**
 * Function to display end to end UL-DL stats
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
void
disp_pktstats(void)
{
	const void *next_key;
	void *next_data;
	uint32_t iter = 0;
	uint64_t i = 0;
	char buf[TIMESTAMP_BUF_LEN] = {0};
	time_t rawtime = time(NULL);
	struct tm *ptm = localtime(&rawtime);
	strftime(buf, TIMESTAMP_BUF_LEN, "%y%m%d%H%M%S", ptm);

	if (rfrsh_pstats == 1) {
		printf("\n");
		rfrsh_pstats = 0;
	}

	for (i = 0; i < PKTSTAT_PARAM_MAX; i++)
		pktstats_quo_rem((enum pktstat_param)i);

	i = 0;
	while (rte_hash_iterate(rte_sess_cli_hash, &next_key, &next_data, &iter) >= 0) {
		i++;
	}
	/* Check If header's to be printed */
	if(dp_pstat_cnt == 0 || dp_pstat_cnt == STAT_DISPSIZE) {
		prn_pktstat_hdrs();
		if(dp_pstat_cnt == STAT_DISPSIZE)
			dp_pstat_cnt=1;
	}
	dp_pstat_cnt++;
#ifdef EXSTATS
	printf("%9lu %9lu %9lu %9lu %9lu %9lu %4s %9lu %9lu %9lu %9lu %9lu \n",
			ul_pkts_dsp.IfMisPKTS, ul_pkts_dsp.IfPKTS, ul_pkts_dsp.ULRX, ul_pkts_dsp.ULTX,
			(ul_pkts_dsp.ULRX - ul_pkts_dsp.ULTX), ul_pkts_dsp.GTP_ECHO,  "||",
			dl_pkts_dsp.IfMisPKTS, dl_pkts_dsp.IfPKTS, dl_pkts_dsp.DLRX, dl_pkts_dsp.DLTX,
			(dl_pkts_dsp.DLRX - dl_pkts_dsp.DLTX));
#elif DEBUG_DDN
	printf("%9lu %9lu %9lu %9lu %9lu %4s %9lu %9lu %9lu %9lu %9lu %9lu \n",
			ul_pkts_dsp.IfMisPKTS, ul_pkts_dsp.IfPKTS, ul_pkts_dsp.ULRX, ul_pkts_dsp.ULTX,
			(ul_pkts_dsp.ULRX - ul_pkts_dsp.ULTX), "||",
			dl_pkts_dsp.IfMisPKTS, dl_pkts_dsp.IfPKTS, dl_pkts_dsp.DLRX, dl_pkts_dsp.DLTX,
			(dl_pkts_dsp.DLRX - dl_pkts_dsp.DLTX), dl_pkts_dsp.ddn_pkts);
#else /* !EXSTATS && !DEBUG_DDN */
	printf("%9lu %9lu %9lu %9lu %6lu %3s %9lu %9lu %9lu %9lu %6lu %3s %6lu\n",
			pkt_cnt_rem[UL_IFMISPKTS], pkt_cnt_rem[UL_IFPKTS],
			pkt_cnt_rem[UL_RX], pkt_cnt_rem[UL_TX], pkt_cnt_rem[UL_DFF], "||",
			pkt_cnt_rem[DL_IFMISPKTS], pkt_cnt_rem[DL_IFPKTS],
			pkt_cnt_rem[DL_RX], pkt_cnt_rem[DL_TX], pkt_cnt_rem[DL_DFF], "||",
			i);
#endif  /* (EXSTATS | DEBUG_DDN) */
	/* Write DP stats into stat file */
	if (fprintf(stats_file, "%s,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu\n",
			buf, ul_pkts_dsp.IfMisPKTS, ul_pkts_dsp.IfPKTS, ul_pkts_dsp.ULRX,
			ul_pkts_dsp.ULTX, (ul_pkts_dsp.ULRX - ul_pkts_dsp.ULTX),
			ul_pkts_dsp.UL_BYTES, dl_pkts_dsp.IfMisPKTS, dl_pkts_dsp.IfPKTS,
			dl_pkts_dsp.DLRX, dl_pkts_dsp.DLTX,
			(dl_pkts_dsp.DLRX - dl_pkts_dsp.DLTX), dl_pkts_dsp.DL_BYTES, i) < 0)
		printf("%s [%d] fprintf(stats_file write failed -"
			" %s (%d)\n",
			__FILE__, __LINE__, strerror(errno), errno);
	if (fflush(stats_file))
		printf("%s [%d] fflush(dp stats file failed - %s (%d)\n",
			__FILE__, __LINE__, strerror(errno), errno);
}

/**
 * Function to display DP traffic stats headers for CLI
 *
 * @param
 * Void
 *
 * @return
 * None
 */
void
prn_trfstat_hdrs(void)
{
	printf("\n\n");
	printf("%s\n", "##NGIC_RTC_DRCT DP Traffic Stats");
	printf("%9s %9s %9s %9s \n",
			"Session_ID", "ue_addr", "RX Bytes", "TX Bytes");
}

/**
 * Function to display DP Traffic stats
 *
 * @param
 *  void
 *
 * @return
 *  None
 **/
void
disp_trfstats(void)
{
	uint32_t ue_ip;
	const void *next_key;
	void *next_data;
	uint32_t iter = 0;

	while (rte_hash_iterate(rte_sess_hash, &next_key, &next_data, &iter) >= 0) {
		struct dp_session_info *tmp_dp_sess_info =
			(struct dp_session_info *)next_data;
		ue_ip = htonl(tmp_dp_sess_info->ue_addr.u.ipv4_addr);
		printf("%#9lX %9s %9lu %9lu\n",
				tmp_dp_sess_info->sess_id,
				inet_ntoa(*(struct in_addr *)(&ue_ip)),
				tmp_dp_sess_info->ipcan_dp_bearer_cdr.data_vol.\
				dl_cdr.bytes,
				tmp_dp_sess_info->ipcan_dp_bearer_cdr.data_vol.\
				ul_cdr.bytes
			  );
	}
}

/**
 * Function to display DP memory stats headers
 *
 * @param
 *  void
 *
 * @return
 *  None
 */
void
prn_mbfstat_hdrs(void)
{
	char buf[MAX_DPDSP_LEN];
	printf("\n\n");
	printf("%s\n", "##NGIC_RTC_DRCT DP Memory Stats");

	printf("%.*s\n",MAX_DPDSP_LEN, (char *) memset(buf, '-', MAX_DPDSP_LEN));
	printf("%26s %27s %26s\n", "UPLINK MBUFS", "||", "DOWNLINK MBUFS");
	printf("%9s %9s %6s %7s %4s %9s %4s %9s %9s %7s %4s %9s\n",
			"RX-ALLOC", "GTPU",
			"GTPE", "KNI", "BPKT", "TX+FREE", "||",
			"RX-ALLOC", "DL_PKT", "KNI", "BPKT", "TX+FREE");
	printf("%7luBn %7luBn %5luM %5luM %5luM %7luBn %3s %7luBn %7luBn %5luM %5luM %7luBn\n",
			mbuf_cnt_quo[UL_RX_ALLOC], mbuf_cnt_quo[UL_GTPU],
			mbuf_cnt_quo[UL_GTPE], mbuf_cnt_quo[UL_KNI],
			mbuf_cnt_quo[UL_BPKT], mbuf_cnt_quo[UL_TX_FREE],"||",
			mbuf_cnt_quo[DL_RX_ALLOC], mbuf_cnt_quo[DL_PKT],
			mbuf_cnt_quo[DL_KNI], mbuf_cnt_quo[DL_BPKT], mbuf_cnt_quo[DL_TX_FREE]);
	printf("%.*s\n",MAX_DPDSP_LEN, (char *) memset(buf, '-', MAX_DPDSP_LEN));
}

/**
 * Function to update quotient/reminder for UL-DL mbuf stats
 *
 * @param
 * type - mbuf stats type
 *
 * @return
 * None
 */
static void mbfstats_quo_rem(enum mbfstat_param type)
{
	uint64_t val = 0, divisor = 0, quo = 0;

	switch (type) {
		case UL_RX_ALLOC:
			divisor = ONE_BILLION;
			val = ul_mbuf_dsp.rx_alloc;
			break;
		case UL_GTPU:
			divisor = ONE_BILLION;
			val = ul_mbuf_dsp.gtpu;
			break;
		case UL_GTPE:
			divisor = ONE_MILLION;
			val = ul_mbuf_dsp.gtp_echo;
			break;
		case UL_KNI:
			divisor = ONE_MILLION;
			val = ul_mbuf_dsp.kni;
			break;
		case UL_BPKT:
			divisor = ONE_MILLION;
			val = ul_mbuf_dsp.bad_pkt;
			break;
		case UL_TX_FREE:
			divisor = ONE_BILLION;
			val = ul_mbuf_dsp.tx_free;
			break;
		case DL_RX_ALLOC:
			divisor = ONE_BILLION;
			val = dl_mbuf_dsp.rx_alloc;
			break;
		case DL_DPKT:
			divisor = ONE_BILLION;
			val = dl_mbuf_dsp.dl_pkt;
			break;
		case DL_KNI:
			divisor = ONE_MILLION;
			val = dl_mbuf_dsp.kni;
			break;
		case DL_BPKT:
			divisor = ONE_MILLION;
			val = dl_mbuf_dsp.bad_pkt;
			break;
		case DL_TX_FREE:
			divisor = ONE_BILLION;
			val = dl_mbuf_dsp.tx_free;
			break;
		default:
			printf("Invalid Disp Params\n");
			break;
	}
	quo = val/divisor;
	if (quo != mbuf_cnt_quo[type])
		dp_mstat_cnt=0;
	mbuf_cnt_quo[type] = quo;
	mbuf_cnt_rem[type] = val%divisor;
}

/**
 * Function to display DP memory stats
 *
 * @param
 *  void
 *
 * @return
 *  None
 */
void
disp_mbfstats(void)
{
	if (rfrsh_mstats == 1) {
		printf("\n");
		rfrsh_mstats = 0;
	}

	for (uint8_t i = UL_RX_ALLOC; i < MBFSTAT_PARAM_MAX; i++)
		mbfstats_quo_rem((enum mbfstat_param)i);

#ifdef FOR_REF
	printf("%9u %9u %6u %7u %4u %9u %4s %9u %9u %7u %4u %9u\n",
			ul_mbuf_dsp.rx_alloc, ul_mbuf_dsp.gtpu,
			ul_mbuf_dsp.gtp_echo, ul_mbuf_dsp.kni, ul_mbuf_dsp.bad_pkt, ul_mbuf_dsp.tx_free, "||",
			dl_mbuf_dsp.rx_alloc, dl_mbuf_dsp.dl_pkt,
			dl_mbuf_dsp.kni, dl_mbuf_dsp.bad_pkt, dl_mbuf_dsp.tx_free);
#endif /* FOR_REF */

	printf("%9lu %9lu %6lu %7lu %4lu %9lu %4s %9lu %9lu %7lu %4lu %9lu\n",
			mbuf_cnt_rem[UL_RX_ALLOC], mbuf_cnt_rem[UL_GTPU],
			mbuf_cnt_rem[UL_GTPE], mbuf_cnt_rem[UL_KNI],
			mbuf_cnt_rem[UL_BPKT], mbuf_cnt_rem[UL_TX_FREE], "||",
			mbuf_cnt_rem[DL_RX_ALLOC], mbuf_cnt_rem[DL_DPKT],
			mbuf_cnt_rem[DL_KNI], mbuf_cnt_rem[DL_BPKT], mbuf_cnt_rem[DL_TX_FREE]);
}

/**
 * Function to fill OUT stats for dp memory struct.
 *
 * @param
 *  void
 *
 * @return
 *  None
 */
void
dp_mbf_stats(void)
{
	ul_mbuf_dsp.rx_alloc = epc_app.ul_params[S1U_PORT_ID].ul_mbuf_rtime.rx_alloc;
	ul_mbuf_dsp.gtpu = epc_app.ul_params[S1U_PORT_ID].ul_mbuf_rtime.gtpu;
	ul_mbuf_dsp.gtp_echo = epc_app.ul_params[S1U_PORT_ID].ul_mbuf_rtime.gtp_echo;
	ul_mbuf_dsp.kni = epc_app.ul_params[S1U_PORT_ID].ul_mbuf_rtime.kni;
	ul_mbuf_dsp.bad_pkt = epc_app.ul_params[S1U_PORT_ID].ul_mbuf_rtime.bad_pkt;
	ul_mbuf_dsp.tx_free = epc_app.ul_params[S1U_PORT_ID].ul_mbuf_rtime.tx_free;

	dl_mbuf_dsp.rx_alloc = epc_app.dl_params[SGI_PORT_ID].dl_mbuf_rtime.rx_alloc;
	dl_mbuf_dsp.dl_pkt = epc_app.dl_params[SGI_PORT_ID].dl_mbuf_rtime.dl_pkt;
	dl_mbuf_dsp.kni = epc_app.dl_params[SGI_PORT_ID].dl_mbuf_rtime.kni;
	dl_mbuf_dsp.bad_pkt = epc_app.dl_params[SGI_PORT_ID].dl_mbuf_rtime.bad_pkt;
	dl_mbuf_dsp.tx_free = epc_app.dl_params[SGI_PORT_ID].dl_mbuf_rtime.tx_free;
}

static void timer_cb(__attribute__ ((unused))
		struct rte_timer *tim, __attribute__ ((unused))void *arg)
{
	static unsigned pkt_statcntr;
	static unsigned dd_statcntr;
	if (pktstats_flg == 1) {
		/* Display pkt stats on cmdline pktstats option */
		nic_in_stats();
		ngic_rtc_in_stats();
		ngic_rtc_out_stats();
		disp_pktstats();
		/* this timer is automatically reloaded until we decide to
		 * stop it, when pkt_statcntr reaches 500. */
		if ((pkt_statcntr++) == 500) {
			/* rte_timer_stop(tim); */
		}
	}
	if (sesstats_flg == 1) {
		/* Display session stats on cmdline sesstats options */
		prn_sesstat_hdrs();
		disp_sesstats();
		sesstats_flg = 0;
	}
	if (mbfstats_flg == 1) {
		/* Display mbf stats on cmdline mbfstats option */
		dp_mbf_stats();
		if(dp_mstat_cnt == 0 || dp_mstat_cnt == STAT_DISPSIZE) {
			prn_mbfstat_hdrs();
			if(dp_mstat_cnt == STAT_DISPSIZE)
				dp_mstat_cnt=1;
		}
		disp_mbfstats();
		dp_mstat_cnt++;
	}
	if (trfstats_flg == 1) {
		/* VCCCCB-34 Statistics- Add #of active sessions, RX & TX bytes */
		/* Display traffic stats:
		 * Session_ID | ue_addr | RX Bytes | TX Bytes */
		prn_trfstat_hdrs();
		disp_trfstats();
		trfstats_flg = 0;
		/* this timer is automatically reloaded until we decide to
		 *       * stop it, when ss_statcntr reaches 500. */
		if ((dd_statcntr++) == 500) {
			/* rte_timer_stop(tim); */
		}
	}
}

/**
 * Function to create DP stats file
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
void create_stats_file()
{
	char filename[STAT_FILE_NAME_LEN];
	char timestamp[TIMESTAMP_BUF_LEN];
	int ret;
	time_t t = time(NULL);
	struct tm *tmp = localtime(&t);
	DIR *cdr_dir = opendir("./stats");

	if (cdr_dir)
		closedir(cdr_dir);
	else if (errno == ENOENT) {
		errno = 0;
		//Create stats directory with permission 755
		mkdir("./stats", S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
	}

	memset(filename, 0, STAT_FILE_NAME_LEN);
	memset(timestamp, 0, TIMESTAMP_BUF_LEN);
	ret = strftime(timestamp, TIMESTAMP_BUF_LEN, "%Y%m%d%H%M%S", tmp);
	if (ret == 0)
		printf("Failed to generate STATS timestamp\n");

	ret = snprintf(filename, STAT_FILE_NAME_LEN, "%s%s_DP_STATS.csv", dp_stats_path, timestamp);
	if (ret < 0)
		printf("output error during DP stats filename creation\n");

	printf("Create DP Stats file: %s\n", filename);

	stats_file = fopen(filename, "w");
	if (!stats_file)
		printf("DP stats file %s failed to open for writing\n"
				" - %s (%d)",
				filename, strerror(errno), errno);

	if (fprintf(stats_file, "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
			"TIMESTAMP", "UL-IfMisPKTS", "UL-IfPKTS", "UL-RX", "UL-TX",
			"UL-DFF", "UL-Bytes", "DL-IfMisPKTS", "DL-IfPKTS", "DL-RX",
			"DL-TX", "DL-DFF", "DL-Bytes", "ActiveSessions") < 0)
		printf("%s [%d] fprintf(stats_file header failed -"
			" %s (%d)\n",
			__FILE__, __LINE__, strerror(errno), errno);
	if (fflush(stats_file))
		printf("%s [%d] fflush(dp stats file failed - %s (%d)\n",
			__FILE__, __LINE__, strerror(errno), errno);
}

void epc_stats_core(void)
{
	/* init timer structures */
	static uint8_t start_timer = 1;
	/* NGIC_RTC_DRCT: this function would be invoked in an
	 * infinite loop. Initialize timer parameters only once */
	if (start_timer == 1) {
		/* create DP Stats file */
		create_stats_file();

		rte_timer_init(&timer0);

		/* load timer0, every second, on master lcore, reloaded automatically */
		uint64_t hz = rte_get_timer_hz();
		unsigned lcore_id = rte_lcore_id();
		rte_timer_reset(&timer0, hz * DP_STATS_TIMER_INTERVAL, PERIODICAL, lcore_id,
				timer_cb, NULL);
		start_timer = 0;
	}
	dp_crtsc = rte_rdtsc();
	dp_dftsc = dp_crtsc - dp_pvtsc;
	if (dp_dftsc > TIMER_RESOLUTION_CYCLES) {
		rte_timer_manage();
		dp_pvtsc = dp_crtsc;
	}

	/* Enabling DP CLI */
	int status;
	static int cmd_ready;

	if (cmd_ready == 0) {
		ngicdp_cl = rte_malloc_socket(NULL,
						sizeof(struct cmdline),
						RTE_CACHE_LINE_SIZE, rte_socket_id());
		ngicdp_cl = cmdline_stdin_new(main_ctx, "ngic-rtc-dp>");
		if (ngicdp_cl == NULL)
			rte_panic("Cannot create cmdline instance\n");
		/* Initialize CLI Session */
		sesstats_flg = 0;
		pktstats_flg = 1;
		trfstats_flg = 0;
		mbfstats_flg = 0;
		rfrsh_pstats = 0;
		cmdline_printf(ngicdp_cl, "\nCommands supported:"
				"\n\t- s= toggle session stats"
				"\n\t- p= toggle pktstats"
				"\n\t- d= toggle traffic stats"
				"\n\t- m= toggle memory stats"
				"\n\t- q= quit CLI"
				"\n\t- h= help");
		if (pktstats_flg == 1)
			printf("\n\tDefault pktstats enabled...\n");
		else if (sesstats_flg == 1)
			printf("\n\tDefault session stats enabled...\n");
		else
			printf("\n");
		cmdline_stdin_new(main_ctx, "ngic-rtc-dp>");
		cmd_ready = 1;
	}

	status = cmdline_poll(ngicdp_cl);
	if (status < 0)
		rte_panic("CLI poll error (%" PRId32 ")\n", status);
	else if (status == RDLINE_EXITED) {
		cmdline_stdin_exit(ngicdp_cl);
		rte_exit(0, NULL);
	}
}
