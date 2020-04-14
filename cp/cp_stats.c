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

#include <sys/stat.h>
#include <dirent.h>
#include <cmdline_socket.h>

#ifdef SDN_ODL_BUILD
#include "nb.h"
#endif /* SDN_ODL_BUILD */

#include "cp_stats.h"
#include "cp_commands.h"
#include "ue.h"

#define DEFAULT_CP_STATS_PATH "./stats/"

const char *cp_stats_path = DEFAULT_CP_STATS_PATH;
FILE *stats_file;

uint64_t ifi_cnt_quo[IFISTAT_PARAM_MAX] = {0};
uint64_t ifi_cnt_rem[IFISTAT_PARAM_MAX] = {0};

uint8_t ifistat_cnt = 0, mstat_cnt = 0;
uint8_t ifistats_flg = 1;

/* ASR- Note:
 * CP::Master Core counts::ifistats.cups_opid
 * CP::iface Core counts::cups_opid_rsp */
struct ifistats_t ifistats = {0};
uint64_t cups_opid_rsp = 0;
struct cp_stats_t cp_stats = {0};

static struct rte_timer timer0;
uint64_t cp_pvtsc = 0, cp_crtsc, cp_dftsc;

/**
 * Function to display CP session stats headers for CLI
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
static void
prn_sesstat_hdrs(void)
{
	char buf[MAX_CPDSP_LEN];
	printf("\n\n");
	printf("%s\n", "##NGIC_RTC_DRCT CP Session Stats");

	printf("%.*s\n",MAX_CPDSP_LEN, (char *) memset(buf, '-', MAX_CPDSP_LEN));
	printf("%14s %16s %16s %16s \n",
			"SESS's Active", "UE_IP", "IMSI", "MSISDN");
	printf("%.*s\n",MAX_CPDSP_LEN, (char *) memset(buf, '-', MAX_CPDSP_LEN));
}

/**
 * Function to display CP session stats
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
	uint8_t j, k;
	const void *next_key;
	void *next_data;
	uint32_t iter = 0, i = 0;
	int32_t ret, hash_res = 0;
	uint32_t ue_ip;
	uint64_t imsi;
	uint64_t msisdn;
	char user_inp;
	char buf[MAX_CPDSP_LEN];

	do {
		prn_sesstat_hdrs();
		for (j = 0;  j < STAT_DISPSIZE; j++){
			hash_res =
				rte_hash_iterate(ue_context_by_imsi_hash, &next_key, &next_data, &iter);
			if (hash_res == -ENOENT) {
				printf("Session Table End...\n");
				break;
			}
			ue_ip = htonl(((ue_context *)next_data)->dp_session->ue_addr.u.ipv4_addr);
			imsi = ((ue_context *)next_data)->imsi;
//			*((uint8_t *)(&imsi) + APN_IMSI_KEY_POSTN) =
//				*((uint8_t *)(&imsi) + APN_IMSI_KEY_POSTN) >>
//				APN_IMSI_KEY_LEN | APN_IMSI_SHIFT_VAL;

			printf("%14u %16s %16lu %2s",
					i++, inet_ntoa(*(struct in_addr *)(&ue_ip)), imsi, " ");
			for (k = 0; k < BINARY_MSISDN_LEN; k++) {
				*((int8_t *)&msisdn + k) = *(int8_t *)(((ue_context *)next_data)->msisdn + k);
			}
			printf("%16lu\n", msisdn);
		}
		printf("Any Key= Continue; X= Exit\n");
		ret = scanf("%c", &user_inp);
		if (ret != EOF && user_inp == 'X') {
			break;
		}
		prn_sesstat_hdrs();
	} while (hash_res >= 0);
	sesstats_flg = 0;        /* Disable sesstats */
	printf("%.*s\n",MAX_CPDSP_LEN, (char *) memset(buf, '-', MAX_CPDSP_LEN));
	printf("\n%9s %9u\n", "Total #of Active Sessions\t", i);
	printf("%.*s\n\n",MAX_CPDSP_LEN, (char *) memset(buf, '-', MAX_CPDSP_LEN));
}

/**
 * Function to display Interface Interaction stats headers
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
static void
prn_ifistat_hdrs(void)
{
	char buf[MAX_CPDSP_LEN];
	printf("\n\n");
	printf("%s\n", "##NGIC_RTC_DRCT CP Interface Interaction Stats");

	printf("%.*s\n",MAX_CPDSP_LEN, (char *) memset(buf, '-', MAX_CPDSP_LEN));
	printf("%32s %27s %25s %25s %6s\n", "S11", "||", "CUPS", "||", "SESS's");
	printf("%7s %6s %6s %6s %6s %6s %6s %6s %3s"
			"%6s %6s %6s %6s %6s %6s %6s %3s %6s\n",
			"CS_RQ", "CS_RS", "MB_RQ", "MB_RS",
			"RAB_RQ", "RAB_RS", "DS_RQ", "DS_RS", "||",
			"CS_RQ", "CS_RS", "MB_RQ", "MB_RS",
			"DS_RQ", "DS_RS", "OP_ID", "||", "Active");
	printf("%6luM %5luM %5luM %5luM %5luM %5luM %5luM %5luM %3s"
			"%5luM %5luM %5luM %5luM %5luM %5luM %5luM %3s\n",
			ifi_cnt_quo[S11_CSREQ], ifi_cnt_quo[S11_CSRSP],
			ifi_cnt_quo[S11_MBREQ], ifi_cnt_quo[S11_MBRSP],
			ifi_cnt_quo[S11_RABREQ], ifi_cnt_quo[S11_RABRSP],
			ifi_cnt_quo[S11_DSREQ], ifi_cnt_quo[S11_DSRSP], "||",
			ifi_cnt_quo[CUPS_CSREQ], ifi_cnt_quo[CUPS_CSRSP],
			ifi_cnt_quo[CUPS_MBREQ], ifi_cnt_quo[CUPS_MBRSP],
			ifi_cnt_quo[CUPS_DSREQ], ifi_cnt_quo[CUPS_DSRSP],
			ifi_cnt_quo[CUPS_OPID], "||");
	printf("%.*s\n",MAX_CPDSP_LEN, (char *) memset(buf, '-', MAX_CPDSP_LEN));
}

static void
ngic_rtc_s11_stats(void)
{
	ifistats.s11_csreq = cp_stats.create_session;
	ifistats.s11_mbreq = cp_stats.modify_bearer;
	ifistats.s11_dsreq = cp_stats.delete_session;
}

static void
ngic_rtc_cups_stats(void)
{

}

/**
 * Function to update Interface Interactions quotient/reminder stats
 *
 * @param
 * type - ifistats type
 *
 * @return
 * None
 */
static void ifistats_quo_rem(enum ifistat_param type)
{
//	const void *next_key;
//	void *next_data;
//	uint32_t iter =0, i = 0;
	uint64_t divisor = ONE_MILLION;
	uint64_t val = 0, quo = 0;

	switch (type) {
		case S11_CSREQ:
			val = ifistats.s11_csreq;
			break;
		case S11_CSRSP:
			val = ifistats.s11_csrsp;
			break;
		case S11_MBREQ:
			val = ifistats.s11_mbreq;
			break;
		case S11_MBRSP:
			val = ifistats.s11_mbrsp;
			break;
		case S11_RABREQ:
			val = ifistats.s11_rabreq;
			break;
		case S11_RABRSP:
			val = ifistats.s11_rabrsp;
			break;
		case S11_DSREQ:
			val = ifistats.s11_dsreq;
			break;
		case S11_DSRSP:
			val = ifistats.s11_dsrsp;
			break;
		case CUPS_CSREQ:
			val = ifistats.cups_csreq;
			break;
		case CUPS_CSRSP:
			val = ifistats.cups_csrsp;
			break;
		case CUPS_MBREQ:
			val = ifistats.cups_mbreq;
			break;
		case CUPS_MBRSP:
			val = ifistats.cups_mbrsp;
			break;
		case CUPS_DSREQ:
			val = ifistats.cups_dsreq;
			break;
		case CUPS_DSRSP:
			val = ifistats.cups_dsrsp;
			break;
		case CUPS_OPID:
			/* ASR- Note:
			 * CP::Master Core counts::ifistats.cups_opid
			 * CP::iface Core counts::cups_opid_rsp */
			val = ifistats.cups_opid - cups_opid_rsp;
//			val = cups_opid_rsp;
//			val = rte_hash_count(resp_op_id_hash);
//			while (rte_hash_iterate(resp_op_id_hash, &next_key, &next_data, &iter) >= 0) {
//				i++;
//			}
			break;
		default:
			printf("Invalid Disp Params\n");
			break;
	}
	quo = val/divisor;
	if (quo != ifi_cnt_quo[type])
		ifistat_cnt=0;
	ifi_cnt_quo[type] = quo;
	ifi_cnt_rem[type] = val%divisor;
}

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
disp_ifistats(void)
{
	const void *next_key;
	void *next_data;
	uint32_t iter = 0, i = 0;
//	char buf[TIMESTAMP_BUF_LEN] = {0};
//	time_t rawtime = time(NULL);
//	struct tm *ptm = localtime(&rawtime);
//	strftime(buf, TIMESTAMP_BUF_LEN, "%y%m%d%H%M%S", ptm);

	if (rfrsh_istats == 1) {
		printf("\n");
		rfrsh_istats = 0;
	}

	for (i = S11_CSREQ; i < IFISTAT_PARAM_MAX; i++)
		ifistats_quo_rem((enum ifistat_param)i);

	i = 0;
	while (rte_hash_iterate(ue_context_by_imsi_hash, &next_key, &next_data, &iter) >= 0) {
		i++;
	}
	/* Check If header's to be printed */
	if(ifistat_cnt == 0 || ifistat_cnt == STAT_DISPSIZE) {
		prn_ifistat_hdrs();
		if(ifistat_cnt == STAT_DISPSIZE)
			ifistat_cnt=1;
	}
	ifistat_cnt++;

	printf("%7lu %6lu %6lu %6lu %6lu %6lu %6lu %6lu %3s"
			"%6lu %6lu %6lu %6lu %6lu %6lu %6lu %3s %6u\n",
			ifi_cnt_rem[S11_CSREQ], ifi_cnt_rem[S11_CSRSP],
			ifi_cnt_rem[S11_MBREQ], ifi_cnt_rem[S11_MBRSP],
			ifi_cnt_rem[S11_RABREQ], ifi_cnt_rem[S11_RABRSP],
			ifi_cnt_rem[S11_DSREQ], ifi_cnt_rem[S11_DSRSP], "||",
			ifi_cnt_rem[CUPS_CSREQ], ifi_cnt_rem[CUPS_CSRSP],
			ifi_cnt_rem[CUPS_MBREQ], ifi_cnt_rem[CUPS_MBRSP],
			ifi_cnt_rem[CUPS_DSREQ], ifi_cnt_rem[CUPS_DSRSP],
			ifi_cnt_rem[CUPS_OPID], "||", i);

	/* Write CP Interface Iteraction stats into stat file */
//	if (fprintf(stats_file, "%s,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu\n",
//			buf, ul_pkts_dsp.IfMisPKTS, ul_pkts_dsp.IfPKTS, ul_pkts_dsp.ULRX,
//			ul_pkts_dsp.ULTX, (ul_pkts_dsp.ULRX - ul_pkts_dsp.ULTX),
//			ul_pkts_dsp.UL_BYTES, dl_pkts_dsp.IfMisPKTS, dl_pkts_dsp.IfPKTS,
//			dl_pkts_dsp.DLRX, dl_pkts_dsp.DLTX,
//			(dl_pkts_dsp.DLRX - dl_pkts_dsp.DLTX), dl_pkts_dsp.DL_BYTES, i) < 0)
//		printf("%s [%d] fprintf(stats_file write failed -"
//			" %s (%d)\n",
//			__FILE__, __LINE__, strerror(errno), errno);
//	if (fflush(stats_file))
//		printf("%s [%d] fflush(dp stats file failed - %s (%d)\n",
//			__FILE__, __LINE__, strerror(errno), errno);
}

/**
 * @brief callback used to display rx packets per second
 * @return number of packets received by the control plane s11 interface
 */
static uint64_t
rx_pkts_per_sec(void)
{
	uint64_t ret = cp_stats.rx - cp_stats.rx_last;

	cp_stats.rx_last = cp_stats.rx;
	return ret;
}

/**
 * @brief callback used to display tx packets per second
 * @return number of packets transmitted by the control plane s11 interface
 */
static uint64_t
tx_pkts_per_sec(void)
{
	uint64_t ret = cp_stats.tx - cp_stats.tx_last;

	cp_stats.tx_last = cp_stats.tx;
	return ret;
}

/**
 * @brief callback used to display control plane uptime
 * @return control plane uptime in seconds
 */
static uint64_t
stats_time(void)
{
	uint64_t ret = cp_stats.time;

	cp_stats.time++;
	return ret;
}

#ifdef SDN_ODL_BUILD
static uint64_t
nb_ok_delta(void)
{
	uint64_t nb_ok = cp_stats.nb_ok;
	uint64_t nb_sent = cp_stats.nb_sent;
	return (nb_ok < nb_sent ? nb_sent - nb_ok : 0);
}

static uint64_t
nb_cnr_delta(void)
{
	uint64_t nb_cnr = cp_stats.nb_cnr;
	uint64_t nb_sent = cp_stats.nb_sent;
	return (nb_cnr < nb_sent ? nb_sent - nb_cnr : 0);
}
#endif /* SDN_ODL_BUILD */

/**
 * @brief statistics entry
 * used to simplify statistics by providing a common interface for statistic
 * values or calculations and their names
 */
struct stat_entry_t {
	enum {VALUE, LAMBDA} type;
	uint8_t spacing;	/** variable length stat entry specifier */
	union {
		uint64_t *value;	/** value used by stat */
		uint64_t (*lambda)(void);	/** stat callback function */
	};
	const char *top;	/** top collumn stat name string */
	const char *bottom;	/** bottom collumn stat name string */
};

#define DEFINE_VALUE_STAT(spacing, function, top, bottom) \
	{VALUE, spacing, {.value = function}, top, bottom}
#define DEFINE_LAMBDA_STAT(spacing, function, top, bottom) \
	{LAMBDA, spacing, {.lambda = function}, top, bottom}
#define PRINT_STAT_ENTRY_HEADER(entry_index, header) \
		printf("%*s ",\
			stat_entries[entry_index].spacing, \
			stat_entries[entry_index].header)

/**
 * statistic entry definitions
 */
struct stat_entry_t stat_entries[] = {
	DEFINE_LAMBDA_STAT(5, stats_time, "", "time"),
	DEFINE_VALUE_STAT(8, &cp_stats.rx, "rx", "pkts"),
	DEFINE_VALUE_STAT(8, &cp_stats.tx, "tx", "pkts"),
	DEFINE_LAMBDA_STAT(8, rx_pkts_per_sec, "rx pkts", "/sec"),
	DEFINE_LAMBDA_STAT(8, tx_pkts_per_sec, "tx pkts", "/sec"),
	DEFINE_VALUE_STAT(8, &cp_stats.create_session, "create", "session"),
	DEFINE_VALUE_STAT(8, &cp_stats.modify_bearer, "modify", "bearer"),
	DEFINE_VALUE_STAT(8, &cp_stats.bearer_resource, "b resrc", "cmd"),
	DEFINE_VALUE_STAT(8, &cp_stats.create_bearer, "create", "bearer"),
	DEFINE_VALUE_STAT(8, &cp_stats.delete_bearer, "delete", "bearer"),
	DEFINE_VALUE_STAT(8, &cp_stats.delete_session, "delete", "session"),
	DEFINE_VALUE_STAT(8, &cp_stats.echo, "", "echo"),
	DEFINE_VALUE_STAT(8, &cp_stats.rel_access_bearer, "rel acc", "bearer"),
	DEFINE_VALUE_STAT(8, &cp_stats.ddn, "",	"ddn"),
	DEFINE_VALUE_STAT(8, &cp_stats.ddn_ack, "ddn", "ack"),
#ifdef SDN_ODL_BUILD
	DEFINE_VALUE_STAT(8, &cp_stats.nb_sent, "nb", "sent"),
	DEFINE_LAMBDA_STAT(8, nb_ok_delta, "nb ok", "delta"),
	DEFINE_LAMBDA_STAT(8, nb_cnr_delta, "nb cnr", "delta"),
#endif /* SDN_ODL_BUILD */
};

/**
 * @brief prints out statistics entries
 */
static inline void
print_stat_entries(void) {
	unsigned i;
	char buf[TIMESTAMP_BUF_LEN] = {0};
	time_t rawtime = time(NULL);
	struct tm *ptm = localtime(&rawtime);
	strftime(buf, TIMESTAMP_BUF_LEN, "%y%m%d%H%M%S", ptm);

	if (!(cp_stats.time % 32)) {
		puts("");
		for (i = 0; i < RTE_DIM(stat_entries); ++i)
			PRINT_STAT_ENTRY_HEADER(i, top);
		puts("");
		for (i = 0; i < RTE_DIM(stat_entries); ++i)
			PRINT_STAT_ENTRY_HEADER(i, bottom);
		puts("");
	}

	for (i = 0; i < RTE_DIM(stat_entries); ++i) {
		printf("%*"PRIu64" ", stat_entries[i].spacing,
				(stat_entries[i].type == VALUE) ?
					*stat_entries[i].value :
					(*stat_entries[i].lambda)());
		/* Write CP stats into stat file */
		if (i == 0) {
			if (fprintf(stats_file, "%s", buf) < 0)
				printf("%s [%d] fprintf(stats_file write failed -"
					" %s (%d)\n", __FILE__, __LINE__, strerror(errno), errno);
		} else {
			if (fprintf(stats_file, ",%lu", (stat_entries[i].type == VALUE) ?
					*stat_entries[i].value : (*stat_entries[i].lambda)()) < 0)
				printf("%s [%d] fprintf(stats_file write failed -"
					" %s (%d)\n", __FILE__, __LINE__, strerror(errno), errno);
		}
	}
	puts("");
	if (fprintf(stats_file, "\n") < 0)
		printf("%s [%d] fprintf(stats_file write failed -"
			" %s (%d)\n", __FILE__, __LINE__, strerror(errno), errno);
	if (fflush(stats_file))
		printf("%s [%d] fflush(cp stats file failed - %s (%d)\n",
			__FILE__, __LINE__, strerror(errno), errno);
}

static void timer_cb(__attribute__ ((unused))
		struct rte_timer *tim, __attribute__ ((unused))void *arg)
{
	static unsigned msg_statcntr;
	if (sesstats_flg == 1) {
		/* VCCCCB-34 Statistics- Add #of active sessions, RX & TX bytes */
		/* Display pkt stats on cmdline sesstats option */
		disp_sesstats();
	}
	if (ifistats_flg == 1) {
		ngic_rtc_s11_stats();
		ngic_rtc_cups_stats();
		disp_ifistats();
	}
	if (msgstats_flg == 1) {
		/* Display pkt stats on cmdline msgstats option */
		if(mstat_cnt == 0 || mstat_cnt == STAT_DISPSIZE) {
			if(mstat_cnt == STAT_DISPSIZE)
				mstat_cnt=1;
		}
		print_stat_entries();
		mstat_cnt++;
		/* this timer is automatically reloaded until we decide to
		 * stop it, when msg_statcntr reaches 500. */
		if ((msg_statcntr++) == 500) {
			/* rte_timer_stop(tim); */
		}
	}
}

/**
 * Function to create CP stats file
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
static void create_stats_file(void)
{
	char filename[STAT_FILE_NAME_LEN];
	char timestamp[TIMESTAMP_BUF_LEN];
	int ret;
	time_t t = time(NULL);
	struct tm *tmp = localtime(&t);
	DIR *stats_dir = opendir("./stats");

	if (stats_dir)
		closedir(stats_dir);
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

	ret = snprintf(filename, STAT_FILE_NAME_LEN, "%s%s_CP_STATS.csv",
			cp_stats_path, timestamp);
	if (ret < 0)
		printf("output error during CP stats filename creation\n");

	printf("Create CP Stats file: %s\n", filename);

	stats_file = fopen(filename, "w");
	if (!stats_file)
		printf("CP stats file %s failed to open for writing\n"
				" - %s (%d)",
				filename, strerror(errno), errno);

	if (fprintf(stats_file, "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
			"TIMESTAMP", "rxpkts", "txpkts", "rxpkts/sec", "txpkts/sec",
			"CreateSession", "ModifyBearer", "BResrcCmd",
			"CreateBearer", "DelBearer", "DelSession", "echo",
			"RelAccBearer", "ddn", "ddn-ack") < 0)
		printf("%s [%d] fprintf(stats_file header failed -"
			" %s (%d)\n",
			__FILE__, __LINE__, strerror(errno), errno);
	if (fflush(stats_file))
		printf("%s [%d] fflush(cp stats file failed - %s (%d)\n",
			__FILE__, __LINE__, strerror(errno), errno);
}

int
do_stats(__rte_unused void *ptr)
{
	/* init timer structures */
	static uint8_t start_timer = 1;
	while (1) {
	/* NGIC_RTC_DRCT: this function would be invoked in an
	 * infinite loop. Initialize timer parameters only once */
		if (start_timer == 1) {
			/* Create CP Stats file */
			create_stats_file();

			rte_timer_init(&timer0);

			/* load timer0, every second, on master lcore, reloaded automatically */
			uint64_t hz = rte_get_timer_hz();
			unsigned lcore_id = rte_lcore_id();
			rte_timer_reset(&timer0, hz * CP_STATS_TIMER_INTERVAL, PERIODICAL, lcore_id,
					timer_cb, NULL);
			start_timer = 0;
		}

		cp_crtsc = rte_rdtsc();
		cp_dftsc = cp_crtsc - cp_pvtsc;
		if (cp_dftsc > TIMER_RESOLUTION_CYCLES) {
			rte_timer_manage();
			cp_pvtsc = cp_crtsc;
		}

		/* Enabling CP CLI */
		int status;
		static int cmd_ready;

		if (cmd_ready == 0) {
			ngiccp_cl = rte_malloc_socket(NULL,
					sizeof(struct cmdline),
					RTE_CACHE_LINE_SIZE, rte_socket_id());
			ngiccp_cl = cmdline_stdin_new(main_ctx, "ngic-rtc-cp>");
			if (ngiccp_cl == NULL)
				rte_panic("Cannot create cmdline instance\n");
			cmdline_printf(ngiccp_cl, "\nCommands supported:"
					"\n\t- r= toggle request query"
					"\n\t- s= toggle session stats"
					"\n\t\t Session Table Index::"
					"\n\t\t\tst= TOP; sm= MIDDLE; se= END"
					"\n\t- i= toggle interface interaction stats (ifistats)"
					"\n\t- m= toggle msgstats"
					"\n\t- q= quit CLI"
					"\n\t- h= help\n");
			cmdline_stdin_new(main_ctx, "ngic-rtc-cp>");
			cmd_ready = 1;
		}

		status = cmdline_poll(ngiccp_cl);
		if (status < 0)
			rte_panic("CLI poll error (%" PRId32 ")\n", status);
		else if (status == RDLINE_EXITED) {
			cmdline_stdin_exit(ngiccp_cl);
			rte_exit(0, NULL);
		}
	}
	return 0;
}

void
reset_cp_stats(void) {
	memset(&cp_stats, 0, sizeof(cp_stats));
}
