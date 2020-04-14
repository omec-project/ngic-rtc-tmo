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

#include <stdint.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_jhash.h>
#include <rte_cfgfile.h>
#include <math.h>

#include "interface.h"
#include "main.h"
#include "packet_filters.h"
#include "util.h"

#include "cp_stats.h"

#define RTE_LOGTYPE_CP RTE_LOGTYPE_USER4

uint64_t base_imsi;
uint64_t base_mei;
uint64_t base_msisdn;
int apn_idx;
uint8_t ebi;
uint32_t base_s11_teid;
uint32_t base_s1u_teid;

#ifdef DP_BUILD
struct cp_stats_t cp_stats = {0};
#else /* CP_BUILD */
static uint32_t imsi_offset = 0;
static uint32_t mei_offset = 0;
static uint32_t msisdn_offset = 0;
static uint32_t s11_teid_offset = 0;
#endif /* DP_BUILD */

#define SIMU_CP_FILE "../config/simu_cp.cfg"

extern char *dpn_id;
extern uint32_t num_adc_rules;
extern uint32_t adc_rule_id[MAX_ADC_RULES];
static uint32_t s1u_spgw_gtpu_teid_offset;

/* Control-Plane Simulator configure parameters. */
struct simu_params {
	uint64_t base_imsi;
	uint64_t base_mei;
	uint64_t base_msisdn;
	int apn_idx;
	uint8_t ebi;
	uint32_t base_s11_teid;
	uint32_t base_s1u_teid;
	uint32_t enb_ip;
	uint32_t num_enb;
	uint32_t s1u_sgw_ip;
	uint32_t ue_ip_start;
	uint32_t ue_ip_range;
	uint32_t max_ue_sess;
	uint32_t default_bearer;
	uint32_t tps;
	uint32_t as_ip_start;
	uint32_t duration;
} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

/* Show Total statistics of Control-plane */
static void
print_stats(struct simu_params *cfg)
{
	uint32_t addr;
	printf("\n**************************\n");
	printf("SIMU CP Test Config :: \n");
	printf("**************************\n");
	addr = htonl(cfg->enb_ip);
	printf("BASE_IMSI                      : %lu\n", cfg->base_imsi);
	printf("BASE_MEI                       : %lu\n", cfg->base_mei);
	printf("BASE_MSISDN                    : %lu\n", cfg->base_msisdn);
	printf("APN_IDX                        : %d\n", cfg->apn_idx);
#ifdef CP_BUILD
	printf("APN_NAME                       : %s\n", apn_list[cfg->apn_idx].apn_name_label);
#endif /* CP_BUILD */

	printf("EPS_BEARER_ID                  : %u\n", cfg->ebi);
	printf("BASE_S11_TEID                  : 0x%X\n", cfg->base_s11_teid);
	printf("BASE_S1U_TEID                  : 0x%X\n", cfg->base_s1u_teid);
	printf("ENB_START_IP                   : %s\n",
											inet_ntoa(*(struct in_addr *)&addr));
	printf("NUM_ENB                        : %u\n", cfg->num_enb);
	addr = htonl(cfg->ue_ip_start);
	printf("UE_START_IP                    : %s\n",
											inet_ntoa(*(struct in_addr *)&addr));
	addr = htonl(cfg->ue_ip_range);
	printf("UE_IP_RANGE                    : %s\n",
											inet_ntoa(*(struct in_addr *)&addr));
	printf("MAX_NUM_CREATE_SESSION (CS)    : %u\n", cfg->max_ue_sess);
	printf("MAX_NUM_MODIFY_BEARER (MB)     : %u\n", cfg->max_ue_sess);
	printf("DEFAULT_BEARER                 : %u\n", cfg->default_bearer);
	printf("TPS                            : %u\n", cfg->tps);
	addr = htonl(cfg->as_ip_start);
	printf("AS_START_IP                    : %s\n",
											inet_ntoa(*(struct in_addr *)&addr));
	printf("\nSIMU CP Transaction stats :: \n");
	printf("NUM_CS_SEND                    : %"PRIu64"\n", cp_stats.create_session);
	printf("NUM_MB_SEND                    : %"PRIu64"\n", cp_stats.modify_bearer);
	printf("NUM_CS_FAILED                  : %"PRIu64"\n",
											(cfg->max_ue_sess - cp_stats.create_session));
	printf("NUM_MB_FAILED                  : %"PRIu64"\n",
											(cfg->max_ue_sess - cp_stats.modify_bearer));
	printf("**************************\n\n");

	if ((cfg->max_ue_sess != cp_stats.create_session) || (cfg->max_ue_sess != cp_stats.modify_bearer)) {
		printf("\n**ERROR : DP not configure properly for %u CS/MB requests.**\n",
				cfg->max_ue_sess);
		exit(1);
	}
	printf("\n************ DP Configured successfully ************\n");

}

#ifdef DEL_SESS_REQ
/* Show Total statistics of Control-plane */
static void
print_del_stats(struct simu_params *cfg)
{
	printf("\n**************************\n");
	printf("STATS :: \n");
	printf("**************************\n");
	printf("MAX_NUM_DEL   : %u\n", cfg->max_ue_sess);
	printf("NUM_DEL_SEND  : %"PRIu64"\n", cp_stats.delete_session);
	printf("NUM_DEL_FAILED: %"PRIu64"\n", (cfg->max_ue_sess - cp_stats.delete_session));
	printf("**************************\n\n");

}
#endif /* DEL_SESS_REQ */

/* Generate unique eNB teid */
static uint32_t
generate_enbipteid(int ue_idx, int max_ue_sess, int num_enb,
		uint32_t *enb_teid, uint32_t *enb_ip_idx)
{
	uint32_t ue_of_ran;
	uint32_t ran;
	uint32_t enb_of_ran;
	uint32_t enb;
	uint32_t ue_teid;
	uint32_t session_idx = 0;

	if (max_ue_sess == 0 || num_enb == 0)
		return -1; /* need to have at least one of each */

	ue_of_ran = ue_idx % max_ue_sess;
	ran = ue_idx / max_ue_sess;
	enb_of_ran = ue_of_ran % num_enb;
	enb = ran * num_enb + enb_of_ran;

	ue_teid = ue_of_ran + max_ue_sess * session_idx + 1;

	*enb_teid = ue_teid;
	*enb_ip_idx = enb;

	return 0;
}

/* Generate unique session teid for each session */
static void
generate_sessteid(uint32_t *teid)
{
	*teid = base_s1u_teid + s1u_spgw_gtpu_teid_offset;
	++s1u_spgw_gtpu_teid_offset;
}

#ifdef CP_BUILD
/* Generate unique ue_context for each session */
static
ue_context *generate_uecontext(int ue_idx, int max_ue_sess, int num_enb)
{
	uint64_t imsi;
	uint64_t mei;
	uint64_t msisdn;
	uint32_t ue_of_ran;
	uint32_t ran;
	uint32_t mme_of_ran;
	uint32_t mme;
	uint32_t ue_teid;
	uint32_t s11_teid;
	uint32_t session_idx = 0;
	ue_context *context = NULL;
	int ret;

	if (max_ue_sess == 0 || num_enb == 0)
		return NULL; /* need to have at least one of each */

	imsi = base_imsi + imsi_offset;
	++imsi_offset;
	mei = base_mei + mei_offset;
	++mei_offset;
	msisdn = base_msisdn + msisdn_offset;
	++msisdn_offset;

	ue_of_ran = ue_idx % max_ue_sess;
	ran = ue_idx / max_ue_sess;

	ue_teid = ue_of_ran + max_ue_sess * session_idx + 1;
	/* ASR- Note: mme_of_ran == enb_of_ran:: 1xMME <> 1xeNB */
	mme_of_ran = ue_of_ran % num_enb;
	mme = ran * num_enb + mme_of_ran;

	s11_teid = base_s11_teid + s11_teid_offset;
	++s11_teid_offset;

	ret = create_ue_context((uint8_t *)&imsi, sizeof(uint64_t),
						ebi, &context, apn_idx);
	if (ret) {
		rte_exit(EXIT_FAILURE,"%s::create_ue_context fail !!!",
				__func__);
	}
	context->mei = mei;
	for (uint8_t i = 0; i < sizeof(uint64_t); i++) {
		context->msisdn[i] = *((int8_t *)&msisdn + i);
	}
	context->s11_mme_gtpc_teid = ue_teid;
	context->s11_mme_gtpc_ipv4.s_addr = mme;
	context->s11_sgw_gtpc_teid = s11_teid;
	context->s11_sgw_gtpc_ipv4 = s11_sgw_ip;

	return context;
}
#endif /* CP_BUILD */

/* Form and send CS and MB request to DP*/
static int
process_cs_mb_req(struct simu_params *param)
{
	printf("\n\n %50s", " CS and MB Requests Generator is started ....!!! \n");
	printf("\n\n %50s", " Please wait for DP configured message ....!!! \n");

	/* Create UE Context & Session Information*/
	uint32_t s1u_teid = 0;
	uint32_t enb_teid = 0;
	uint32_t enb_ip_idx = 0;

	time_t tstart, tend;
	unsigned int count = 0;
	int second_expired = 1;

	while(1) {
		if(second_expired)
			time(&tstart);
		second_expired = 0;

		while(cp_stats.create_session < param->max_ue_sess){
			time(&tend);
			if(fabs(difftime(tend, tstart)) >= fabs(1.0)) {
				count = 0;
				second_expired = 1;
				break;
			}

			if (count < param->tps) {
				struct session_info *sess = NULL;
#ifdef CP_BUILD
				ue_context *context = NULL;
				/* ASR- Note: ue_idx == cp_stats.create_session;
				 * initial val. cp_stats.create_session = 0; */
				context=
					generate_uecontext(cp_stats.create_session, param->max_ue_sess, param->num_enb);
#endif /* CP_BUILD */
				sess = rte_zmalloc_socket(NULL, sizeof(struct session_info),
									RTE_CACHE_LINE_SIZE, rte_socket_id());

				/*generate teid for each create session */
				generate_sessteid(&s1u_teid);

				/* ASR- Note: ue_idx == cp_stats.create_session;
				 * initial val. cp_stats.create_session = 0; */
				generate_enbipteid(cp_stats.create_session, param->max_ue_sess, param->num_enb,
						&enb_teid, &enb_ip_idx);

				sess->ue_addr.iptype = IPTYPE_IPV4;
				sess->ue_addr.u.ipv4_addr = (param->ue_ip_start) + cp_stats.create_session;

				sess->ul_s1_info.sgw_teid = s1u_teid;
				sess->ul_s1_info.sgw_addr.iptype = IPTYPE_IPV4;
				sess->ul_s1_info.sgw_addr.u.ipv4_addr = param->s1u_sgw_ip;

				sess->dl_s1_info.sgw_addr.iptype = IPTYPE_IPV4;
				sess->dl_s1_info.sgw_addr.u.ipv4_addr = param->s1u_sgw_ip;

				sess->ul_apn_mtr_idx = ulambr_idx;
				sess->dl_apn_mtr_idx = dlambr_idx;
				sess->ipcan_dp_bearer_cdr.charging_id = 10;
				sess->ipcan_dp_bearer_cdr.pdn_conn_charging_id = 10;


				sess->ul_s1_info.enb_addr.iptype = IPTYPE_IPV4;
				sess->ul_s1_info.enb_addr.u.ipv4_addr = param->enb_ip + enb_ip_idx;
				sess->num_ul_pcc_rules = 1;
				sess->num_dl_pcc_rules = 1;
				sess->ul_pcc_rule_id[0] = FIRST_FILTER_ID;
				sess->dl_pcc_rule_id[0] = FIRST_FILTER_ID;

				sess->sess_id = SESS_ID(sess->ue_addr.u.ipv4_addr, param->default_bearer);

				struct dp_id dp_id = { .id = DPN_ID };

				if (session_create(dp_id, sess) < 0)
					rte_exit(EXIT_FAILURE,"Bearer Session create fail !!!");
				RTE_LOG_DP(DEBUG, CP,
						"cs_count= %lu; param->max_ue_sess= %u\n",
						cp_stats.create_session, param->max_ue_sess);
				cp_stats.create_session++;
				/* ASR- ZMQ-Push-Pull water mark throttle back */
				sleep(0.001);

				/* Modify the session */
				sess->dl_s1_info.enb_teid = ntohl(enb_teid);
				sess->dl_s1_info.enb_addr.iptype = IPTYPE_IPV4;
				sess->dl_s1_info.enb_addr.u.ipv4_addr = param->enb_ip + enb_ip_idx;

				sess->num_adc_rules = num_adc_rules;

				for (uint32_t i = 0; i < num_adc_rules; i++)
					sess->adc_rule_id[i] = adc_rule_id[i];

				if (session_modify(dp_id, sess) < 0)
					rte_exit(EXIT_FAILURE,"Bearer Session modify fail !!!");
				RTE_LOG_DP(DEBUG, CP, "mb_count= %"PRIu64"\n",
						cp_stats.modify_bearer);
				RTE_LOG_DP(DEBUG, CP, "count= %d; param->tps= %d\n\n",
						count, param->tps);
				++count;
				cp_stats.modify_bearer++;
				/* ASR- ZMQ-Push-Pull water mark throttle back */
				sleep(0.001);

				/* ASR- TMOPL VCCCCB-25
				 * Reference @DP session_info:: apn_idx, ue_context, pdn_connection
				 */
				/* session_info: CP CDR collation handle */
#ifdef CP_BUILD
				context->dp_session = sess;
#endif /* CP_BUILD */
				sess->dp_session = sess;
			}
			if(second_expired)
				break;
		}
		if(cp_stats.create_session >= param->max_ue_sess)
			break;
	}
	RTE_LOG_DP(DEBUG, CP,
			"Final cs_count= %lu; param->max_ue_sess= %u"
			"\n\tFinal count= %d\n\n",
			cp_stats.create_session, param->max_ue_sess, count);
	return 0;
}

#ifdef DEL_SESS_REQ
/* Form and delete request to DP*/
static int
process_delete_req(struct simu_params *param)
{

	printf("\n\n %50s", "Start sending delete session request ....!!! \n");

	/* Create Session Information*/
	uint32_t s1u_teid = 0;
	uint32_t enb_teid = 0;
	uint32_t enb_ip_idx = 0;

	time_t tstart, tend;
	unsigned int count = 0;
	int second_expired = 1;

	while(1) {
		if(second_expired)
			time(&tstart);
		second_expired = 0;

		while(cp_stats.delete_session < param->max_ue_sess) {

			time(&tend);
			if(fabs(difftime(tend, tstart)) >= fabs(1.0)) {
				count = 0;
				second_expired = 1;
				break;
			}

			if (count < param->tps) {
				struct session_info sess;

				memset(&sess, 0, sizeof(struct session_info));

				/*generate teid for each create session */
				generate_sessteid(&s1u_teid);

				generate_enbipteid(cp_stats.delete_session, param->max_ue_sess, param->num_enb,
						&enb_teid, &enb_ip_idx);

				sess.ue_addr.iptype = IPTYPE_IPV4;
				sess.ue_addr.u.ipv4_addr = (param->ue_ip_start) + cp_stats.delete_session;

				sess.sess_id = SESS_ID(sess.ue_addr.u.ipv4_addr, param->default_bearer);

				struct dp_id dp_id = { .id = DPN_ID };

				if (session_delete(dp_id, &sess) < 0)
					rte_exit(EXIT_FAILURE,"Bearer Session create fail !!!");

				cp_stats.delete_session++;
				++count;
			}

			if(second_expired)
				break;
		}
		if (cp_stats.delete_session >= param->max_ue_sess)
				break;
	}
	return 0;
}
#endif /* DEL_SESS_REQ */

static int
parse_agrs(struct simu_params *cfg)
{
	struct in_addr addr;

	struct rte_cfgfile_parameters rte_cfgfile_param = { '#' };
	const char *file_entry = NULL;
	char *end = NULL;

	struct rte_cfgfile *file = rte_cfgfile_load_with_params(SIMU_CP_FILE, 0,
															&rte_cfgfile_param);
	if (file == NULL)
		rte_exit(EXIT_FAILURE, "Cannot load configuration profile %s\n",
				SIMU_CP_FILE);

	file_entry = rte_cfgfile_get_entry(file, "0", "BASE_IMSI");
	if (file_entry)
		cfg->base_imsi =  (uint64_t) strtoll(file_entry, &end, 10);

	file_entry = rte_cfgfile_get_entry(file, "0", "BASE_MEI");
	if (file_entry)
		cfg->base_mei =  (uint64_t) strtoll(file_entry, &end, 10);

	file_entry = rte_cfgfile_get_entry(file, "0", "BASE_MSISDN");
	if (file_entry)
		cfg->base_msisdn =  (uint64_t) strtoll(file_entry, &end, 10);

	file_entry = rte_cfgfile_get_entry(file, "0", "APN_IDX");
	if (file_entry)
		cfg->apn_idx =  (int) strtoll(file_entry, &end, 10);

	file_entry = rte_cfgfile_get_entry(file, "0", "EPS_BEARER_ID");
	if (file_entry)
		cfg->ebi =  (int) strtoll(file_entry, &end, 10);

	file_entry = rte_cfgfile_get_entry(file, "0", "BASE_S11_TEID");
	if (file_entry)
		cfg->base_s11_teid =  (uint32_t) strtoll(file_entry, &end, 16);

	file_entry = rte_cfgfile_get_entry(file, "0", "BASE_S1U_TEID");
	if (file_entry)
		cfg->base_s1u_teid =  (uint32_t) strtoll(file_entry, &end, 16);

	file_entry = rte_cfgfile_get_entry(file, "0", "ENB_START_IP");
	if (file_entry) {
		if (inet_aton(file_entry, &addr) == 0) {
			fprintf(stderr, "Invalid address\n");
			exit(EXIT_FAILURE);
		}
		cfg->enb_ip = ntohl(addr.s_addr);
	}

	file_entry = rte_cfgfile_get_entry(file, "0", "NUM_ENB");
	if (file_entry)
		cfg->num_enb =  (uint32_t) strtoll(file_entry, &end, 10);

	file_entry = rte_cfgfile_get_entry(file, "0", "S1U_SGW_IP");
	if (file_entry) {
		if (inet_aton(file_entry, &addr) == 0) {
			fprintf(stderr, "Invalid address\n");
			exit(EXIT_FAILURE);
		}
		cfg->s1u_sgw_ip = ntohl(addr.s_addr);
	}

	file_entry = rte_cfgfile_get_entry(file, "0", "UE_START_IP");
	if (file_entry) {
		if (inet_aton(file_entry, &addr) == 0) {
			fprintf(stderr, "Invalid address\n");
			exit(EXIT_FAILURE);
		}
		cfg->ue_ip_start = ntohl(addr.s_addr);
	}

	file_entry = rte_cfgfile_get_entry(file, "0", "UE_IP_RANGE");
	if (file_entry) {
		if (inet_aton(file_entry, &addr) == 0) {
			fprintf(stderr, "Invalid address\n");
			exit(EXIT_FAILURE);
		}
		cfg->ue_ip_range = ntohl(addr.s_addr);
	}

	file_entry = rte_cfgfile_get_entry(file, "0", "MAX_UE_SESS");
	if (file_entry)
		cfg->max_ue_sess =  (uint32_t) strtoll(file_entry, &end, 10);

	file_entry = rte_cfgfile_get_entry(file, "0", "AS_START_IP");
	if (file_entry) {
		if (inet_aton(file_entry, &addr) == 0) {
			fprintf(stderr, "Invalid address\n");
			exit(EXIT_FAILURE);
		}
		cfg->as_ip_start = ntohl(addr.s_addr);
	}

	file_entry = rte_cfgfile_get_entry(file, "0", "DEFAULT_BEARER");
	if (file_entry)
		cfg->default_bearer =  (uint32_t) strtoll(file_entry, &end, 10);

	file_entry = rte_cfgfile_get_entry(file, "0", "TPS");
	if (file_entry)
		cfg->tps =  (uint32_t) strtoll(file_entry, &end, 10);

	file_entry = rte_cfgfile_get_entry(file, "0", "BREAK_DURATION");
	if (file_entry)
		cfg->duration =  (uint32_t) strtoll(file_entry, &end, 10);

	return 0;
}

#ifdef CP_BUILD
int simu_cp(__rte_unused void *ptr)
#else /* DP_BUILD */
int simu_cp(void)
#endif /* CP_BUILD */
{
		struct simu_params cfg = {0};

		/* Parsing simu config parameters. */
		int ret = parse_agrs(&cfg);
		if (ret < 0)
			exit(1);
		base_imsi = cfg.base_imsi;
		base_mei = cfg.base_mei;
		base_msisdn = cfg.base_msisdn;
		apn_idx = cfg.apn_idx;
		ebi = cfg.ebi;
		base_s11_teid = cfg.base_s11_teid;
		base_s1u_teid = cfg.base_s1u_teid;

#ifdef DP_BUILD
		/* Parse the rules into DP */
		/* Configure  PCC, Meter and SDF rules on DP. */
		init_packet_filters();
		/* Configure ADC rules on DP.*/
		parse_adc_rules();
#endif /* DP_BUILD */

		/* Wait to create stream channel with FPC*/
		sleep(5);

		/* Form and send CS and MB request to DP. */
		ret = process_cs_mb_req(&cfg);
		if (ret < 0)
			exit(1);

		/* Show CS and MB requests STATS. */
		sleep(5);
		print_stats(&cfg);

#ifdef DEL_SESS_REQ
		sleep(cfg.duration);

		/* Form and send delete request to DP. */
		ret = process_delete_req(&cfg);
		if (ret < 0)
			exit(1);

		/* Show delete session requests STATS. */
		sleep(5);
		print_del_stats(&cfg);
#endif /* DEL_SESS_REQ */

		return 0;
}


