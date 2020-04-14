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

#ifndef UE_H
#define UE_H

/**
 * @file
 *
 * Contains all data structures required by 3GPP TS 23.401 Tables 5.7.3-1 and
 * 5.7.4-1 (that are nessecary for current implementaiton) to describe the
 * Connections, state, bearers, etc as well as functions to manage and/or
 * obtain value for their fields.
 *
 */

#include <stdint.h>
#include <arpa/inet.h>
#include <immintrin.h>

#include <rte_malloc.h>
#include <rte_lcore.h>
#include <rte_jhash.h>
#include <rte_hash.h>

#include "gtpv2c_ie.h"
#include "gtpv2c_ie.h"
#include "packet_filters.h"
#include "interface.h"

#define SDF_FILTER_TABLE "sdf_filter_table"
#define ADC_TABLE "adc_rule_table"
#define PCC_TABLE "pcc_table"
#define SESSION_TABLE "session_table"
#define METER_PROFILE_SDF_TABLE "meter_profile_sdf_table"
#define METER_PROFILE_APN_TABLE "meter_profile_apn_table"

#define SDF_FILTER_TABLE_SIZE        (1024)
#define ADC_TABLE_SIZE               (1024)
#define PCC_TABLE_SIZE               (1025)
#define METER_PROFILE_SDF_TABLE_SIZE (2048)

/* Set DPN ID on respective CP */
#define DPN_ID                       (12345)

#define MAX_BEARERS                  (11)
#define MAX_FILTERS_PER_UE           (16)

/* CP Session capacty: 65,536 i.e. 64K UEs.
 * __builtin_ffsll(...)::
 *         Scan Forward for bit set in 64b field == 8bytes
 * MAX UE SIZE == 64K/8 */
#define CP_UE_BLOCK                  8192
#define UE_BUFF_MASK                 255

/* ASR- TMOPL VCCCCB-28
 * Many PDN connections for the same IMSI on a given APN not allowed
 * REQD: Many PDN connections same IMSI different APN
 * ue_context_by_imsi_hash::Key= fn(IMSI, apn).
 * Insert apn_indx @byte7 of imsi; MAX_NB_APN: MAX VAL= 255
 */
#define APN_IMSI_KEY_POSTN           7
#define APN_IMSI_KEY_LEN             4
#define APN_IMSI_SHIFT_VAL           0xF0

extern struct rte_hash *ue_context_by_imsi_hash;
extern struct rte_hash *ue_context_by_fteid_hash;

extern uint8_t apn_count, ip_count, mask_count;
extern uint8_t pdns_count, sdns_count;
extern uint8_t tmrth_count, volth_count;

typedef struct ue_ippool_t {
	int hosts;                      /* max. possible hosts */
	struct in_addr netid;           /* network id */
	struct in_addr netmask;         /* subnetmask */
} ue_ippool;
extern ue_ippool ue_pool_list[MAX_NB_APN];

/* Primary & Secondary DNS config list */
extern struct in_addr pdns_list[MAX_NB_APN];
extern struct in_addr sdns_list[MAX_NB_APN];
/* Timer & Volume threshold config list */
extern uint64_t tmr_trshld_list[MAX_NB_APN];
extern uint64_t vol_trshld_list[MAX_NB_APN];
/* UL and DL AMBR LIST */
extern uint32_t ul_ambr_list[MAX_NB_APN];
extern uint32_t dl_ambr_list[MAX_NB_APN];

typedef struct apn_t {
	uint8_t apn_idx;
	char *apn_name_label;
	size_t apn_name_length;
	ue_ippool *ue_pool;
	struct in_addr *pdns;
	struct in_addr *sdns;
	unsigned char *ue_ipbf;
	uint64_t *tmr_trshld;     /* CDR timer threshold: Sec */
	uint64_t *vol_trshld;     /* CDR volume threshold: MBytes*/
	ambr_ie apn_ambr;         /* UL/DL AMBR values configured in cp cfg */
} apn;
extern apn apn_list[MAX_NB_APN];

typedef struct pdn_connection_t {
	apn *apn_in_use;
	ambr_ie apn_ambr;
	uint32_t apn_restriction;

	ambr_ie session_ambr;
	ambr_ie session_gbr;

	struct in_addr ipv4;
	struct in6_addr ipv6;

	uint32_t s5s8_sgw_gtpc_teid;
	struct in_addr s5s8_sgw_gtpc_ipv4;

	uint32_t s5s8_pgw_gtpc_teid;
	struct in_addr s5s8_pgw_gtpc_ipv4;

	pdn_type_ie pdn_type;
	/* See  3GPP TS 32.298 5.1.2.2.7 for Charging Characteristics fields*/
	charging_characteristics_ie charging_characteristics;

	uint8_t default_bearer_id;
	uint8_t num_bearers; /* Number of bearers in pdn */

	struct eps_bearer_t *eps_bearers[MAX_BEARERS]; /* index by ebi - 5 */

	struct eps_bearer_t *packet_filter_map[MAX_FILTERS_PER_UE];
} pdn_connection;

typedef struct ue_context_t {
	uint64_t imsi;
	uint8_t unathenticated_imsi;
	uint64_t mei;
	int8_t msisdn[BINARY_MSISDN_LEN];

	/* ASR- TMOPL VCCCCB-21
	 * NGIC state info re-design for billing and LI
	 */
	tai_t tai;
	ecgi_t ecgi;
	rat_type_ie_t rat_type;
	/* VCCCCB-44, CDR content verification
	 * Populate ULI Info */
	uli_info_ie_t uli_info;
	/* VCCCCB-44, CDR content verification
	 * Populate MNC/MCC from proper Serving Network IE */
	serving_network_ie_t serving_nw;

	ambr_ie mn_ambr;
	/* SM- TMOPL VCCCCB-35
	 * Send Delete session response based on SI
	 */
	indication_t indication_value;

	uint32_t s11_sgw_gtpc_teid;
	struct in_addr s11_sgw_gtpc_ipv4;
	uint32_t s11_mme_gtpc_teid;
	struct in_addr s11_mme_gtpc_ipv4;

	uint16_t bearer_bitmap;
	uint16_t teid_bitmap;
	uint8_t num_pdns;

	pdn_connection *pdns[MAX_BEARERS];
	struct eps_bearer_t *eps_bearers[MAX_BEARERS]; /* index by ebi - 5 */

	/* temporary bearer to be used during resource bearer cmd -
	 * create/deletee bearer req - rsp */
	struct eps_bearer_t *ded_bearer;

	/* ASR- TMOPL VCCCCB-21
	 * NGIC state info re-design for billing and LI
	 */
	selection_mode_ie_t seletion_mode;
	pdn_type_ie_t pdn_type;
	paa_ie_t paa;
	ue_timezone_ie_t ue_timezone;
	charging_char_ie_t charging_characteristics;
	struct session_info *dp_session; /* session_info: CP CDR collation handle */
} ue_context;

typedef struct eps_bearer_t {
	uint8_t eps_bearer_id;

	bearer_qos_ie qos;

	uint32_t charging_id;

	struct in_addr s1u_sgw_gtpu_ipv4;
	uint32_t s1u_sgw_gtpu_teid;
	struct in_addr s5s8_sgw_gtpu_ipv4;
	uint32_t s5s8_sgw_gtpu_teid;
	struct in_addr s5s8_pgw_gtpu_ipv4;
	uint32_t s5s8_pgw_gtpu_teid;
	struct in_addr s1u_enb_gtpu_ipv4;
	uint32_t s1u_enb_gtpu_teid;

	struct in_addr s11u_mme_gtpu_ipv4;
	uint32_t s11u_mme_gtpu_teid;

	pdn_connection *pdn;

	int packet_filter_map[MAX_FILTERS_PER_UE];
	uint8_t num_packet_filters;
} eps_bearer;
struct eps_bearer_t;

/**
 * sets the s1u_sgw gtpu teid given the bearer
 * @param bearer
 *   bearer whose tied is to be set
 * @param context
 *   ue context of bearer, whose teid is to be set
 */
void
set_s1u_sgw_gtpu_teid(eps_bearer *bearer, ue_context *context);


/**
 * sets the s5s8_sgw gtpu teid given the bearer
 * @param bearer
 *   bearer whose tied is to be set
 * @param context
 *   ue context of bearer, whose teid is to be set
 */
void
set_s5s8_sgw_gtpu_teid(eps_bearer *bearer, ue_context *context);


/**
 * sets the s5s8_pgw gtpc teid given the pdn_connection
 * @param pdn
 *   pdn_connection whose s5s8 tied is to be set
 */
void
set_s5s8_pgw_gtpc_teid(pdn_connection *pdn);

/**
 * Initializes UE hash table
 */
void
create_ue_hash(void);


/**
 * This function takes the c-string argstr describing a apn by url, for example
 *  label1.label2.label3 and populates the apn structure according 3gpp 23.003
 *  clause 9.1
 * @param an_apn
 *   apn to be initialized
 * @param argstr
 *   c-string containing the apn label
 */
void
set_apn_name(apn *an_apn, char *argstr);

/**
 * returns the apn strucutre of the apn referenced by create session message
 * @param apn_label
 *   apn_label within a create session message
 * @param apn_length
 *   the length as recorded by the apn information element
 * @return
 *   the apn label configured for the CP
 */
/* ASR- Note: Reserved for Future Use (RFU) */
apn *
get_apn(char *apn_label, uint16_t apn_length);

/**
 * returns the apn strucutre of the apn referenced by create session message
 * @param apn_label
 *   apn_label within a create session message
 * @param apn_length
 *   the length as recorded by the apn information element
 * @return
 *   the apn idx configured for the CP
 */
int
get_apn_idx(char *apn_label, uint16_t apn_length);

/**
 * assigns the ip pool variable from parsed c-string
 * @param ip_str
 *   ip address c-string from command line
 */
void
set_ip_pool(const char *ip_str);

/**
 * assigns the ip pool mask variable from parsed c-string
 * @param ip_str
 *   ip address c-string from command line
 *
 */
void
set_ip_pool_mask(const char *ip_str);

/**
 * assigns the ip pool variable from parsed c-string
 * @param ip_str
 *   ip address c-string from command line
 */
void
set_primary_dns(const char *ip_str);

/**
 * assigns the ip pool variable from parsed c-string
 * @param ip_str
 *   ip address c-string from command line
 */
void
set_secondary_dns(const char *ip_str);

/**
 * assigns per APN timer threshold (sec) parsed c-string
 * @param tmr_trhsld
 *   tmr_trshld c-string from command line
 */
void
set_timer_trshld(const char *tmr_trshld_str);

/**
 * assigns per APN volume threshold (MBytes) parsed c-string
 * @param vol_trhsld
 *   vol_trshld c-string from command line
 */
void
set_vol_trshld(const char *vol_trshld_str);

/**
 * assigns per APN UL AMBR value parsed c-string
 * @param ul_ambr_str
 *   ul_ambr_str c-string from command line
 */
void
set_ul_ambr(const char *ul_ambr_str);

/**
 * assigns per APN DL AMBR value parsed c-string
 * @param dl_ambr_str
 *   dl_ambr_str c-string from command line
 */
void
set_dl_ambr(const char *dl_ambr_str);

/**
 * Simple ip-pool
 * @param ipv4
 *   ip address to be used for a new UE connection
 * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to
 *          3gpp specified cause error value
 */
uint32_t
acquire_ip(apn *apn_requested, struct in_addr *ipv4);

/**
 * Release ip-pool
 * @param apn *
 *   pointer to apn_in_use
 * @param ipv4
 *   ip address to be used for a new UE connection
 * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to
 *          3gpp specified cause error value
 */
uint32_t
release_ip(apn *apn_used, struct in_addr *ipv4);

/* For Debugging */
/** print (with a column header) either context by the context and/or
 * iterating over hash
 * @param h
 *   pointer to rte_hash containing ue hash table
 * @param context
 *   denotes if some context is to be indicated by '*' character
 */
void
print_ue_context_by(struct rte_hash *h, ue_context *context);

/** creates an UE Context (if needed), and pdn connection with a default bearer
 * given the UE IMSI, and EBI
 * @param imsi
 *   value of information element of the imsi
 * @param imsi_len
 *   length of information element of the imsi
 * @param ebi
 *   Eps Bearer Identifier of default bearer
 * @param context
 *   UE context to be created
 * @param apn_indx
 *   apn_indx
 * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to
 *          3gpp specified cause error value
 *   \- < 0 for all other errors
 */
int
create_ue_context(uint8_t *imsi_val, uint16_t imsi_len,
		uint8_t ebi, ue_context **context, uint8_t apn_indx);

#endif /* UE_H */
