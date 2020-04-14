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

#include <rte_debug.h>
#include <rte_branch_prediction.h>
#include <rte_errno.h>
#include <rte_lcore.h>
#include <rte_malloc.h>

#include <errno.h>
#include <stddef.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>

#include "ue.h"
#include "interface.h"
#include "cp.h"

struct rte_hash *ue_context_by_imsi_hash;
struct rte_hash *ue_context_by_fteid_hash;

uint8_t apn_count, ip_count, mask_count;
uint8_t pdns_count, sdns_count;
uint8_t tmrth_count, volth_count;
uint8_t ul_ambr_count = 0, dl_ambr_count = 0;

apn apn_list[MAX_NB_APN];
ue_ippool ue_pool_list[MAX_NB_APN];
/* Primary & Secondary DNS config list */
struct in_addr pdns_list[MAX_NB_APN];
struct in_addr sdns_list[MAX_NB_APN];
/* Timer & Volume threshold config list */
uint64_t tmr_trshld_list[MAX_NB_APN];
uint64_t vol_trshld_list[MAX_NB_APN];
/* UL and DL AMBR LIST */
uint32_t ul_ambr_list[MAX_NB_APN];
uint32_t dl_ambr_list[MAX_NB_APN];

const uint32_t s11_sgw_gtpc_base_teid = 0xC0FFEE;
static uint32_t s11_sgw_gtpc_teid_offset;
const uint32_t s5s8_pgw_gtpc_base_teid = 0xD0FFEE;
static uint32_t s5s8_pgw_gtpc_teid_offset;

uint32_t base_s1u_sgw_gtpu_teid = 0xf0000000;

void
set_s1u_sgw_gtpu_teid(eps_bearer *bearer, ue_context *context)
{
	uint8_t index = __builtin_ffs(~(context->teid_bitmap)) - 1;
	bearer->s1u_sgw_gtpu_teid = (context->s11_sgw_gtpc_teid & 0x00ffffff)
	    | ((0xf0 + index) << 24);
	context->teid_bitmap |= (0x01 << index);
}

void
set_s5s8_sgw_gtpu_teid(eps_bearer *bearer, ue_context *context)
{
	uint8_t index = __builtin_ffs(~(context->teid_bitmap)) - 1;
	/* Note: s5s8_sgw_gtpu_teid based s11_sgw_gtpc_teid
	 * Computation same as s1u_sgw_gtpu_teid
	 */
	bearer->s5s8_sgw_gtpu_teid = (context->s11_sgw_gtpc_teid & 0x00ffffff)
	    | ((0xf0 + index) << 24);
	context->teid_bitmap |= (0x01 << index);
}

void
set_s5s8_pgw_gtpc_teid(pdn_connection *pdn)
{
	pdn->s5s8_pgw_gtpc_teid = s5s8_pgw_gtpc_base_teid
		+ s5s8_pgw_gtpc_teid_offset;
	++s5s8_pgw_gtpc_teid_offset;
}

void
create_ue_hash(void)
{
	struct rte_hash_parameters rte_hash_params = {
			.name = "bearer_by_imsi_hash",
	    .entries = LDB_ENTRIES_DEFAULT,
	    .key_len = sizeof(uint64_t),
	    .hash_func = rte_jhash,
	    .hash_func_init_val = 0,
	    .socket_id = rte_socket_id(),
	};

	ue_context_by_imsi_hash = rte_hash_create(&rte_hash_params);
	if (!ue_context_by_imsi_hash) {
		rte_panic("%s hash create failed: %s (%u)\n.",
				rte_hash_params.name,
		    rte_strerror(rte_errno), rte_errno);
	}
	rte_hash_params.name = "bearer_by_fteid_hash";
	rte_hash_params.key_len = sizeof(uint32_t);
	ue_context_by_fteid_hash = rte_hash_create(&rte_hash_params);
	if (!ue_context_by_fteid_hash) {
		rte_panic("%s hash create failed: %s (%u)\n.",
				rte_hash_params.name,
		    rte_strerror(rte_errno), rte_errno);
	}
}

void
set_apn_name(apn *an_apn, char *argstr)
{
	if (argstr == NULL)
		rte_panic("@%s::Undefined!!! APN Name arg\n",
				__func__);
	an_apn->apn_name_length = strlen(argstr) + 1;
	an_apn->apn_name_label =
					rte_zmalloc_socket(NULL, an_apn->apn_name_length,
								RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (an_apn->apn_name_label == NULL)
		rte_panic("@%s::Failure!!! alloc apn_name_label:"
				"\n\t%s (%s:%d)\n",
				__func__, rte_strerror(rte_errno),
				__FILE__, __LINE__);
	/* Note: create_session::IE Access Point Name (APN)::
	* apn[0] = nb of chars in apn_name after '.';
	* apn[1, ... n] = apn_name chars; apn[n] != '/0' i.e. not NULL terminated */
	strncpy(an_apn->apn_name_label + 1, argstr, strlen(argstr));
	char *ptr, *size;
	size = an_apn->apn_name_label;
	*size = 1;
	ptr = an_apn->apn_name_label + strlen(argstr) - 1;
	do {
		if (ptr == size)
			break;
		if (*ptr == '.') {
			*ptr = *size;
			*size = 0;
		} else {
			(*size)++;
		}
		--ptr;
	} while (ptr != an_apn->apn_name_label);

	an_apn->apn_idx = apn_count;
	an_apn->ue_ipbf = rte_zmalloc_socket(NULL, CP_UE_BLOCK,
									RTE_CACHE_LINE_SIZE, rte_socket_id());
	memset(an_apn->ue_ipbf, UE_BUFF_MASK, CP_UE_BLOCK);
	apn_count++;
}

/* ASR- Note: Reserved for Future Use (RFU) */
apn *
get_apn(char *apn_label, uint16_t apn_length)
{
	int i;

	for(i=0; i < MAX_NB_APN; i++)   {
	        if ((apn_length == apn_list[i].apn_name_length)
	         && !memcmp(apn_label, apn_list[i].apn_name_label, apn_length)) {
	                break;
	        }
	}
	if(i >= MAX_NB_APN)     {
		fprintf(stderr,
		    "Received create session request with incorrect "
				"apn_label :%s", apn_label);
		return NULL;
	}
	return apn_list+i;
}

int
get_apn_idx(char *apn_label, uint16_t apn_length)
{
	int i;

	for(i=0; i < MAX_NB_APN; i++)   {
	        if ((apn_length == apn_list[i].apn_name_length)
	         && !strncasecmp(apn_label, apn_list[i].apn_name_label, apn_length)) {
	                break;
	        }
	}
	if(i >= MAX_NB_APN)     {
		fprintf(stderr,
		    "Received create session request with incorrect "
				"apn_label :%s", apn_label);
		return -1;
	}
	return apn_list[i].apn_idx;
}

void
set_ip_pool(const char *ip_str)
{
	struct in_addr *ue_ipnet = &ue_pool_list[ip_count].netid;
	if (!inet_aton(ip_str, ue_ipnet))
		rte_panic("@%s::Exiting w/ Invalid argument: %s",
				__func__, ip_str);
	printf("Parsed ueip_pool: %s; ip_count= %u\n",
			inet_ntoa(*ue_ipnet), ip_count);
	ip_count++;
}

void
set_ip_pool_mask(const char *ip_str)
{
	if (ip_count < apn_count) {
		rte_panic("@%s::Insufficient IP POOLS for APN LIST:"
				"\n\tapn_count= %u; ip_count= %u\n",
				__func__, apn_count, ip_count);
	}
	struct in_addr *ue_netmask = &ue_pool_list[mask_count].netmask;
	if (!inet_aton(ip_str, ue_netmask))
		rte_panic("@%s::Exiting w/ Invalid argument: %s",
				__func__, ip_str);
	ue_pool_list[mask_count].hosts = htonl(~ue_netmask->s_addr) + 1;
	printf("Parsed ueip_pool_mask: %s; Nb UEs= %d; mask_count= %u\n",
			inet_ntoa(*ue_netmask),
			ue_pool_list[mask_count].hosts, mask_count);
	ue_pool_list[mask_count].netid.s_addr &=
		ue_pool_list[mask_count].netmask.s_addr;
	mask_count++;
}

void
set_primary_dns(const char *ip_str)
{
	if (mask_count < apn_count) {
		rte_panic("@%s::Insufficient IP MASKS for APN LIST:"
				"\n\tapn_count= %u; mask_count= %u\n",
				__func__, apn_count, mask_count);
	}
	struct in_addr *pdns_ip = &pdns_list[pdns_count];
	if (!inet_aton(ip_str, pdns_ip))
		rte_panic("@%s::Exiting w/ Invalid argument: %s",
				__func__, ip_str);
	printf("Parsed primary_dns_ip: %s; pdns_count= %u\n",
			inet_ntoa(*pdns_ip), pdns_count);
	pdns_count++;
}

void
set_secondary_dns(const char *ip_str)
{
	if (pdns_count < apn_count) {
		rte_panic("@%s::Insufficient Primary DNS for APN LIST:"
				"\n\tapn_count= %u; pdns_count= %u\n",
				__func__, apn_count, pdns_count);
	}
	struct in_addr *sdns_ip = &sdns_list[sdns_count];
	if (!inet_aton(ip_str, sdns_ip))
		rte_panic("@%s::Exiting w/ Invalid argument: %s",
				__func__, ip_str);
	printf("Parsed secondary_dns_ip: %s; sdns_count= %u\n",
			inet_ntoa(*sdns_ip), sdns_count);
	sdns_count++;
}

void
set_timer_trshld(const char *tmr_trshld_str)
{
	if (sdns_count < apn_count) {
		rte_panic("@%s::Insufficient Secondary DNS for APN LIST:"
				"\n\tapn_count= %u; sdns_count= %u\n",
				__func__, apn_count, sdns_count);
	}
	errno = 0;
	uint64_t tmr_trshld = strtoul(tmr_trshld_str, NULL, 10);
	if (
		(errno == ERANGE && (tmr_trshld == ULONG_MAX)) ||
		(errno != 0 && tmr_trshld == 0)) {
		rte_panic("@%s::Exiting w/ Invalid argument: %s",
				__func__, tmr_trshld_str);
	}
	tmr_trshld_list[tmrth_count] = tmr_trshld;
	printf("Parsed timer_threshold: %lu; tmrth_count= %u\n",
			tmr_trshld, tmrth_count);
	tmrth_count++;
}

void
set_vol_trshld(const char *vol_trshld_str)
{
	if (tmrth_count < apn_count) {
		rte_panic("@%s::Insufficient Timer thresholds for APN LIST:"
				"\n\tapn_count= %u; tmrth_count= %u\n",
				__func__, apn_count, tmrth_count);
	}
	errno = 0;
	uint64_t vol_trshld = strtoul(vol_trshld_str, NULL, 10);
	if (
		(errno == ERANGE && (vol_trshld == ULONG_MAX)) ||
		(errno != 0 && vol_trshld == 0)) {
		rte_panic("@%s::Exiting w/ Invalid argument: %s",
				__func__, vol_trshld_str);
	}
	vol_trshld_list[volth_count] = vol_trshld;
	printf("Parsed volume_threshold: %lu; volth_count= %u\n",
			vol_trshld, volth_count);
	volth_count++;
}

void
set_ul_ambr(const char *ul_ambr_str)
{
	errno = 0;
	uint64_t ul_ambr_val = strtoul(ul_ambr_str, NULL, 10);
	if (
		(errno == ERANGE && (ul_ambr_val == ULONG_MAX)) ||
		(errno != 0 && ul_ambr_val == 0)) {
		rte_panic("@%s::Exiting w/ Invalid argument: %s",
				__func__, ul_ambr_str);
	}
	ul_ambr_list[ul_ambr_count] = ul_ambr_val;
	printf("Parsed UL AMBR value: %lu; ul_ambr_count= %u\n",
			ul_ambr_val, ul_ambr_count);
	ul_ambr_count++;
}

void
set_dl_ambr(const char *dl_ambr_str)
{
	errno = 0;
	uint64_t dl_ambr_val = strtoul(dl_ambr_str, NULL, 10);
	if (
		(errno == ERANGE && (dl_ambr_val == ULONG_MAX)) ||
		(errno != 0 && dl_ambr_val == 0)) {
		rte_panic("@%s::Exiting w/ Invalid argument: %s",
				__func__, dl_ambr_str);
	}
	dl_ambr_list[dl_ambr_count] = dl_ambr_val;
	printf("Parsed DL AMBR value: %lu; dl_ambr_count= %u\n",
			dl_ambr_val, dl_ambr_count);
	dl_ambr_count++;
}

static inline int ffs_bit(void *buf, int len)
{
	int num_long_chunks = len / 64;
	for (int i = 0;i<num_long_chunks;i++) {
		if (((unsigned long *)buf)[i] != 0)
			return (i*64 + __builtin_ffsll(((unsigned long *)buf)[i])-1);
	}
	return -1;
}

uint32_t
acquire_ip(apn *apn_requested, struct in_addr *ipv4)
{
	int next_ip_index =
				ffs_bit(apn_requested->ue_ipbf, CP_UE_BLOCK*8);
	ue_ippool *ue_net = apn_requested->ue_pool;
	if ((next_ip_index < 0)||(next_ip_index >= ue_net->hosts)) {
		fprintf(stderr, "IP Pool depleted\n");
		return GTPV2C_CAUSE_ALL_DYNAMIC_ADDRESSES_OCCUPIED;
	}
	ipv4->s_addr =
				ntohl(htonl(ue_net->netid.s_addr) + next_ip_index);
	apn_requested->ue_ipbf[next_ip_index/8] &=
								~(1 << (next_ip_index %8));
	return 0;
}

uint32_t
release_ip(apn *apn_used, struct in_addr *ipv4)
{
	uint32_t ip_index = ipv4->s_addr-htonl(apn_used->ue_pool->netid.s_addr);
	apn_used->ue_ipbf[ip_index/8] |=
								(1 << (ip_index %8));
	return 0;
}

void
print_ue_context_by(struct rte_hash *h, ue_context *context)
{
	uint64_t *key;
	int32_t ret;
	uint32_t next = 0;
	int i;
	printf(" %16s %1s %16s %16s %8s %8s %11s\n", "imsi", "u", "mei",
			"msisdn", "s11-teid", "s11-ipv4", "56789012345");
	if (context) {
		printf("*%16lx %1lx %16lx %s %8x %15s ", context->imsi,
		    (uint64_t) context->unathenticated_imsi, context->mei,
		    context->msisdn, context->s11_sgw_gtpc_teid,
		     inet_ntoa(context->s11_sgw_gtpc_ipv4));
		for (i = 0; i < MAX_BEARERS; ++i) {
			printf("%c", (context->bearer_bitmap & (1 << i))
					? '1' : '0');
		}
		printf("\t0x%04x\n", context->bearer_bitmap);
	}
	if (h == NULL)
		return;
	while (1) {
		ret = rte_hash_iterate(h, (const void **) &key,
				(void **) &context, &next);
		if (ret < 0)
			break;
		printf(" %16lx %1lx %16lx %s %8x %15s ",
			context->imsi,
			(uint64_t) context->unathenticated_imsi,
			context->mei,
		    context->msisdn, context->s11_sgw_gtpc_teid,
		    inet_ntoa(context->s11_sgw_gtpc_ipv4));
		for (i = 0; i < MAX_BEARERS; ++i) {
			printf("%c", (context->bearer_bitmap & (1 << i))
					? '1' : '0');
		}
		printf("\t0x%4x", context->bearer_bitmap);
		puts("");
	}
}

int
create_ue_context(uint8_t *imsi_val, uint16_t imsi_len,
		uint8_t ebi, ue_context **context, uint8_t apn_indx)
{
	int ret;
	int i;
	uint8_t ebi_index;
	uint64_t imsi = UINT64_MAX;
	pdn_connection *pdn = NULL;
	eps_bearer *bearer = NULL;

	memcpy(&imsi, imsi_val, imsi_len);
	/* ASR- TMOPL VCCCCB-28
	 * Many PDN connections for the same IMSI on a given APN not allowed
	 * REQD: Many PDN connections same IMSI different APN
	 * ue_context_by_imsi_hash::Key= fn(IMSI, apn)
	 * Insert 4 bits apn_indx @byte7 of imsi; MAX_NB_APN: MAX VAL= 15
	 */
	*((uint8_t *)(&imsi) + APN_IMSI_KEY_POSTN) =
		*((uint8_t *)(&imsi) + APN_IMSI_KEY_POSTN) << APN_IMSI_KEY_LEN | apn_indx;

	ret = rte_hash_lookup_data(ue_context_by_imsi_hash, &imsi,
	    (void **) &(*context));

	/* On no existing ue_context: Allocate new ue_context
	 * Add entry: ue_context_by_imsi_hash::key= imsi */
	if (ret == -ENOENT) {
		(*context) = rte_zmalloc_socket(NULL, sizeof(ue_context),
		    RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (*context == NULL) {
			fprintf(stderr, "Failure to allocate ue context "
					"structure: %s (%s:%d)\n",
					rte_strerror(rte_errno),
					__FILE__,
					__LINE__);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
		(*context)->imsi = imsi;
		ret = rte_hash_add_key_data(ue_context_by_imsi_hash,
		    (const void *) &(*context)->imsi, (void *) (*context));
		if (ret < 0) {
			fprintf(stderr,
				"%s - Error on rte_hash_add_key_data add\n",
				strerror(ret));
			rte_free((*context));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
	}

	if ((spgw_cfg == SGWC) || (spgw_cfg == SPGWC)) {
		(*context)->s11_sgw_gtpc_teid = s11_sgw_gtpc_base_teid
		    + s11_sgw_gtpc_teid_offset;
		++s11_sgw_gtpc_teid_offset;

	} else if (spgw_cfg == PGWC){
		(*context)->s11_sgw_gtpc_teid = s5s8_pgw_gtpc_base_teid
			+ s5s8_pgw_gtpc_teid_offset;
	}

	/* On no existing ue_context:
	 * Add entry: ue_context_by_fteid_hash::key= s11_sgw_gtpc_teid */
	ret = rte_hash_add_key_data(ue_context_by_fteid_hash,
	    (const void *) &(*context)->s11_sgw_gtpc_teid,
	    (void *) (*context));

	if (ret < 0) {
		fprintf(stderr,
			"%s - Error on ue_context_by_fteid_hash add\n",
			strerror(ret));
		rte_hash_del_key(ue_context_by_imsi_hash,
		    (const void *) &(*context)->imsi);
		if (ret < 0) {
			/* If we get here something bad happened. The
			 * context that was added to
			 * ue_context_by_imsi_hash above was not able
			 * to be removed.
			 */
			rte_panic("%s - Error on "
				"ue_context_by_imsi_hash del\n",
				strerror(ret));
		}
		rte_free((*context));
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	ebi_index = ebi - 5;
	pdn = (*context)->pdns[ebi_index];
	bearer = (*context)->eps_bearers[ebi_index];

	if (bearer) {
		/* bearer context exists */
		if (pdn) {
			/* bearer pdn connection exists: Overwrite old session
			 * ...clean up old session's dedicated bearers */
			for (i = 0; i < MAX_BEARERS; ++i) {
				if (!pdn->eps_bearers[i])
					continue;
				if (i == ebi_index) {
					bzero(bearer, sizeof(*bearer));
					continue;
				}
				rte_free(pdn->eps_bearers[i]);
				pdn->eps_bearers[i] = NULL;
				(*context)->eps_bearers[i] = NULL;
				(*context)->bearer_bitmap &= ~(1 << ebi_index);
			}
		} else {
			/* No bearer pdn connection exists:
			 * Create default bearer on another pdn connection's dedicated bearer */
			bearer->pdn->eps_bearers[ebi_index] = NULL;
			bzero(bearer, sizeof(*bearer));
			pdn = rte_zmalloc_socket(NULL,
				sizeof(struct pdn_connection_t),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
			if (pdn == NULL) {
				fprintf(stderr, "Failure to allocate PDN "
						"structure: %s (%s:%d)\n",
						rte_strerror(rte_errno),
						__FILE__,
						__LINE__);
				rte_free((*context));
				return GTPV2C_CAUSE_SYSTEM_FAILURE;
			}
			(*context)->pdns[ebi_index] = pdn;
			(*context)->num_pdns++;
			pdn->eps_bearers[ebi_index] = bearer;
			pdn->default_bearer_id = ebi;
			pdn->num_bearers++;
		}
	} else {
		/* No bearer context exists:
		 * Create default bearer & pdn connection */
		bearer = rte_zmalloc_socket(NULL, sizeof(eps_bearer),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (bearer == NULL) {
			fprintf(stderr, "Failure to allocate bearer "
					"structure: %s (%s:%d)\n",
					rte_strerror(rte_errno),
					__FILE__,
					__LINE__);
			rte_free((*context));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
		bearer->eps_bearer_id = ebi;
		pdn = rte_zmalloc_socket(NULL, sizeof(struct pdn_connection_t),
		    RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (pdn == NULL) {
			fprintf(stderr, "Failure to allocate PDN "
					"structure: %s (%s:%d)\n",
					rte_strerror(rte_errno),
					__FILE__,
					__LINE__);
			rte_free((*context));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
		(*context)->eps_bearers[ebi_index] = bearer;
		(*context)->pdns[ebi_index] = pdn;
		/* ASR- TMOPL VCCCCB-25:
		 * Increment num_pdns for default bearer */
		(*context)->num_pdns++;
		(*context)->bearer_bitmap |= (1 << ebi_index);
		pdn->eps_bearers[ebi_index] = bearer;
		pdn->default_bearer_id = ebi;
		pdn->num_bearers++;
	}

	for (i = 0; i < MAX_FILTERS_PER_UE; ++i)
		bearer->packet_filter_map[i] = -ENOENT;

	bearer->pdn = pdn;
	bearer->eps_bearer_id = ebi;
	return 0;
}

