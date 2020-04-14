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

/* Reference: CDR ParameterDescription TS32298-g00 */

#ifndef _SCTF_H_
#define _SCTF_H_

#include "gtpv2c.h"
#include "common_ipc_api.h"

#define NAME_LEN 255
#define DER_LEN 512
#define SLCTN_MODE_MASK 0x03
#define TIMESTAMP_LEN 9
#define TAG_FOR_NON_STRUCT_TYPE 128
#define TAG_FOR_STRUCT_TYPE 160
#define DEFAULT_INT_LEN 2
#define SUB_HEAD_LEN 3
#define DEFAULT_BOOL_LEN 1
#define ECGI_LEN 4
#define PLMN_OCT_LEN 3
#define BOOL_TRUE 0xFF
#define BOOL_FALSE 0x00
#define ASC_PLUS 0x2B
#define ASC_MINUS 0x2D
#define TAG_FOR_MULTI_BYTE 0xBF
#define TAG_FOR_SEQ 0x30
#define PGW_REC_TYPE 0x4F
#define TAG_FOR_SEQ_LOSD 0x22 //Tag for List of Service Data
#define LENGTH_INDICATOR 0x82
#define PGW_REC_HEADER_LEN 5
#define ZERO_LEN 0x00
#define PDPTYPE_ORG_NUM 0x1
#define PDPTYPE_IPV4 0x21
#define RATING_GROUP_VOL 100
#define APN_OI_LEN 20
#define MULTIBYTE_INDI 0x9f
#define ULI_TYPE 0x18
#define ASC_VAL_FOR_DOT 0x2E
#define SERVING_NODE_TYPE_TAG 10
#define SERVING_NODE_TYPE_VAL 5
/*
 * GPRS Records defined @TS32298-g00:Sec 5.2.2.2 PS Domain CDRs
 */
enum pgw_tag_name {
	RECORD_TYPE,
	SERVED_IMSI = 3,
	PGW_ADDRESS,
	CHARGING_ID,
	SERVINGNODE_ADDRESS,
	ACCESS_POINT_NAME,
	PDP_PDN_TYPE,
	SERVED_PDPPDN_ADDRESS,
	DYNAMIC_ADDRESSFLAG = 11,
	LISTOF_TRAFFIC_VOLUME,
	REC_OPENING_TIME,
	DURATION,
	CAUSE_FOR_REC_CLOSING,
	DIAGNOSTICS,
	REC_SEQ_NUMBER,
	NODE_ID,
	REC_EXTN,
	LOCAL_SEQ_NO,
	APN_SELECTION_MODE,
	SERVED_MSISDN,
	CHARGING_CHAR,
	CHCH_SELECTION_MODE,
	IMSI_SIG_CTX,
	SERVINGNODE_PLMN_ID = 27,
	PS_FURNISH_CHRG_INFO,
	SERVED_IMEI,
	RAT_TYPE,
	MSTIME_ZONE,
	USER_LOC_INFO,
	CAMEL_CHRG_INFO,
	LIST_OF_SERVICE_DATA,
	SERVING_NODE_TYPE,
	SERVED_MNNAI,
	PGW_PLMN_ID,
	START_TIME,
	STOP_TIME,
	SERVED_3GPP2_MEID,
	PDN_CONN_CHRG_ID,
	IMSI_UNAUTHEN_FLAG,
	USER_CSG_INFO,
	GPP2_USER_LOC_INFO,
	SERVED_PDPPDN_ADD_EXT,
	LOW_PRIO_INDI,
	DYN_ADDRESS_FLAG_EXT,
	SERVING_NODE_IPV6_ADDRESS = 49,
	PGW_IPV6_ADD_USED
};

enum chservice_service_tag_name {
	RATING_GROUP = 1,
	CHRG_RULE_BASE_NAME,
	RESULT_CODE,
	LOCAL_SEQ_NUM,
	TIME_OF_FIRST_USE,
	TIME_OF_LAST_USE,
	TIME_USAGE,
	SERVICE_COND_CHG,
	QOS_INFO_NEG,
	SERVING_NODE_ADDRESS,
	DATA_VOL_FBC_UL = 12,
	DATA_VOL_FBC_DL,
	TIME_OF_REPORT,
	USER_LOCATION_INFO = 20,
	RAT_TYPE_SRV = 30,
};

enum data_type {
	BOOLEAN,
	ENUMERATED,
	INTEGER,
	BITSTRING,
	OCTETSTRING,
	IPADDRESS
};

typedef enum GPRSRecord {
	MOCALL_RECORD = 0,
	MT_RECORD = 1,
	SGW_RECORD = 84,
	PGW_RECORD = 85,
	MMTRF_RECORD = 88
} gprs_record_typs_t;
gprs_record_typs_t cdr_record_type;

typedef enum APNSelectionMode {
	MS_NETWORK_PROVIDED_SUBSCRIPTION_VERIFIED = 0,
	MS_PROVIDED_SUBSCRIPTION_NOTVERIFIED = 1,
	NETWORK_PROVIDED_SUBSCRIPTION_NOTVERIFIED = 2
} apn_selection_mode_t;
apn_selection_mode_t apn_slctn_md;

typedef enum ChChSelectionMode {
	SERVINGNODE_SUPPLIED = 0,
	SUBSCRIPTION_SPECIFIC = 1,
	APN_SPECIFIC = 2,
	HOME_DEFAULT = 3,
	ROAMING_DEFAULT = 4,
	VISITING_DEFAULT = 5,
	FIXED_DEFAULT = 6
} chch_selection_mode_t;
chch_selection_mode_t chch_slctn_md;

typedef enum ServiceConditionChange {
	QOS_CHANGE = 0,
	SGSN_CHANGE = 1,

	SGSN_PLMNID_CHANGE = 2,
	TARIFF_TIME_SWITCH = 3,
	PDP_CONTEXT_RELEASE = 4,
	RAT_CHANGE = 5,
	SERVICE_IDLEDOUT = 6,
	RESERVED = 7,
	CONFIGURATION_CHANGE = 8,
	SERVICESTOP = 9,

	DCCA_TIME_THRESHOLD_REACHED = 10,
	DCCA_VOLUME_THRESHOLD_REACHED = 11,
	DCCA_SERVICE_SPECIFIC_UNIT_THRESHOLD_REACHED = 12,
	DCCA_TIME_EXHAUSTED = 13,
	DCCA_VOLUME_EXHAUSTED = 14,
	DCCA_VALIDITY_TIMEOUT = 15,
	RESERVED1 = 16,

	DCCA_REAUTHORISATION_REQUEST = 17,
	DCCA_CONTINUE_ONGOINGSESSION = 18,

	DCCA_RETRYANDTERMINATE_ONGOINGSESSION = 19,

	DCCA_TERMINATE_ONGOINGSESSION = 20,

	CGI_SAICHANGE = 21,
	RAI_CHANGE = 22,
	DCCA_SERVICE_SPECIFIC_UNITEXHAUSTED = 23,
	RECORD_CLOSURE = 24,
	TIMELIMIT = 25,

	VOLUMELIMIT = 26,

	SERVICE_SPECIFIC_UNITLIMIT = 27,
	ENVELOPE_CLOSURE = 28,
	ECGI_CHANGE = 29,
	TAI_CHANGE = 30,
	USER_LOCATION_CHANGE = 31,
	USER_CSGINFORMATION_CHANGE = 32,
	PRESENCE_INPRA_CHANGE = 33,

	ACCESS_CHANGEOF_SDF = 34,
	INDIRECT_SERVICE_CONDITION_CHANGE = 35,
	SERVING_PLMN_RATE_CONTROL_CHANGE = 36,

	APN_RATE_CONTROL_CHANGE = 37
} service_condition_change_t;
uint64_t svc_cond_chg;

typedef struct pdn_type {
	uint8_t pdn_type :3;
	uint8_t spare :5;
} pdn_type_t;

typedef struct ue_timezone {
uint8_t timezone;
uint8_t spare1 :6;
uint8_t ds_time :2;
} ue_timezone_t;

typedef struct cdr_container {
uint32_t ratingGroup; /* TS32.298::Datatype= INTEGER */
uint8_t chargingRuleBaseName[NAME_LEN];/* TS32.298::Datatype= IA5String */
uint32_t resultCode; /* TS32.298::Datatype= INTEGER */
uint32_t localSequenceNumber; /* TS32.298::Datatype= INTEGER */
uint64_t timeOfFirstUsage; /* TS32.298::Datatype= OCTET(9) */
uint64_t timeOfLastUsage; /* TS32.298::Datatype= OCTET(9) */
uint32_t timeUsage; /* TS32.298::Datatype= INTEGER */
uint64_t serviceConditionChange; /* TS32.298::Datatype= BIT STRING */
uint32_t qCI; /* TS32.298::Datatype= INTEGER */
uint32_t maxRequestedBandwithUL; /* TS32.298::Datatype= INTEGER */
uint32_t maxRequestedBandwithDL; /* TS32.298::Datatype= INTEGER */
uint32_t guaranteedBitrateUL; /* TS32.298::Datatype= INTEGER */
uint32_t guaranteedBitrateDL; /* TS32.298::Datatype= INTEGER */
uint32_t aRP; /* TS32.298::Datatype= INTEGER */
uint32_t datavolumeFBCUplink; /* TS32.298::Datatype= INTEGER */
uint32_t datavolumeFBCDownlink; /* TS32.298::Datatype= INTEGER */
uint64_t timeOfReport; /* TS32.298::Datatype= OCTET(9) */
uint32_t userLocationInformation; /* TS32.298::Datatype= OCTET STRING */
} cdr_container_t;

typedef struct sctf_msg {
/* recordType value:: TS32.298::ggsnMBMSRecord [77] GGSNMBMSRecord */
uint32_t recordType; /* TS32.298::Datatype= INTEGER */
uint8_t servedIMSI[BINARY_IMSI_LEN]; /* TS32.298::Datatype= OCTET(8) */
struct in_addr p_GWAddress; /* TS32.298::Datatype= IP ADDRESS */
uint32_t chargingID; /* TS32.298::Datatype= INTEGER */
struct in_addr servingNodeAddress; /* TS32.298::Datatype= IP ADDRESS */
uint8_t accessPointNameNI[NAME_LEN]; /* TS32.298::Datatype= IA5String */
pdn_type_t pdpPDNType; /* TS32.298::Datatype= OCTET STRING(2) */
struct in_addr servedPDPPDNAddress; /* TS32.298::Datatype= IP ADDRESS */
uint8_t dynamicAddressFlag; /* TS32.298::Datatype= BOOLEAN */
uint64_t recordOpeningTime; /* TS32.298::Datatype= OCTET(9) */
uint32_t duration; /* TS32.298::Datatype= INTEGER */
uint32_t causeForRecClosing; /* TS32.298::Datatype= INTEGER */
uint8_t nodeID[NAME_LEN]; /* TS32.298::Datatype= IA5String */
uint8_t apnSelectionMode; /* TS32.298::Datatype= ENUMERATED */
uint8_t servedMSISDN[BINARY_MSISDN_LEN]; /* TS32.298::Datatype= OCTET(8) */
uint32_t chargingCharacteristics; /* TS32.298::Datatype= OCTET STRING(2) */
uint8_t chChSelectionMode; /* TS32.298::Datatype= ENUMERATED */
mcc_mnc_t servingNodePLMNIdentifier; /* TS32.298::Datatype= OCTET STRING(3) */
uint8_t servedIMEISV[BINARY_MEI_LEN]; /* TS32.298::Datatype= OCTET(8) */
uint32_t rATType; /* TS32.298::Datatype= INTEGER */
ue_timezone_t mSTimeZone; /* TS32.298::Datatype= OCTET STRING(2) */
uint8_t uli_info[ULI_LEN]; /* TS32.298::Datatype= OCTET STRING */
tai_t tai; /* TS32.298::Datatype= OCTET */
ecgi_t ecgi; /* TS32.298::Datatype= OCTET */
cdr_container_t cdr_container;
} sctf_msg_t;

uint16_t sctf_to_asn1_encode(sctf_msg_t *sctf_msg, uint8_t *der);
/**
 * Assemble Secure Charge Trigger Function (SCTF)  message
 * @param buf
 *	buf - message buffer.
 *
 * @return
 *	void
 */
void sctf_msg_assemble(struct resp_msgbuf *rbuf);
#endif /* _SCTF_H_ */
