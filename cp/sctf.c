#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/asn1.h>
#include "sctf.h"

sctf_msg_t *sctf_msg;
uint32_t localSeqNo = 0;

static int
encode_data_to_der(enum data_type type, uint16_t tag_idx, uint64_t val,
		uint8_t *der, uint16_t *der_index)
{
	char str[NAME_LEN];
	char str_cat[NAME_LEN];
	int i, len, set_bit, first_bit = 1;
	ASN1_TYPE *asn_ptr = NULL;
	ASN1_INTEGER *myval = NULL;
	unsigned char *buf = NULL;

	switch(type) {
		case INTEGER:
		case OCTETSTRING:
			myval = ASN1_INTEGER_new();
			ASN1_INTEGER_set(myval, val);
			len = i2d_ASN1_INTEGER(myval, &buf);
			if (tag_idx >= MSTIME_ZONE) {
				if (tag_idx == SERVING_NODE_TYPE) {
					der[(*der_index)++] = TAG_FOR_MULTI_BYTE;
					der[(*der_index)++] = tag_idx;
					der[(*der_index)++] = buf[1] + 2; //TAG + LENGTH IND
					der[(*der_index)++] = SERVING_NODE_TYPE_TAG;
				} else {
					der[(*der_index)++] = MULTIBYTE_INDI;
					der[(*der_index)++] = tag_idx;
				}
			} else {
				der[(*der_index)++] = TAG_FOR_NON_STRUCT_TYPE + tag_idx;
			}
			der[(*der_index)++] = buf[1];// TYPE, LEN, DATA ...
			for(i = DEFAULT_INT_LEN; i < len; i++)
				der[(*der_index)++] = buf[i];
			ASN1_INTEGER_free(myval);
			if(buf)
				free(buf);
			break;
		case BITSTRING:
			if (!val)
				return -1;
			sprintf(str,"FORMAT:BITLIST,BITSTRING:");
			while(val) {
				set_bit = __builtin_ffsll(val)-1;
				if(first_bit) {
					sprintf(str_cat,"%d",set_bit);
					first_bit = 0;
				} else {
					sprintf(str_cat,",%d",set_bit);
				}
				strcat(str, str_cat);
				val &= ~(1LLU << (set_bit));
			}
			asn_ptr = ASN1_generate_nconf(str, NULL);
			der[(*der_index)++] = TAG_FOR_NON_STRUCT_TYPE + tag_idx;
			der[(*der_index)++] = asn_ptr->value.bit_string->length;
			for(i = 0; i < asn_ptr->value.bit_string->length; i++)
				der[(*der_index)++] = asn_ptr->value.bit_string->data[i];
			ASN1_TYPE_free(asn_ptr);
			break;
		case BOOLEAN:
			der[(*der_index)++] = TAG_FOR_NON_STRUCT_TYPE + tag_idx;
			der[(*der_index)++] = DEFAULT_BOOL_LEN;
			if(val)
				der[(*der_index)++] = BOOL_TRUE;
			else
				der[(*der_index)++] = BOOL_FALSE;
			break;
		case ENUMERATED:
			sprintf(str,"ENUMERATED:%lu",val);
			asn_ptr = ASN1_generate_nconf(str, NULL);
			der[(*der_index)++] = TAG_FOR_NON_STRUCT_TYPE + tag_idx;
			der[(*der_index)++] = asn_ptr->value.enumerated->length;
			for(i = 0; i < asn_ptr->value.enumerated->length; i++)
				der[(*der_index)++] = asn_ptr->value.enumerated->data[i];
			ASN1_TYPE_free(asn_ptr);
			break;
		case IPADDRESS:
			sprintf(str,"INTEGER:%lu",val);
			asn_ptr = ASN1_generate_nconf(str, NULL);

			der[(*der_index)++] = TAG_FOR_STRUCT_TYPE + tag_idx;
			if (tag_idx == SERVED_PDPPDN_ADDRESS) {
				der[(*der_index)++] = asn_ptr->value.integer->length + 4;
				der[(*der_index)++] = TAG_FOR_STRUCT_TYPE;
			}
			der[(*der_index)++] = asn_ptr->value.integer->length + 2;
			der[(*der_index)++] = TAG_FOR_NON_STRUCT_TYPE;
			der[(*der_index)++] = asn_ptr->value.integer->length;
			for(i = 0; i < asn_ptr->value.integer->length; i++)
				der[(*der_index)++] = asn_ptr->value.integer->data[i];
			ASN1_TYPE_free(asn_ptr);
			break;
		default:
			printf("Invalid data type\n");
	}
	return 0;
}

static int
encode_octetstring_to_der(uint16_t tag_idx, uint8_t *ptr, int length,
		uint8_t *der, uint16_t *der_index)
{
	der[(*der_index)++] = TAG_FOR_NON_STRUCT_TYPE + tag_idx;
	der[(*der_index)++] = length;
	for(int i = 0; i < length; i++) {
		der[(*der_index)++] = ptr[i];
	}
	return 0;
}

static int
encode_timestamp_to_der(uint16_t tag_idx, uint64_t val, uint8_t *der,
		uint16_t *der_index)
{
	struct tm *ptm;
	unsigned long ulval;
	ptm = localtime((time_t *)&val);
	if(tag_idx == START_TIME || tag_idx == STOP_TIME) {
		der[(*der_index)++] = MULTIBYTE_INDI;
		der[(*der_index)++] = tag_idx;
	} else {
		der[(*der_index)++] = TAG_FOR_NON_STRUCT_TYPE + tag_idx;
	}
	der[(*der_index)++] = TIMESTAMP_LEN;
	der[(*der_index)++] = ((((ptm->tm_year-100)/10) << 4) |
							((ptm->tm_year-100) % 10));
	der[(*der_index)++] = ((((ptm->tm_mon+1)/10) << 4) |
							((ptm->tm_mon+1) % 10));
	der[(*der_index)++] = (((ptm->tm_mday/10) << 4) | (ptm->tm_mday % 10));
	der[(*der_index)++] = (((ptm->tm_hour/10) << 4) | (ptm->tm_hour % 10));
	der[(*der_index)++] = (((ptm->tm_min/10) << 4) | (ptm->tm_min % 10));
	der[(*der_index)++] = (((ptm->tm_sec/10) << 4) | (ptm->tm_sec % 10));
	if(ptm->tm_gmtoff < 0) {
		ulval = -ptm->tm_gmtoff;
		der[(*der_index)++] = ASC_MINUS;
	} else {
		der[(*der_index)++] = ASC_PLUS;
		ulval = ptm->tm_gmtoff;
	}
	der[(*der_index)++] = ((((ulval/3600)/10) << 4) | ((ulval/3600) % 10));
	der[(*der_index)++] = (((((ulval%3600)/60)/10) << 4) | (((ulval%3600)/60) % 10));
	return 0;
}

uint16_t sctf_to_asn1_encode(sctf_msg_t *sctf_msg, uint8_t *der)
{
	uint16_t der_index = 0, der_index_tmp = 0, rec_len = 0, uli_len = 0;
	uint8_t tmp[3] = {0};
	int i = 0;

	//Update SET Tag and length
	der[der_index++] = TAG_FOR_MULTI_BYTE;
	der[der_index++] = PGW_REC_TYPE;
	der[der_index++] = LENGTH_INDICATOR;
	//Initialized to 0, Length should be updated once all structure populated
	der[der_index++] = ZERO_LEN;
	der[der_index++] = ZERO_LEN;

	//Encode the main structure
	encode_data_to_der(INTEGER, RECORD_TYPE, sctf_msg->recordType,
			der, &der_index);
	encode_octetstring_to_der(SERVED_IMSI, sctf_msg->servedIMSI,
			BINARY_IMSI_LEN, der, &der_index);
	encode_data_to_der(IPADDRESS, PGW_ADDRESS, sctf_msg->p_GWAddress.s_addr,
			der, &der_index);
	encode_data_to_der(INTEGER, CHARGING_ID, sctf_msg->chargingID, der,
			&der_index);
	encode_data_to_der(IPADDRESS, SERVINGNODE_ADDRESS,
			sctf_msg->servingNodeAddress.s_addr, der, &der_index);
	encode_octetstring_to_der(ACCESS_POINT_NAME, sctf_msg->accessPointNameNI,
			strlen((char *)sctf_msg->accessPointNameNI), der, &der_index);

	der[der_index++] = TAG_FOR_NON_STRUCT_TYPE + PDP_PDN_TYPE;
	der[der_index++] = DEFAULT_INT_LEN;
	der[der_index++] = PDPTYPE_ORG_NUM;
	der[der_index++] = PDPTYPE_IPV4;

	encode_data_to_der(IPADDRESS, SERVED_PDPPDN_ADDRESS,
			sctf_msg->servedPDPPDNAddress.s_addr, der, &der_index);
	encode_data_to_der(BOOLEAN, DYNAMIC_ADDRESSFLAG,
			sctf_msg->dynamicAddressFlag, der, &der_index);
	encode_timestamp_to_der(REC_OPENING_TIME, sctf_msg->recordOpeningTime,
			der, &der_index);
	encode_data_to_der(INTEGER, DURATION, sctf_msg->duration, der, &der_index);
	encode_data_to_der(INTEGER, CAUSE_FOR_REC_CLOSING,
			sctf_msg->causeForRecClosing, der, &der_index);
	encode_data_to_der(INTEGER, REC_SEQ_NUMBER,
			sctf_msg->cdr_container.localSequenceNumber + 1, der, &der_index);
	encode_octetstring_to_der(NODE_ID, sctf_msg->nodeID,
			strlen((char *)sctf_msg->nodeID), der, &der_index);
	encode_data_to_der(INTEGER, LOCAL_SEQ_NO,
			++localSeqNo, der, &der_index);
	encode_data_to_der(ENUMERATED, APN_SELECTION_MODE,
			sctf_msg->apnSelectionMode, der, &der_index);
	encode_octetstring_to_der(SERVED_MSISDN, &sctf_msg->servedMSISDN[1],
			sctf_msg->servedMSISDN[0], der, &der_index);
	encode_data_to_der(OCTETSTRING, CHARGING_CHAR,
			sctf_msg->chargingCharacteristics, der, &der_index);
	encode_data_to_der(ENUMERATED, CHCH_SELECTION_MODE,
			sctf_msg->chChSelectionMode, der, &der_index);

	//Encoding plmn
	tmp[0] = sctf_msg->servingNodePLMNIdentifier.mcc_digit_2 << 4 |
		sctf_msg->servingNodePLMNIdentifier.mcc_digit_1;
	tmp[1] = sctf_msg->servingNodePLMNIdentifier.mnc_digit_3 << 4 |
		sctf_msg->servingNodePLMNIdentifier.mcc_digit_3;
	tmp[2] = sctf_msg->servingNodePLMNIdentifier.mnc_digit_2 << 4 |
		sctf_msg->servingNodePLMNIdentifier.mnc_digit_1;
	der[der_index++] = TAG_FOR_NON_STRUCT_TYPE + SERVINGNODE_PLMN_ID;
	der[der_index++] = PLMN_OCT_LEN;
	for(i = 0; i < PLMN_OCT_LEN; i++)
		der[der_index++] = tmp[i];

	encode_octetstring_to_der(SERVED_IMEI, sctf_msg->servedIMEISV,
			BINARY_MEI_LEN, der, &der_index);
	encode_data_to_der(INTEGER, RAT_TYPE, sctf_msg->rATType, der, &der_index);

	der[der_index++] = MULTIBYTE_INDI;
	der[der_index++] = MSTIME_ZONE;
	der[der_index++] = DEFAULT_INT_LEN;
	der[der_index++] = sctf_msg->mSTimeZone.timezone;
	der[der_index++] = sctf_msg->mSTimeZone.ds_time << 6 | sctf_msg->mSTimeZone.spare1;

	//Populate User Location Information
	der[der_index++] = MULTIBYTE_INDI;
	der[der_index++] = USER_LOC_INFO;
	uli_len = strlen((char *)sctf_msg->uli_info);
	der[der_index++] = uli_len;
	for(i = 0; i < uli_len; i++) {
		der[der_index++] = sctf_msg->uli_info[i];
	}

	//Store the der_index once main struct populated, this will be used for sub-structure length calculation
	der_index_tmp = der_index;

	//Update SEQUENCE Tag and length for sub-structure
	// TAG_FOR_SEQ_LOSD = TAG_FOR_STRUCT_TYPE + LIST_OF_SERVICE_DATA + 1
	der[der_index++] = TAG_FOR_MULTI_BYTE;
	der[der_index++] = TAG_FOR_SEQ_LOSD;
	//Initialized to 0, Length should be updated once sub structure populated;
	der[der_index++] = ZERO_LEN;
	der[der_index++] = TAG_FOR_SEQ;
	//Initialized to 0, Length should be updated once sub structure populated;
	der[der_index++] = ZERO_LEN;

	//Encoding sub structure
	encode_data_to_der(INTEGER, RATING_GROUP,
			sctf_msg->cdr_container.ratingGroup, der, &der_index);
	encode_octetstring_to_der(CHRG_RULE_BASE_NAME,
			sctf_msg->cdr_container.chargingRuleBaseName,
			strlen((char *)sctf_msg->cdr_container.chargingRuleBaseName),
			der, &der_index);
	encode_data_to_der(INTEGER, RESULT_CODE,
			sctf_msg->cdr_container.resultCode, der, &der_index);
	encode_data_to_der(INTEGER, LOCAL_SEQ_NUM,
			sctf_msg->cdr_container.localSequenceNumber + 1, der, &der_index);
	encode_timestamp_to_der(TIME_OF_FIRST_USE,
			sctf_msg->recordOpeningTime, der, &der_index);
	encode_timestamp_to_der(TIME_OF_LAST_USE,
			sctf_msg->cdr_container.timeOfReport, der, &der_index);
	encode_data_to_der(INTEGER, TIME_USAGE,
			(uint64_t)(difftime((time_t)sctf_msg->cdr_container.timeOfReport, (time_t)sctf_msg->recordOpeningTime)), der, &der_index);
	encode_data_to_der(BITSTRING, SERVICE_COND_CHG,
			sctf_msg->cdr_container.serviceConditionChange, der, &der_index);
	//NO-NEED to populate these info now
	//encode_data_to_der(INTEGER, sctf_msg->cdr_container.qCI);
	//encode_data_to_der(INTEGER, sctf_msg->cdr_container.maxRequestedBandwithUL);
	//encode_data_to_der(INTEGER, sctf_msg->cdr_container.maxRequestedBandwithDL);
	//encode_data_to_der(INTEGER, sctf_msg->cdr_container.guaranteedBitrateUL);
	//encode_data_to_der(INTEGER, sctf_msg->cdr_container.guaranteedBitrateDL);
	//encode_data_to_der(INTEGER, sctf_msg->cdr_container.aRP);
	encode_data_to_der(INTEGER, DATA_VOL_FBC_UL,
			sctf_msg->cdr_container.datavolumeFBCUplink, der, &der_index);
	encode_data_to_der(INTEGER, DATA_VOL_FBC_DL,
			sctf_msg->cdr_container.datavolumeFBCDownlink, der, &der_index);
	encode_timestamp_to_der(TIME_OF_REPORT,
			sctf_msg->cdr_container.timeOfReport, der, &der_index);

	//Len = Tot Len - Main struct Len - (substruct tag + TAG + Len)
	der[der_index_tmp + 2] =
		der_index - der_index_tmp - SUB_HEAD_LEN;
	//Sub struct len = Tot Len - Main struct Len - (substruct tag + LOSQ + Len + SEQ TAG + Len)
	der[der_index_tmp + 4] = der_index - der_index_tmp - PGW_REC_HEADER_LEN;

	encode_data_to_der(INTEGER, SERVING_NODE_TYPE, SERVING_NODE_TYPE_VAL,
			der, &der_index);
	//Encode Start/Stop Time
	if (!sctf_msg->cdr_container.localSequenceNumber) {
		encode_timestamp_to_der(START_TIME,
				sctf_msg->recordOpeningTime, der, &der_index);
	}
	if ((!sctf_msg->causeForRecClosing) || (sctf_msg->causeForRecClosing == CDR_REC_ABNORMAL_REL)) {
		encode_timestamp_to_der(STOP_TIME,
				sctf_msg->cdr_container.timeOfReport, der, &der_index);
	}
	der[der_index]='\0';

	//Record Len = Total len - HEADER (SET TAG + PGW ID + LENGTH INDICATOR + LENGTH(2))
	rec_len = der_index - PGW_REC_HEADER_LEN;
	der[3] = *((uint8_t *)(&rec_len) + 1);
	der[4] = *((uint8_t *)(&rec_len) + 0);
#if 0
	printf("Encoded Der Data Length:[%d]\n", der_index);
	for(int loop = 0; loop < der_index; loop++)
		printf("%02x\t",der[loop]);
#endif
	return der_index;
}

