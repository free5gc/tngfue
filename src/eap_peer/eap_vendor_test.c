/*
 * EAP peer method: Test method for vendor specific (expanded) EAP type
 * Copyright (c) 2005-2015, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * This file implements a vendor specific test method using EAP expanded types.
 * This is only for test use and must not be used for authentication since no
 * security is provided.
 */

#include "eap_vendor_test.h"

#define EAP_VENDOR_ID EAP_VENDOR_HOSTAP
#define EAP_VENDOR_TYPE 0x03

/* EAP-VENDOR-TEST Subtypes */
#define EAP_VENDOR_TEST_SUBTYPE_5GSTART 0x01
#define EAP_VENDOR_TEST_SUBTYPE_5GNAS 0x02
#define EAP_VENDOR_TEST_SUBTYPE_5GNOTIFICATION 0x03
#define EAP_VENDOR_TEST_SUBTYPE_5GSTOP 0x04

unsigned char hexCharToByte(char c) {
    if ('0' <= c && c <= '9') {
        return c - '0';
    } else if ('a' <= c && c <= 'f') {
        return c - 'a' + 10;
    } else if ('A' <= c && c <= 'F') {
        return c - 'A' + 10;
    } else {
        return 0;
    }
}

void buildPLMN(struct ue_info *ueinfo, char *plmn, size_t plmn_len)
{
	u8 plmnBytes[3] = {};
	ueinfo->plmnBytes[0] = hexCharToByte(plmn[0]) | ((hexCharToByte(plmn[1]) << 4) & 0xF0);

    if (plmn_len==5) {
        ueinfo->plmnBytes[1] = hexCharToByte(plmn[2]) | 0xF0;
        ueinfo->plmnBytes[2] = hexCharToByte(plmn[3]) | ((hexCharToByte(plmn[4]) << 4) & 0xF0);
    } else if (plmn_len==6) { 
        ueinfo->plmnBytes[1] = hexCharToByte(plmn[2]) | ((hexCharToByte(plmn[3]) << 4) & 0xF0);
        ueinfo->plmnBytes[2] = hexCharToByte(plmn[4]) | hexCharToByte(plmn[5]);
    }
	return;
}

void buildMSIN(struct ue_info *ueinfo, char *msin)
{
	size_t msin_len = strlen(msin);
	size_t msinBytes_len = msin_len / 2;
	for (int i = 0; i < msin_len; i += 2) {
		int j = i/2;
		if ( i+1 == msin_len) {
			ueinfo->msinBytes[j] = 0xF0 | hexCharToByte(msin[i]);
		} else {
			ueinfo->msinBytes[j] = hexCharToByte(msin[i+1]) << 4 | hexCharToByte(msin[i]);
		}
	}
}

RegexMatchRes matchRegex(const char *input, const char *pattern)
{
	regex_t regex;
	regmatch_t match[2];
	RegexMatchRes result = {-1, -1 }; // default pos

	if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
		fprintf(stderr, "Error compiling  regex\n");
        return result;
	}

	printf("input: %s\n", input);
	if (regexec(&regex, input, 2, match, 0) == 0){
		if (match[1].rm_so != -1) {
			result.start = match[1].rm_so;
			result.end = match[1].rm_eo;

			for (int i = result.start; i < result.end; i++) {
				printf("%c", input[i]);
			}
			printf("\n");
		}
	} else {
		fprintf(stderr, "Error executing regex\n");
	}

	regfree(&regex);
	return result;
}

void get_nai_info(struct ue_info *ueinfo, char *nai_username)
{
	RegexMatchRes gettype = matchRegex(nai_username, "type([0-9])");
	RegexMatchRes getrid = matchRegex(nai_username, "rid([0-9]+)");
	RegexMatchRes getschid = matchRegex(nai_username, "schid([0-9]+)");
	if (gettype.start != -1) {
		char hextype[2] = {};
		sprintf(hextype, "%x", atoi(nai_username + gettype.start));
		size_t type_length = (strlen(hextype) % 2) ? strlen(hextype)/2 + 1 : strlen(hextype)/2;
		for (int i = 0; i < strlen(hextype); ) {
			if ( i == 0 && strlen(hextype) % 2) {
				ueinfo->typeBytes[i/2] = hexCharToByte(hextype[i]);
				i++;
 			} else {
				ueinfo->typeBytes[i/2] = hexCharToByte(hextype[i]) << 4 | hexCharToByte(hextype[i+1]);
				i+=2;
			}
		}
		for (int i = 0; i < type_length; i++) {
			printf("x%02x", ueinfo->typeBytes[i]);
		}
		printf("\n");
	}
	if (getrid.start != -1) {
		char hexrid[10] = {};
		sprintf(hexrid, "%x", atoi(nai_username + getrid.start));
		size_t rid_length = (strlen(hexrid) % 2) ? strlen(hexrid)/2 + 1 : strlen(hexrid)/2;
		for (int i = 0; i < strlen(hexrid); ) {
			if ( i == 0 && strlen(hexrid) % 2 ) {
				ueinfo->ridBytes[i/2] = hexCharToByte(hexrid[i]);
				i++;
			} else {
				ueinfo->ridBytes[i/2] = hexCharToByte(hexrid[i]) << 4 | hexCharToByte(hexrid[i+1]);
				i+=2;
			}
		}
		for (int i = 0; i < rid_length; i++){
			printf("x%02x", ueinfo->ridBytes[i]);
		}
		printf("\n");
	}
	if (getschid.start != -1) {
		char hexschid[3] = {};
		sprintf(hexschid, "%x", atoi(nai_username + gettype.start));
		size_t schid_length = (strlen(hexschid) % 2) ? strlen(hexschid)/2 + 1 : strlen(hexschid)/2;
		for (int i = 0; i < strlen(hexschid); ) {
			if ( i == 0 && strlen(hexschid) % 2) {
				ueinfo->schidBytes[i/2] = hexCharToByte(hexschid[i]);
				i++;
			} else {
				ueinfo->schidBytes[i/2] = hexCharToByte(hexschid[i]) << 4 | hexCharToByte(hexschid[i+1]);
				i+=2;
			}
		}
		for (int i = 0; i < schid_length; i++) {
			printf("x%02x", ueinfo->schidBytes[i]);
		}
		printf("\n");
	}
}

void get_ue_info(struct eap_vendor_test_data *data)
{
	FILE *f = fopen("sec.conf", "r");
	if (f == NULL) {
		wpa_printf(MSG_ERROR, "File sec.conf not exist\n");
		exit(1);
	}
	char buffer[64];
	int pos = 0;
	while (fgets(buffer, 64, f) != NULL) {
		wpa_printf(MSG_DEBUG, "%s", buffer);
		char *token = strtok(buffer, ":");
		char *val = strtok(NULL, ":");
		val = strtok(val, "\n");
		if (strncmp(token, "imsi_identity", 13) == 0) {
			buildPLMN(&data->ueinfo, val, 5);
			buildMSIN(&data->ueinfo, val+5);
			strncpy(data->supi, val, sizeof(data->supi));
		} else if (strncmp(token, "nai_username", 12) == 0) {
			get_nai_info(&data->ueinfo, val);
			u8 pueid[] = {0x77, 0x00, 0x0d, 0x01};
			memcpy(&data->ueid, &pueid, sizeof(pueid));
			pos = sizeof(pueid);
			memcpy(&data->ueid[pos], &data->ueinfo.plmnBytes, sizeof(data->ueinfo.plmnBytes));
			pos += sizeof(data->ueinfo.plmnBytes);
			memcpy(&data->ueid[pos], &data->ueinfo.ridBytes, sizeof(data->ueinfo.ridBytes));
			pos += sizeof(data->ueinfo.ridBytes);
			memcpy(&data->ueid[pos], &data->ueinfo.schidBytes, sizeof(data->ueinfo.schidBytes));
			pos += sizeof(data->ueinfo.schidBytes);
			memcpy(&data->ueid[pos], &data->ueinfo.hnPubKeyIdBytes, sizeof(data->ueinfo.hnPubKeyIdBytes));
			pos += sizeof(data->ueinfo.hnPubKeyIdBytes);
			memcpy(&data->ueid[pos], &data->ueinfo.msinBytes, sizeof(data->ueinfo.msinBytes));
			pos += sizeof(data->ueinfo.msinBytes);
		}
	}
	fclose(f);
}

static void * eap_vendor_test_init(struct eap_sm *sm)
{
	struct eap_vendor_test_data *data;
	data = os_zalloc(sizeof(*data));
	if (data == NULL)
		return NULL;
	data->state = INIT;
	data->nas_uplink_cnt = malloc(4 * sizeof(u8));
	for (int i = 0; i < 4; i++)
		data->nas_uplink_cnt[i] = 0;
	cnt_set(data->uplink_cnt, 0, 0);
	cnt_set(data->downlink_cnt, 0, 0);
	data->cipher = 0x00;	// AlgCiphering128NEA0
	data->integrity = 0x02; // AlgIntegrity128NIA2

	get_ue_info(data);
	// u8 id[] =  {0x77, 0x00, 0x0d, 0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x50};
	// memcpy(&data->ueid, &id, sizeof(id));

	data->pduSessionId = 1;
	return data;
}

static void eap_vendor_test_deinit(struct eap_sm *sm, void *priv)
{
	struct eap_vendor_test_data *data = priv;
	os_free(data);
}

static struct wpabuf * eap_vendor_add_type(struct wpabuf *resp, u8 type)
{
	wpa_printf(MSG_DEBUG, "EAP-VENDOR-TYPE 5G NAS TYPE LEN: %ld ", sizeof(type));
	wpabuf_resize(&resp, 2);
	wpabuf_put_u8(resp, type);

	// spare
	wpabuf_put_u8(resp, 0x00);
	return resp;
}

static struct wpabuf * get_length(struct wpabuf *resp)
{
	struct wpabuf *len_body = wpabuf_alloc(2);
	// reg req len
	wpabuf_put_be16(len_body, wpabuf_len(resp));
	resp = wpabuf_concat(len_body, resp);
	wpa_hexdump_buf(MSG_DEBUG, "current data is: ", resp);
	return resp;
}

static struct wpabuf * GetRegistrationRequest(struct wpabuf *resp, u8 *identity,
		size_t identity_len, nas_UESecurityCapability *securityCapability,
		nas_5GMMCapability *capability5GMM)
{
	struct wpabuf *resp_nas_pdu = wpabuf_alloc(21);
	// ExtendedProtocolDiscriminator
	wpabuf_put_u8(resp_nas_pdu, Epd5GSMobilityManagementMessage);
	// SpareHalfOctetAndSecurityHeaderType
	wpabuf_put_u8(resp_nas_pdu, SecurityHeaderTypePlainNas);
	// RegistrationRequestMessageIdentity
	wpabuf_put_u8(resp_nas_pdu, MsgTypeRegistrationRequest);
	// NgksiAndRegistrationType5GS
	wpabuf_put_u8(resp_nas_pdu, 0x79);
	// mobile identity length
	wpabuf_put_be16(resp_nas_pdu, identity_len);
	// mobile identity
	wpabuf_put_data(resp_nas_pdu, &identity[0], identity_len);

	// 5GMM Capability
	if (capability5GMM != NULL) {
		wpabuf_resize(&resp_nas_pdu, capability5GMM->len + 2);
		wpabuf_put_u8(resp_nas_pdu, capability5GMM->iei);
		wpabuf_put_u8(resp_nas_pdu, capability5GMM->len);
		for(int i=0; i<capability5GMM->len; i++)
			wpabuf_put_u8(resp_nas_pdu, capability5GMM->val[i]);
	}
	// UE Security Capability
	if (securityCapability != NULL) {
		wpabuf_resize(&resp_nas_pdu, securityCapability->len + 2);
		wpabuf_put_u8(resp_nas_pdu, securityCapability->iei);
		wpabuf_put_u8(resp_nas_pdu, securityCapability->len);
		for(int i=0; i<securityCapability->len; i++)
			wpabuf_put_u8(resp_nas_pdu, securityCapability->val[i]);
	}

	return wpabuf_concat(resp, get_length(resp_nas_pdu));
}

static struct wpabuf * eap_vendor_an_param(struct eap_vendor_test_data *data, struct wpabuf *resp)
{
	struct wpabuf * an_param = wpabuf_alloc(40);
	// ueid encode (hardcoded)
	wpabuf_put_u8(an_param, 0x06);
	wpabuf_put_u8(an_param, sizeof(data->ueid));
	wpabuf_put_data(an_param, &data->ueid[0], sizeof(data->ueid));

	// GUAMI (amf related, amfid=cafe00, you can see amfcfg.yaml)
	u8 data2[6] = {0x00, 0x00, 0x00, 0xca, 0xfe, 0x00};
	memcpy(data2, &data->ueinfo.plmnBytes, sizeof(data->ueinfo.plmnBytes));
	// u8 data2[] = {0x02, 0xf8, 0x39, 0xca, 0xfe, 0x00};
	wpabuf_put_u8(an_param, 0x01);
	wpabuf_put_u8(an_param, sizeof(data2));
	wpabuf_put_data(an_param, &data2[0], sizeof(data2));

	// establishment cause
	wpabuf_put_u8(an_param, 0x04);
	wpabuf_put_u8(an_param, 0x01);
	wpabuf_put_u8(an_param, 0x03);

	// PLMN ID
	u8 *data3 = malloc( sizeof(data->ueinfo.plmnBytes));
	memcpy(data3, &data->ueinfo.plmnBytes, sizeof(data->ueinfo.plmnBytes));
	// u8 data3[] = {0x02, 0xf8, 0x39};
	wpabuf_put_u8(an_param, 0x02);
	wpabuf_put_u8(an_param, sizeof(data->ueinfo.plmnBytes));
	wpabuf_put_data(an_param, &data3[0], sizeof(data->ueinfo.plmnBytes));
	free(data3);

	// NSSAI
	// TS23 501 clause 5.15.9: trusted- non3gpp shall not include NSSAI by default
	/*
	u8 data4[]= {0x04, 0x01, 0x01, 0x02, 0x03, 0x04, 0x01, 0x11, 0x22, 0x33};
	wpabuf_put_u8(resp, 0x03);
	wpabuf_put_u8(resp, sizeof(data4));
	for (int i= 0; i< 10; i++)
		wpabuf_put_u8(resp, data4[i]);
	*/

	return wpabuf_concat(resp, get_length(an_param));
}

static struct wpabuf * eap_vendor_test_nas_pdu(struct eap_vendor_test_data *data, struct wpabuf *resp)
{
	wpa_printf(MSG_DEBUG, "EAP-VENDOR-TYPE 5GSTART NAS PDU");
	u8 *identity = malloc( (sizeof(data->ueid) - 3) * sizeof(u8));
	if (identity == NULL) {
		printf("identity is nulptr!!\n");
		exit(1);
	}
	memcpy(identity, &data->ueid[3], (sizeof(data->ueid) - 3) *sizeof(u8));
	// u8 identity[] = {0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x50};
	nas_UESecurityCapability securityCapability = {
		0x2e, 0x02, {0x80, 0x20}
	};
	resp = GetRegistrationRequest(resp, identity, sizeof(data->ueid)-3, &securityCapability, NULL);
	free(identity);
	return resp;
}

static struct wpabuf * eap_vendor_test_process_5gstart(struct eap_vendor_test_data *data, u8 id)
{
	struct wpabuf *resp_body = wpabuf_alloc(2), *resp;
	wpa_printf(MSG_DEBUG, "EAP-VENDOR-TYPE 5GSTART: check identity match (id=%d)", id);

	wpa_printf(MSG_DEBUG, "Generating EAP-VENDOR-TYPE 5GSTART (id=%d)", id);

	// put data inside
	resp_body = eap_vendor_add_type(resp_body, EAP_VENDOR_TEST_SUBTYPE_5GNAS);

	// generate AN parameter and put in
	resp_body = eap_vendor_an_param(data, resp_body);

	// generate NAS PDU
	resp_body = eap_vendor_test_nas_pdu(data, resp_body);

	// build header
	resp = eap_msg_alloc(EAP_VENDOR_ID, EAP_VENDOR_TYPE, wpabuf_len(resp_body),
						 EAP_CODE_RESPONSE, id);

	resp = wpabuf_concat(resp, resp_body);

	return resp;
}

static struct wpabuf * GetIdentityResponse(struct wpabuf *resp, u8 *identity)
{
	wpabuf_resize(&resp, 13);
	// iden res len
	wpabuf_put_u8(resp, 12);
	// ExtendedProtocolDiscriminator
	wpabuf_put_u8(resp, Epd5GSMobilityManagementMessage);
	// SpareHalfOctetAndSecurityHeaderType
	wpabuf_put_u8(resp, SecurityHeaderTypePlainNas);
	// MsgTypeIdentityResponse
	wpabuf_put_u8(resp, 0x5c);
	// mobile identity length
	wpabuf_put_u8(resp, 0x08);
	// mobile identity
	for (int i = 0; i < 8; i++)
		wpabuf_put_u8(resp, identity[i]);
	return resp;
}

static struct wpabuf * eap_vendor_test_process_5gnas_identity(u8 id)
{
	struct wpabuf *resp_body = wpabuf_alloc(2), *resp;
	wpa_printf(MSG_DEBUG, "EAP-VENDOR-TYPE 5GNAS: check identity match (id=%d)", id);

	// put data inside
	resp_body = eap_vendor_add_type(resp_body, EAP_VENDOR_TEST_SUBTYPE_5GNAS);
	resp_body = GetIdentityResponse(resp_body, (u8 *)"nems@704");

	// build header
	resp = eap_msg_alloc(EAP_VENDOR_ID, EAP_VENDOR_TYPE, wpabuf_len(resp_body),
						 EAP_CODE_RESPONSE, id);

	resp = wpabuf_concat(resp, resp_body);

	return resp;
}

void convert_byte(u8 *ret, char *src, size_t len) {
	if (len % 2 == 1) {
		wpa_printf(MSG_ERROR, "malform len input %d", len);
	}

	for (int i = 0; i < len; i += 2) {
		if (src[i] <= '9' && src[i] >= '0') {
			ret[i / 2] = (src[i] - '0') << 4;
		} else if (src[i] >= 'a' && src[i] <= 'f') {
			ret[i / 2] = (src[i] - 'a' + 10) << 4;
		} else if (src[i] >= 'A' && src[i] <= 'F') {
			ret[i / 2] = (src[i] - 'A' + 10) << 4;
		} else {
			wpa_printf(MSG_ERROR, "malform value s %s", src[i]);
		}

		if (src[i + 1] <= '9' && src[i + 1] >= '0') {
			ret[i / 2] += (src[i + 1] - '0');
		} else if (src[i + 1] >= 'a' && src[i + 1] <= 'f') {
			ret[i / 2] += (src[i + 1] - 'a' + 10);
		} else if (src[i + 1] >= 'A' && src[i + 1] <= 'F') {
			ret[i / 2] += (src[i + 1] - 'A' + 10);
		} else {
			wpa_printf(MSG_ERROR, "malform value s2 %s", src[i + 1]);
		}
	}
}

void sync_config_sqn(u8 *sqn, size_t len)
{
	for (int i = len - 1; i >= 0; i--)
	{
		if (sqn[i] != 0xff)
		{
			sqn[i]++;
			wpa_printf(MSG_DEBUG, "seq add: %x", sqn[i]);
			break;
		}
		else
			sqn[i] = 0x00;
	}
	FILE *f = fopen("sec.conf", "r");
	if (f == NULL) {
		wpa_printf(MSG_ERROR, "File sec.conf not exist\n");
		exit(1);
	}
	char buffer[64], buffer_copy[64];
	char new_sqn[18] = "SQN:", file_val[201] = {};
	while (fgets(buffer, 64, f) != NULL)
	{
		strcpy(buffer_copy, buffer);
		char *token = strtok(buffer, ":");
		if (token[0] == 'S')
		{
			for (int i = 0; i < len; i++)
			{
				int tmp = sqn[i] / 16;
				char add;
				if (tmp <= 9 && tmp >= 0)
					new_sqn[4 + 2 * i] = tmp + '0';
				else
					new_sqn[4 + 2 * i] = tmp - 10 + 'a';
				tmp = sqn[i] % 16;
				if (tmp <= 9 && tmp >= 0)
					new_sqn[5 + 2 * i] = tmp + '0';
				else
					new_sqn[5 + 2 * i] = tmp - 10 + 'a';
			}
			new_sqn[16] = '\n';
			strcat(file_val, new_sqn);
		}
		else
			strcat(file_val, buffer_copy);
	}
	fclose(f);
	f = fopen("sec.conf", "w");
	fputs(file_val, f);
	fclose(f);
}

static struct wpabuf * GetAutheticationResponse(struct wpabuf *resp, const u8 *_rand, struct eap_vendor_test_data *data)
{
	wpabuf_resize(&resp, 23);
	// auth res len
	wpabuf_put_u8(resp, 0);
	wpabuf_put_u8(resp, 21);
	// ExtendedProtocolDiscriminator
	wpabuf_put_u8(resp, Epd5GSMobilityManagementMessage);
	// SpareHalfOctetAndSecurityHeaderType
	wpabuf_put_u8(resp, SecurityHeaderTypePlainNas);
	// MsgTypeAutheticationResponse
	wpabuf_put_u8(resp, 0x57);

	// generate res*
	FILE *f = fopen("sec.conf", "r");
	if (f == NULL) {
		wpa_printf(MSG_ERROR, "File sec.conf not exist\n");
		exit(1);
	}
	char buffer[64];
	u8 *kk, *sqn, *amf, *opc;
	while (fgets(buffer, 64, f) != NULL) {
		wpa_printf(MSG_DEBUG, "%s", buffer);
		char *token = strtok(buffer, ":");
		char *val = strtok(NULL, ":");
		val = strtok(val, "\n");

		if (strncmp(token, "K", 1) == 0) {
			kk = malloc((strlen(val) / 2) * sizeof(u8));
			convert_byte(kk, val, strlen(val));
		} else if (strncmp(token, "SQN", 3) == 0) {
			sqn = malloc((strlen(val) / 2) * sizeof(u8));
			convert_byte(sqn, val, strlen(val));
			// sync_config_sqn(sqn, 6);
		} else if (strncmp(token, "AMF", 3) == 0) {
			amf = malloc((strlen(val) / 2) * sizeof(u8));
			convert_byte(amf, val, strlen(val));
		} else if (strncmp(token, "OPC", 3) == 0) {
			opc = malloc((strlen(val) / 2) * sizeof(u8));
			convert_byte(opc, val, strlen(val));
		}
	}
	fclose(f);
	char snnstr[100] = {};
	sprintf(snnstr, "5G:mnc%c%c%c.mcc%c%c%c.3gppnetwork.org", '0', data->supi[3], data->supi[4], data->supi[0], data->supi[1], data->supi[2]);
	u8 *snn = malloc(strlen(snnstr)*sizeof(u8));
	for (int i = 0; i < strlen(snnstr); i++) {
		snn[i] = snnstr[i];
	}
	// u8 snn[] = {0x35, 0x47, 0x3a, 0x6d, 0x6e, 0x63, 0x30, 0x39, 0x33, 0x2e, 0x6d, 0x63, 0x63, 0x32, 0x30, 0x38, 0x2e, 0x33, 0x67, 0x70, 0x70, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2e, 0x6f, 0x72, 0x67};
	u8 _autn[16] = {};
	u8 ik[16] = {};
	u8 ck[16] = {};
	u8 res[8] = {};

	size_t res_len = 8;
	// get constance
	milenage_generate(opc, amf, kk, sqn, _rand, _autn, ik, ck, res, &res_len);
	// ck || ik
	u8 *key = malloc(32 * sizeof(u8));
	memcpy(key, &ck, sizeof(ck) * sizeof(u8));
	memcpy(key + 16, &ik, sizeof(ik) * sizeof(u8));

	// RES* calculation
	// FC || P0 || L0 || ...
	u8 *words = (u8 *)malloc((55 + res_len) * sizeof(u8));
	words[0] = FC_FOR_RES_STAR_XRES_STAR_DERIVATION;
	memcpy(words + 1, snn, strlen(snnstr) * sizeof(u8));
	words[33] = 0x00, words[34] = 32;
	for (int i = 0; i < 16; i++)
		words[35 + i] = _rand[i];
	// memcpy(words+ 35, &_rand, 16* sizeof(u8));
	words[51] = 0x00, words[52] = 0x10;
	for (int i = 0; i < res_len; i++)
		words[53 + i] = res[i];
	// memcpy(words+ 53, &res, res_len * sizeof(u8));
	words[53 + res_len] = 0x00, words[54 + res_len] = res_len;
	u8 *ans = (u8 *)malloc(32 * sizeof(u8));
	if (hmac_sha256(key, 32, words, (55 + res_len), ans) == 0)
	{
		// RES* iei
		wpabuf_put_u8(resp, 0x2d);
		// RES* length
		wpabuf_put_u8(resp, 16);
		// RES*
		for (int i = 0; i < 16; i++)
			wpabuf_put_u8(resp, ans[i + 16]);
	}
	free(ans);
	free(words);
	sync_config_sqn(sqn, 6);
	// Kausf calculation
	u8 *param = malloc(43 * sizeof(u8)), *kausf = malloc(32 * sizeof(u8));
	param[0] = FC_FOR_KAUSF_DERIVATION;
	memcpy(param + 1, snn, 32 * sizeof(u8));
	param[33] = 0x00, param[34] = 32;
	for (int i = 0; i < 6; i++)
		param[35 + i] = _autn[i];
	// memcpy(param+ 35, &_autn, 6* sizeof(u8));
	param[41] = 0x00, param[42] = 0x06;
	if (hmac_sha256(key, 32, param, 43, kausf) == -1)
	{
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TYPE 5GNAS Authentication: kausf fail");
		data->state = INIT;
		return resp;
	}
	free(param);

	// Kseaf calculation
	u8 *seaf = malloc(35 * sizeof(u8)), *kseaf = malloc(32 * sizeof(u8));
	seaf[0] = FC_FOR_KSEAF_DERIVATION;
	memcpy(seaf + 1, snn, 32 * sizeof(u8));
	seaf[33] = 0x00, seaf[34] = 32;
	if (hmac_sha256(kausf, 32, seaf, 35, kseaf) == -1)
	{
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TYPE 5GNAS Authentication: kseaf fail");
		data->state = INIT;
		return resp;
	}
	free(seaf);
	free(snn);

	// kamf calculation
	u8 *_amf = malloc(22 * sizeof(u8));
	data->kamf = malloc(32 * sizeof(u8));
	_amf[0] = FC_FOR_KAMF_DERIVATION;
	u8 *supi = malloc(sizeof(data->supi));
	for (int i = 0; i < sizeof(data->supi); i++) {
		supi[i] = data->supi[i];
	}
	// u8 supi[] = {0x32, 0x30, 0x38, 0x39, 0x33, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x30, 0x35};
	memcpy(_amf + 1, supi, 15 * sizeof(u8));
	_amf[16] = 0x00, _amf[17] = 0x0f, _amf[18] = 0x00, _amf[19] = 0x00, _amf[20] = 0x00, _amf[21] = 0x02;
	if (hmac_sha256(kseaf, 32, _amf, 22, data->kamf) == -1)
	{
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TYPE 5GNAS Authentication: kamf fail");
		data->state = INIT;
		return resp;
	}
	free(_amf);
	free(kseaf);
	free(kausf);

	// nas encryption key calculation
	u8 *alg = malloc(7 * sizeof(u8)), *k = malloc(32 * sizeof(u8));
	data->k_nas_enc = malloc(16 * sizeof(u8));
	alg[0] = FC_FOR_ALGORITHM_KEY_DERIVATION;
	alg[1] = 0x01, alg[2] = 0x00, alg[3] = 0x01;
	alg[4] = data->cipher, alg[5] = 0x00, alg[6] = 0x01;
	if (hmac_sha256(data->kamf, 32, alg, 7, k) == -1)
	{
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TYPE 5GNAS Authentication: k_nas_enc fail");
		data->state = INIT;
		return resp;
	}
	for (int i = 0; i < 16; i++)
		data->k_nas_enc[i] = k[16 + i];

	realloc(k, 32 * sizeof(u8));
	data->k_nas_int = malloc(16 * sizeof(u8));
	alg[1] = 0x02;
	alg[4] = data->integrity;
	if (hmac_sha256(data->kamf, 32, alg, 7, k) == -1)
	{
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TYPE 5GNAS Authentication: k_nas_int fail");
		data->state = INIT;
		return resp;
	}
	for (int i = 0; i < 16; i++)
		data->k_nas_int[i] = k[16 + i];
	free(alg);
	free(k);

	// ktngf calculation
	u8 *tngf = malloc(10 * sizeof(u8));
	data->ktngf = malloc(32 * sizeof(u8));
	tngf[0] = FC_FOR_KTNGF_DERIVATION;
	for (int i = 0; i < 4; i++)
	{
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TYPE 5GNAS Authentication: tngf uplink cnt: %x", 0x000000ff & (data->uplink_cnt.count >> (24 - 8 * i)));
		tngf[i + 1] = 0x000000ff & (data->uplink_cnt.count >> (24 - 8 * i));
	}
	tngf[5] = 0x00, tngf[6] = 0x04;
	tngf[7] = 0x02, tngf[8] = 0x00, tngf[9] = 0x01;
	if (hmac_sha256(data->kamf, 32, tngf, 10, data->ktngf) == -1)
	{
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TYPE 5GNAS Authentication: ktngf fail");
		data->state = INIT;
		return resp;
	}
	free(tngf);

	// ktnap calculation
	u8 *tnap = malloc(4 * sizeof(u8));
	data->ktnap = malloc(32 * sizeof(u8));
	tnap[0] = FC_FOR_KTIPSEC_KTNAP_DERIVATION;
	tnap[1] = 0x02, tnap[2] = 0x00, tnap[3] = 0x01;
	if (hmac_sha256(data->ktngf, 32, tnap, 4, data->ktnap) == -1)
	{
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TYPE 5GNAS Authentication: ktnap fail");
		data->state = INIT;
		return resp;
	}

	// ktipsec calculation
	u8 *ktipsec = malloc(32 * sizeof(u8));
	data->ikev2.shared_secret_len = 32;
	tnap[1] = 0x01;
	if (hmac_sha256(data->ktngf, 32, tnap, 4, ktipsec) == -1)
	{
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TYPE 5GNAS Authentication: ktnap fail");
		data->state = INIT;
		return resp;
	}
	data->ikev2.shared_secret = os_memdup(ktipsec, 32);
	free(tnap);
	free(ktipsec);

	data->state = SUCCESS;

	return resp;
}

static struct wpabuf * eap_vendor_test_process_5gnas_authentcation(u8 id, const struct wpabuf *reqData, struct eap_vendor_test_data *data)
{
	struct wpabuf *resp_body = wpabuf_alloc(2), *resp;
	wpa_printf(MSG_DEBUG, "EAP-VENDOR-TYPE 5GNAS: check identity match (id=%d)", id);

	// read data
	u8 pos = 21 + reqData->buf[20];
	u8 _rand[16] = {};
	u8 autn[16] = {};
	u8 len;
	while (pos < wpabuf_len(reqData))
	{
		// iei
		u8 tmp = reqData->buf[pos++];
		if (tmp >= 0x80)
			tmp = (tmp & 0xf0) >> 4;
		switch (tmp)
		{
		case 0x21:
			memcpy(_rand, &(reqData->buf[pos]), 16 * sizeof(*(reqData->buf)));
			pos += 16;
			break;
		case 0x20:
			len = reqData->buf[pos++];
			memcpy(autn, &(reqData->buf[pos]), len * sizeof(*(reqData->buf)));
			pos += 16;
			break;
		case 0x78: // TODO: EAP
			pos = wpabuf_len(reqData);
			break;
		default:
			pos = wpabuf_len(reqData);
			break;
		}
	}

	// put data inside

	resp_body = eap_vendor_add_type(resp_body, EAP_VENDOR_TEST_SUBTYPE_5GNAS);
	// generate AN parameter and put in
	resp_body = eap_vendor_an_param(data, resp_body);

	resp_body = GetAutheticationResponse(resp_body, (const u8 *)_rand, data);

	// build header
	resp = eap_msg_alloc(EAP_VENDOR_ID, EAP_VENDOR_TYPE, wpabuf_len(resp_body),
						 EAP_CODE_RESPONSE, id);

	resp = wpabuf_concat(resp, resp_body);
	return resp;
}

static struct wpabuf * GetSecurityModeComplete(struct wpabuf *resp, u8 imeisv_req, u8 additional_5g_security_information, u8 *ueid)
{
	// TODO: modify other parts of the response
	wpabuf_resize(&resp, 3);
	// ExtendedProtocolDiscriminator
	wpabuf_put_u8(resp, Epd5GSMobilityManagementMessage);
	// SpareHalfOctetAndSecurityHeaderType
	wpabuf_put_u8(resp, SecurityHeaderTypePlainNas);
	// MsgTypeSecurityModeComplete
	wpabuf_put_u8(resp, 0x5e);
	if (imeisv_req == 0x01)
	{
		wpabuf_resize(&resp, 12);
		// Imei: iei
		wpabuf_put_u8(resp, 0x77);
		// Imei: len
		wpabuf_put_u8(resp, 0x00);
		wpabuf_put_u8(resp, 0x09);
		// Imei: octet* 9
		wpabuf_put_u8(resp, 0b00010101);
		wpabuf_put_u8(resp, 0b00010001);
		for (int i = 0; i < 7; i++)
			wpabuf_put_u8(resp, 0x00);
	}

	// registration request
	nas_UESecurityCapability securityCapability = {
		0x2e, 0x02, {0x80, 0x20}
	};
	nas_5GMMCapability capability5GMM = {
		0x10, 0x01, {0x07}
	};
	struct wpabuf *registration_request;
	registration_request = GetRegistrationRequest(registration_request, &ueid[3], sizeof(ueid) - 3, &securityCapability, &capability5GMM);
	wpabuf_resize(&resp, 1);
	wpabuf_put_u8(resp, 0x71);
	resp = wpabuf_concat(resp, registration_request);

	return resp;
}

static struct wpabuf * encrypt_nas(u8 method, u8 *key, u8 *cnt, struct wpabuf *resp)
{
	switch (method)
	{
	case 0x00:
		return resp;
		break;
	// TODO: add other types
	default:
		return resp;
		break;
	}
}

static struct wpabuf * nia2(u8 *key, int cnt, struct wpabuf *resp)
{
	u8 *m = malloc(wpabuf_len(resp) + 8);
	for (int i = 0; i < 4; i++)
		m[i] = 0x000000ff & (cnt >> (24 - 8 * i));
	m[4] = 0x10;
	for (int i = 5; i < 8; i++)
		m[i] = 0x00;
	for (int i = 0; i < wpabuf_len(resp); i++)
		m[i + 8] = resp->buf[i];
	// memcpy(m + 8, &resp, wpabuf_len(resp) * sizeof(u8));
	u8 *output = malloc(16 * sizeof(u8));
	if (omac1_aes_128(key, m, wpabuf_len(resp) + 8, output) != 0)
		return NULL;
	struct wpabuf *mac = wpabuf_alloc(4);
	for (int i = 0; i < 4; i++)
		wpabuf_put_u8(mac, output[i]);
	free(m);
	return mac;
}

static struct wpabuf * encrypt_nas_mac32(u8 method, u8 *key, int cnt, struct wpabuf *resp)
{
	switch (method)
	{
	case 0x00:
		return resp;
		break;
	case 0x02:
		return nia2(key, cnt, resp);
		break;
	// TODO: add other types
	default:
		return resp;
		break;
	}
}

static struct wpabuf * BuildSecureNAS(u8 securityheader, struct wpabuf *resp, struct eap_vendor_test_data *data)
{
	struct wpabuf *length = wpabuf_alloc(2);
	// cipher the message
	resp = encrypt_nas(data->cipher, data->k_nas_enc, data->nas_uplink_cnt, resp);

	wpa_hexdump_buf(MSG_DEBUG, "EAP-VENDOR-TYPE: build secure nas", resp);
	struct wpabuf *resp_body = wpabuf_alloc(1), *result = wpabuf_alloc(4), *security_header = wpabuf_alloc(2);
	// add sqn num
	wpabuf_put_u8(resp_body, cnt_sqn(data->uplink_cnt));
	resp_body = wpabuf_concat(resp_body, resp);
	wpa_hexdump_buf(MSG_DEBUG, "EAP-VENDOR-TYPE: add sqn", resp_body);
	// put security header
	wpabuf_put_u8(security_header, Epd5GSMobilityManagementMessage);
	if (securityheader == SecurityHeaderTypeIntegrityProtectedWithNew5gNasSecurityContext) {
		wpabuf_put_u8(security_header, SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext);
	} else {
		wpabuf_put_u8(security_header, securityheader);
	}
	// integrity protection
	result = encrypt_nas_mac32(data->integrity, data->k_nas_int, data->uplink_cnt.count, resp_body);
	// combination
	result = wpabuf_concat(result, resp_body);
	// combination
	result = wpabuf_concat(security_header, result);
	wpa_hexdump_buf(MSG_DEBUG, "EAP-VENDOR-TYPE: add mac32", result);
	// implement uplink cnt
	cnt_add(data->uplink_cnt);

	wpabuf_put_be16(length, wpabuf_len(result));
	result = wpabuf_concat(length, result);
	return result;
}

static struct wpabuf * eap_vendor_test_process_5gnas_smc(u8 id, const struct wpabuf *reqData, struct eap_vendor_test_data *data)
{
	struct wpabuf *resp_body = wpabuf_alloc(2), *resp;
	wpa_printf(MSG_DEBUG, "EAP-VENDOR-TYPE 5GNAS: check identity match (id=%d)", id);

	bool integrity = false, cipher = false;
	// checking that the UE security capabilities sent by the AMF
	switch (reqData->buf[17])
	{
	case 0: // plain 5GS
		break;
	case 1: // integrity protected
		integrity = true;
		break;
	case 2: // integrity protected and cipher protected
		integrity = true;
		cipher = true;
		break;
	case 3: //
		integrity = true;
		cnt_set(data->downlink_cnt, 0, 0);
		break;
	case 4:
		integrity = true;
		cipher = true;
		for (int i = 0; i < 4; i++)
			data->nas_uplink_cnt[i] = 0;
		cnt_set(data->downlink_cnt, 0, 0);
		break;
	default:
		wpa_printf(MSG_ERROR, "Wrong security header type: 0x%x", reqData->buf[17]);
		return resp_body;
	}
	if (integrity == true && data->integrity == 0x00)
	{
		wpa_printf(MSG_ERROR, "integrity is set but originally set none");
		return resp_body;
	}
	else if (integrity == false && data->integrity != 0x00)
	{
		wpa_printf(MSG_ERROR, "integrity set none but originally set");
		return resp_body;
	}
	if (cipher == true && data->cipher == 0x00)
	{
		wpa_printf(MSG_ERROR, "cipher is set but originally set none");
		return resp_body;
	}
	else if (cipher == false && data->cipher != 0x00)
	{
		wpa_printf(MSG_ERROR, "cipher set none but originally set");
		return resp_body;
	}

	// sequence number
	if (cnt_sqn(data->downlink_cnt) > reqData->buf[22])
	{
		wpa_printf(MSG_DEBUG, "set DLCount overflow");
		cnt_set_overflow(data->downlink_cnt, cnt_sqn(data->downlink_cnt) + 1);
	}
	cnt_set_sqn(data->downlink_cnt, reqData->buf[22]);

	// Get the MAC for NAS
	u8 mac32[4] = {}, *payload;
	payload = malloc((reqData->used - 6) * sizeof(u8));
	for (int i = 6; i < reqData->used; i++)
		payload[i - 6] = reqData->buf[i];
	free(payload);
	wpa_printf(MSG_DEBUG, "Calculate NAS MAC (algorithm: %x, DLCount: 0x%0x)", data->integrity, data->downlink_cnt.count);
	// mac32 = NASMacCalculate(data->integrity, data->k_nas_int, data->cnt.count, \
	//		0x02, 0x01, payload);

	u8 pos = 29 + reqData->buf[28];
	u8 imeisv_req = 0x00, additional_5g_seciurity_information = 0x00;
	while (pos < wpabuf_len(reqData))
	{
		// iei
		u8 tmp = reqData->buf[pos++];
		// if (tmp >= 0x80)
		//	tmp= (tmp & 0xf0) >> 4;
		wpa_printf(MSG_DEBUG, "EAP_VENDOR_TEST: tmpiei: 0x%x", tmp);
		switch (tmp)
		{
		case 0xe0:
			// pos++;
			break;
		case 0xe1:
			imeisv_req = 0x01;
			// pos++;
			break;
		case 0x36:
			pos++;
			additional_5g_seciurity_information = reqData->buf[pos++];
			break;
		default:
			pos = wpabuf_len(reqData);
			break;
		}
	}

	// put data inside
	struct wpabuf *nasPDU;
	nasPDU = GetSecurityModeComplete(resp_body, imeisv_req, additional_5g_seciurity_information, data->ueid);
	// build security nas
	nasPDU = BuildSecureNAS(reqData->buf[17], nasPDU, data);

	// AN parameter length
	struct wpabuf *anParameter = wpabuf_alloc(2);
	wpabuf_put_le16(anParameter, 0x0000);
	resp_body = wpabuf_concat(anParameter, nasPDU);

	// build header
	resp = eap_msg_alloc(EAP_VENDOR_ID, EAP_VENDOR_TYPE, wpabuf_len(resp_body) + 2,
						 EAP_CODE_RESPONSE, id);
	resp = eap_vendor_add_type(resp, EAP_VENDOR_TEST_SUBTYPE_5GNAS);

	resp = wpabuf_concat(resp, resp_body);
	return resp;
}

static struct wpabuf* decrypt_nas(u8 securityHeaderType, struct wpabuf *resp, struct eap_vendor_test_data *data)
{
	wpa_printf(MSG_DEBUG, "decrypt nas packet");
	u8 securityHeader[6] = {};
	u8 sqn = resp->buf[6];
	struct wpabuf *payload = wpabuf_alloc(wpabuf_len(resp) - 6);
	struct wpabuf *receviedMac = wpabuf_alloc(4);
	memcpy(securityHeader, wpabuf_head(resp), 6 * sizeof(u8));
	wpabuf_put_data(receviedMac, wpabuf_head(resp) + 2, 4);
	wpabuf_put_data(payload, wpabuf_head(resp) + 6, wpabuf_len(resp) - 6);

	wpa_printf(MSG_DEBUG, "securityHeaderType: %d", securityHeaderType);
	bool cipher = false;
	switch(securityHeaderType)
	{
	case SecurityHeaderTypeIntegrityProtected:
		wpa_printf(MSG_DEBUG, "Security header type: Integrity Protected");
		break;
	case SecurityHeaderTypeIntegrityProtectedAndCiphered:
		cipher = true;
		wpa_printf(MSG_DEBUG, "Security header type: Integrity Protected And Ciphered");
		break;
	case SecurityHeaderTypeIntegrityProtectedWithNew5gNasSecurityContext:
		wpa_printf(MSG_DEBUG, "Security Header Type Integrity Protected With New 5g Nas Security Context");
		cnt_set(data->downlink_cnt, 0, 0);
		break;
	case SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext:
		wpa_printf(MSG_DEBUG, "Security header type: Integrity Protected And Ciphered With New 5G Security Context");
		cnt_set(data->downlink_cnt, 0, 0);
		cipher = true;
		break;
	default:
		wpa_printf(MSG_ERROR, "security header type fail %d", securityHeaderType);
	}

	if (data->downlink_cnt.count > sqn)
		cnt_set_overflow(data->downlink_cnt, cnt_overflow(data->downlink_cnt) + 1);
	cnt_set_sqn(data->downlink_cnt, sqn);

	// integrity protection
	struct wpabuf *mac32_result = wpabuf_alloc(4);
	mac32_result = encrypt_nas_mac32(data->integrity, data->k_nas_int, data->downlink_cnt.count, payload);
	if (wpabuf_cmp(mac32_result, receviedMac) == -1)
		wpa_printf(MSG_ERROR, "the mac is not equal dude......");
	else
		wpa_hexdump_buf(MSG_DEBUG, "the mac is: ", mac32_result);
	struct wpabuf *ans = wpabuf_alloc(wpabuf_len(payload) - 1);
	wpabuf_put_data(ans, wpabuf_head(payload) + 1, wpabuf_len(payload) - 1);
	return ans;
}

static struct wpabuf* GetRegistrationComplete()
{
	struct wpabuf *resp_nas_pdu = wpabuf_alloc(3);
	// ExtendedProtocolDiscriminator
	wpabuf_put_u8(resp_nas_pdu, Epd5GSMobilityManagementMessage);
	// SpareHalfOctetAndSecurityHeaderType
	wpabuf_put_u8(resp_nas_pdu, SecurityHeaderTypePlainNas);
	// RegistrationCompleteMessageIdentity
	wpabuf_put_u8(resp_nas_pdu, MsgTypeRegistrationComplete);
	return resp_nas_pdu;
}

static struct wpabuf* eap_vendor_test_process_reg_accept(const struct wpabuf *reqData, struct eap_vendor_test_data *data)
{
	struct wpabuf *plainNas = wpabuf_alloc(0);
	// NAS Decode
	// u8 security_param = reqData->buf[1] & 0x0f;
	u8 security_param = 2;
	plainNas = decrypt_nas(security_param, reqData, data);
	cnt_add(data->downlink_cnt);

	struct wpabuf *resp = wpabuf_alloc(0);
	resp = GetRegistrationComplete();
	return BuildSecureNAS(security_param, resp, data);
}

void eap_vendor_test_process_est_accept(const struct wpabuf *reqData, struct eap_vendor_test_data *data, int start, int len)
{
	// Skip Authorized QoS rules
	int authQoSRuleLen = reqData->buf[start + 5] * 256 + reqData->buf[start + 6];
	// Skip Session AMBR as well: 7 octet
	int idx = start + 14 + authQoSRuleLen;
	while (idx < len)
	{
		switch(reqData->buf[idx])
		{
		case 0x59: // 5GSM cause
		case 0x56: // RQ timer value
			idx += 2;
			break;
		case 0x29: // PDU address
			if (reqData->buf[idx + 2] = 1)
			{
				data->pdu_address = malloc(4 * sizeof(u8));
				memcpy(data->pdu_address, &(reqData->buf[idx + 3]), 4 * sizeof(u8));
				idx += 2 + reqData->buf[idx + 1];
			}
			wpa_hexdump(MSG_DEBUG, "This is PDU Address: ", data->pdu_address, 4);
			break;
		default:
			// TODO: add all the others in TS 24.501 Table 8.3.2.1.1
			idx = len;
		}
	}
}

void eap_vendor_test_build_GRE_tunnel(struct eap_vendor_test_data *data)
{
	uint32_t greKeyField = 0;
	greKeyField |= (data->ikev2.child_sa[data->ikev2.child_sa_idx - 1].QoS.QFIList[0] & 0x3F) << 24;
	char *greTun = malloc(200 * sizeof(char));
	sprintf(greTun, "ip tunnel add greTun0 mode gre remote %s local %s ikey %d okey %d dev xfrm-1",
			data->ikev2.up_ip_addr, data->ikev2.cfg->ueIPAddr, greKeyField, greKeyField);
	wpa_printf(MSG_DEBUG, "greTun: %s", greTun);
	system(greTun);
	free(greTun);
	char *addr_add = malloc(200 * sizeof(char));
	sprintf(addr_add, "ip addr add %d.%d.%d.%d dev greTun0",
			*data->pdu_address, *(data->pdu_address + 1), *(data->pdu_address + 2), *(data->pdu_address + 3));
	wpa_printf(MSG_DEBUG, "pdu_address: %s", greTun);
	system(addr_add);
	free(addr_add);
	system("ip link set dev greTun0 up");
	system("ip route replace default dev greTun0");
}

void eap_vendor_test_process_DLnas_trasport(const struct wpabuf *reqData, struct eap_vendor_test_data *data)
{
	struct wpabuf *plainNas = wpabuf_alloc(0);
	// NAS Decode
	// u8 security_param = reqData->buf[1] & 0x0f;
	u8 security_param = 1;
	plainNas = decrypt_nas(security_param, reqData, data);
	cnt_add(data->downlink_cnt);

	int idx = 6, pduSessionID;
	int payload_len = plainNas->buf[4] * 256 + plainNas->buf[5];
	if (idx + payload_len < wpabuf_len(plainNas))
		pduSessionID = (reqData->buf[idx + payload_len] == 0x12) ? reqData->buf[idx + payload_len + 1] : 1;
	eap_vendor_test_process_est_accept(plainNas, data, idx, payload_len + idx);
	eap_vendor_test_build_GRE_tunnel(data);
}

static struct wpabuf * eap_vendor_test_process_5gnas(struct eap_sm *sm,
						struct eap_vendor_test_data *data,
						u8 id,
						const struct wpabuf *reqData,
						int padding)
{
	struct wpabuf *resp = wpabuf_alloc(0);
	int security_param = reqData->buf[1 + padding] & 0x0f;
	wpa_printf(MSG_DEBUG, "5GNAS Try to get data: 17 security header type: %d", security_param);
	if (security_param != 0)
	{
		security_param = 7;
		// TODO: decode the integrity protection and encrypted protection
	}
	wpa_printf(MSG_DEBUG, "5GNAS Try to get data: 18: %d", reqData->buf[2 + padding + security_param]);
	switch (reqData->buf[2 + padding + security_param]) // Message Identity
	{
	case MsgTypeIdentityRequest:
		resp = eap_vendor_test_process_5gnas_identity(id);
		break;
	case MsgTypeAuthenticationRequest:
		resp = eap_vendor_test_process_5gnas_authentcation(id, reqData, data);
		break;
	case MsgTypeSecurityModeCommand:
		resp = eap_vendor_test_process_5gnas_smc(id, reqData, data);
		break;
	case MsgTypeRegistrationAccept:
		resp = eap_vendor_test_process_reg_accept(reqData, data);
		break;
	case MsgTypeDLNASTransport:
		eap_vendor_test_process_DLnas_trasport(reqData, data);
		break;
	default:
		break;
	}
	return resp;
}

static struct wpabuf * eap_vendor_test_process_5gnotification(struct eap_sm *sm,
							 struct eap_vendor_test_data *data,
							 u8 id,
							 const struct wpabuf *reqData)
{
	struct wpabuf *resp_body = wpabuf_alloc(0), *resp;
	wpa_printf(MSG_DEBUG, "EAP-VENDOR-TYPE 5GNOTIFICATION: check identity match (id=%d)", id);
	// read data: AN parameter
	u8 pos = 16;
	u8 len;
	while (pos < wpabuf_len(reqData))
	{
		// iei
		u8 tmp = reqData->buf[pos++];
		if (tmp >= 0x80)
			tmp = (tmp & 0xf0) >> 4;
		switch (tmp)
		{
		// IPv4
		case 0x01:
			len = reqData->buf[pos];
			sprintf(data->ipv4, "%d.%d.%d.%d", reqData->buf[pos + 1], reqData->buf[pos + 2], reqData->buf[pos + 3], reqData->buf[pos + 4]);
			wpa_printf(MSG_DEBUG, "trying to solve the ipv4: %s", data->ipv4);
			memset(&data->sin_tngf, 0, sizeof(data->sin_tngf));
			data->sin_tngf.sin_family = AF_INET;
			data->sin_tngf.sin_addr.s_addr = inet_addr(data->ipv4);
			data->sin_tngf.sin_port = htons(500);
			pos += 5;
			break;
		// IPv6
		case 0x02:
			len = reqData->buf[pos];
			memcpy(data->ipv6, &reqData->buf[pos + 1], sizeof(data->ipv6));
			pos += 17;
			data->ipv6[16] = '\0';
			break;
		default:
			pos = wpabuf_len(reqData);
			break;
		}
	}

	// put data inside
	resp_body = eap_vendor_add_type(resp_body, EAP_VENDOR_TEST_SUBTYPE_5GNOTIFICATION);
	// wpabuf_resize(&resp_body, 1);
	// spare octet
	// wpabuf_put_u8(resp_body, 0x00);

	// build header
	resp = eap_msg_alloc(EAP_VENDOR_ID, EAP_VENDOR_TYPE, wpabuf_len(resp_body),
						 EAP_CODE_RESPONSE, id);

	resp = wpabuf_concat(resp, resp_body);

	return resp;
}

static struct wpabuf * eap_vendor_test_process(struct eap_sm *sm, void *priv,
											  struct eap_method_ret *ret,
											  const struct wpabuf *reqData)
{
	struct eap_vendor_test_data *data = priv;
	struct wpabuf *resp;
	const struct eap_hdr *req;
	const u8 *pos;
	u8 subtype, id;
	size_t len;

	wpa_hexdump_buf(MSG_DEBUG, "EAP-VENDOR-TYPE: EAP data", reqData);

	// check header present
	pos = eap_hdr_validate(EAP_VENDOR_ID, EAP_VENDOR_TYPE, reqData, &len);
	if (pos == NULL || len < 1)
	{
		ret->ignore = true;
		return NULL;
	}

	wpa_printf(MSG_DEBUG, "EAP header validation: %d, EAP data state: %d, len: %ld", *pos, data->state, len);

	// request type distinguisher
	req = wpabuf_head(reqData);
	id = eap_get_id(reqData);
	len = be_to_host16(req->length);

	// default false message
	ret->ignore = false;
	ret->methodState = METHOD_CONT;
	ret->decision = DECISION_FAIL;
	ret->allowNotifications = true;

	subtype = *pos++;
	wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: Subtype=%d", subtype);
	pos += 2; /* reserverd block*/

	switch (subtype)
	{
	case EAP_VENDOR_TEST_SUBTYPE_5GSTART:
		resp = eap_vendor_test_process_5gstart(data, id);
		data->state = CONFIRM;
		break;
	case EAP_VENDOR_TEST_SUBTYPE_5GNAS:
		resp = eap_vendor_test_process_5gnas(sm, data, id, reqData, 16);
		break;
	case EAP_VENDOR_TEST_SUBTYPE_5GNOTIFICATION:
		resp = eap_vendor_test_process_5gnotification(sm, data, id, reqData);
		break;
	default:
		wpa_printf(MSG_DEBUG, "EAP-VENDOR-TEST: Unknown subtype=%d", subtype);
		resp = eap_msg_alloc(EAP_VENDOR_ID, EAP_VENDOR_TYPE, 1,
							 EAP_CODE_RESPONSE, id);
		break;
	}

	wpa_hexdump_buf(MSG_DEBUG, "EAP-VENDOR-TYPE: EAP response data", resp);

	if (resp == NULL)
		return NULL;

	if (data->state == INIT) {
		data->state = CONFIRM;
		ret->methodState = METHOD_CONT;
		ret->decision = DECISION_FAIL;
	} else {
		ret->methodState = METHOD_CONT;
		ret->decision = DECISION_UNCOND_SUCC;
	}

	return resp;
}

static bool eap_vendor_test_isKeyAvailable(struct eap_sm *sm, void *priv)
{
	struct eap_vendor_test_data *data = priv;
	return data->state == SUCCESS;
}

static u8 *eap_vendor_test_getKey(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_vendor_test_data *data = priv;
	u8 *key;

	if (data->state != SUCCESS)
		return NULL;

	key = os_memdup(data->ktnap, 32);
	if (key == NULL)
		return NULL;

	*len = 32;

	return key;
}

/* Ref TS 23.502 Clause 4.12a.5
	   TS 24.501 Clause 8.3.1*/
static struct wpabuf * eap_vendor_test_pdu_session_establish_request(struct eap_sm *sm, void *priv)
{
	struct eap_vendor_test_data *data = priv;
	struct wpabuf *resp_nas_pdu = wpabuf_alloc(100);
	// ExtendedProtocolDiscriminator
	wpabuf_put_u8(resp_nas_pdu, Epd5GSSessionManagementMessage);
	// PDU session ID
	wpabuf_put_u8(resp_nas_pdu, data->pduSessionId);
	// PTI
	wpabuf_put_u8(resp_nas_pdu, 0x00);
	// ULNASTransportMessageIdentity
	wpabuf_put_u8(resp_nas_pdu, MsgTypePDUSessionEstablishmentRequest);
	// Integrity protection maximum data rate
	wpabuf_put_be16(resp_nas_pdu, 0xffff);
	// PDU session type: IPv4 (0x01)
	wpabuf_put_u8(resp_nas_pdu, PDUSessionEstablishmentRequestPDUSessionTypeType);
	wpabuf_put_u8(resp_nas_pdu, 0x01);
	// SSC Mode: mode 1
	wpabuf_put_u8(resp_nas_pdu, PDUSessionEstablishmentRequestSSCModeType);
	wpabuf_put_u8(resp_nas_pdu, 0x01);
	// Extended protocol configuration options
	// Ref TS 24.008 Clause 10.5.6.3
	wpabuf_put_u8(resp_nas_pdu, PDUSessionEstablishmentRequestExtendedProtocolConfigurationOptionsType);
	struct wpabuf *ExtendedProtocolConfigurationOptions = wpabuf_alloc(20);
	// extend, spare, config protocol
	wpabuf_put_u8(ExtendedProtocolConfigurationOptions, 0x80);
	// IPAddressAllocationViaNASSignallingUL
	wpabuf_put_be16(ExtendedProtocolConfigurationOptions, IPAddressAllocationViaNASSignallingUL);
	wpabuf_put_u8(ExtendedProtocolConfigurationOptions, 0x00);
	// DNSServerIPv4AddressRequestUL
	wpabuf_put_be16(ExtendedProtocolConfigurationOptions, DNSServerIPv4AddressRequestUL);
	wpabuf_put_u8(ExtendedProtocolConfigurationOptions, 0x00);
	// DNSServerIPv6AddressRequestUL
	wpabuf_put_be16(ExtendedProtocolConfigurationOptions, DNSServerIPv6AddressRequestUL);
	wpabuf_put_u8(resp_nas_pdu, 0x00);

	// concatenation
	wpabuf_put_u8(resp_nas_pdu, wpabuf_len(ExtendedProtocolConfigurationOptions));
	resp_nas_pdu = wpabuf_concat(resp_nas_pdu, ExtendedProtocolConfigurationOptions);

	return resp_nas_pdu;
}

/* Ref */
static void eap_vendor_test_ulNasTransport(struct eap_sm *sm, void *priv)
{
	struct eap_vendor_test_data *data = priv;
	struct wpabuf * pduSessionEstReq = wpabuf_alloc(0);
	pduSessionEstReq = eap_vendor_test_pdu_session_establish_request(sm, data);

	struct wpabuf * resp = wpabuf_alloc(100);
	// ExtendedProtocolDiscriminator
	wpabuf_put_u8(resp, Epd5GSMobilityManagementMessage);
	// SpareHalfOctetAndSecurityHeaderType
	wpabuf_put_u8(resp, SecurityHeaderTypePlainNas);
	// MsgTypeIdentityResponse
	wpabuf_put_u8(resp, MsgTypeULNASTransport);
	// Payload container type and Spare half octet
	wpabuf_put_u8(resp, PayloadContainerTypeN1SMInfo);
	// Payload container
	wpabuf_put_be16(resp, wpabuf_len(pduSessionEstReq));
	resp = wpabuf_concat(resp, pduSessionEstReq);
	wpabuf_resize(&resp, 100);
	// PDU session ID
	wpabuf_put_u8(resp, ULNASTransportPduSessionID2ValueType);
	wpabuf_put_u8(resp, data->pduSessionId);
	// ULNASTransportRequestTypeType
	wpabuf_put_u8(resp, ULNASTransportRequestTypeType + (ULNASTransportRequestTypeInitialRequest & 7));
	// S-NSSAI
	wpabuf_put_u8(resp, ULNASTransportSNSSAIType);
	wpabuf_put_u8(resp, 0x04);
	// SST, SD
	wpabuf_put_be32(resp, 0x01010203);
	// DNN
	wpabuf_put_u8(resp, ULNASTransportDNNType);
	wpabuf_put_u8(resp, 0x09);
	// 1st segment length
	wpabuf_put_u8(resp, 0x08);
	u8 dnn[] = "internet";
	wpabuf_put_data(resp, dnn, 8);

	// security header type
	u8 security_param = 2;
	resp = BuildSecureNAS(security_param, resp, data);

	wpa_hexdump_buf(MSG_DEBUG, "ulNasTransport for pduSessionEstablishmentReq: ", resp);
	write(data->s_tcp, (u8 *)wpabuf_head(resp), wpabuf_len(resp));

	eap_vendor_test_ikev2_process(sm, data);
}

/* Ref TS 24.502 Clause 7.3A.3 */
static void eap_vendor_test_NWt_setup(struct eap_sm *sm, void *priv)
{
	struct eap_vendor_test_data *data = priv;

	data->ikev2.child_sa[data->ikev2.child_sa_idx].xfrmIfaceId = data->ikev2.child_sa_idx + 1;
	// generate key
	ikev2_generate_key_for_childSA(&data->ikev2);
	// reading wifiifname
	FILE *f = fopen("sec.conf", "r");
	if (f == NULL) {
		wpa_printf(MSG_ERROR, "File sec.conf not exist\n");
		exit(1);
	}
	char buffer[64];
	char wifiifname[IFNAMSIZ-1];
	memset(wifiifname, 0, IFNAMSIZ-1);
	while (fgets(buffer, 64, f) != NULL) {
		wpa_printf(MSG_DEBUG, "%s", buffer);
		char *token = strtok(buffer, ":");
		char *val = strtok(NULL, ":");
		val = strtok(val, "\n");
		if (strncmp(token, "wifiifname", 10) == 0) {
			strncpy(wifiifname, val, IFNAMSIZ-1);
		}
	}
	if (wifiifname[0] == 0) {
		wpa_printf(MSG_ERROR, "please set wifiifname in wpa_supplicant/sec.conf. ");
		exit(1);
	}
	// Xfrm Rules
	char *link_add = malloc(200 * sizeof(char));
	sprintf(link_add, "ip link add xfrm-%d type xfrm dev %s if_id %d", data->ikev2.child_sa[data->ikev2.child_sa_idx].xfrmIfaceId, wifiifname, data->ikev2.child_sa[data->ikev2.child_sa_idx].xfrmIfaceId);
	wpa_printf(MSG_DEBUG, "link add: %s", link_add);
	system(link_add);
	free(link_add);
	char *addr_add = malloc(200 * sizeof(char));;
	sprintf(addr_add, "ip addr add %s/24 broadcast 10.0.0.255 dev xfrm-%d", data->ikev2.cfg->ueIPAddr, data->ikev2.child_sa[data->ikev2.child_sa_idx].xfrmIfaceId);
	system(addr_add);
	free(addr_add);
	char *set_up = malloc(200 * sizeof(char));;
	sprintf(set_up, "ip link set dev xfrm-%d up", data->ikev2.child_sa[data->ikev2.child_sa_idx].xfrmIfaceId);
	system(set_up);
	free(set_up);

	// flush odd xfrm rules
	system("ip xfrm state deleteall");
	system("ip xfrm policy deleteall");

	// insert state and policy

	char *state_add_init = malloc(200 * sizeof(char));
	sprintf(state_add_init, "ip xfrm state add src %s dst %s proto esp spi 0x%s mode tunnel auth \"hmac(sha1)\" 0x%s enc cipher_null \"\"",
			data->ipv4, data->NICIP, data->ikev2.child_sa[data->ikev2.child_sa_idx].r_spi, data->ikev2.child_sa[data->ikev2.child_sa_idx].integ_key_resp_to_init);
	wpa_printf(MSG_DEBUG, "state add: %s", state_add_init);
	system(state_add_init);
	free(state_add_init);

	char *state_add_resp = malloc(200 * sizeof(char));
	sprintf(state_add_resp, "ip xfrm state add src %s dst %s proto esp spi 0x%s mode tunnel auth \"hmac(sha1)\" 0x%s enc cipher_null \"\"",
			data->NICIP, data->ipv4, data->ikev2.sa.proposal[0].spi, data->ikev2.child_sa[data->ikev2.child_sa_idx].integ_key_init_to_resp);
	wpa_printf(MSG_DEBUG, "state add: %s", state_add_resp);
	system(state_add_resp);
	free(state_add_resp);

	char *policy_add_init = malloc(200 * sizeof(char));
	sprintf(policy_add_init, "ip xfrm policy add src %s dst %s proto tcp dir out tmpl src %s dst %s proto esp spi 0x%s mode tunnel",
			data->ikev2.cfg->ueIPAddr, data->ikev2.nas_ip_addr, data->NICIP, data->ipv4, data->ikev2.sa.proposal[0].spi);
	wpa_printf(MSG_DEBUG, "policy add: %s", policy_add_init);
	system(policy_add_init);
	free(policy_add_init);

	char *policy_add_resp = malloc(200 * sizeof(char));
	sprintf(policy_add_resp, "ip xfrm policy add src %s dst %s proto tcp dir in tmpl src %s dst %s proto esp spi 0x%s mode tunnel",
			data->ikev2.nas_ip_addr, data->ikev2.cfg->ueIPAddr, data->ipv4, data->NICIP, data->ikev2.child_sa[data->ikev2.child_sa_idx].r_spi);
	wpa_printf(MSG_DEBUG, "policy add: %s", policy_add_resp);
	system(policy_add_resp);
	free(policy_add_resp);

	system("ip xfrm state ls");
	system("ip xfrm policy ls");

	// IKEV2 socket setup
	struct protoent *ppe;
	ppe = getprotobyname("tcp");
	data->s_tcp = socket(PF_INET, SOCK_STREAM, ppe->p_proto);
	int enable = 1;
	setsockopt(data->s_tcp, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));

	struct sockaddr_in ue_addr;
	bzero(&ue_addr, sizeof(ue_addr));
	ue_addr.sin_family = AF_INET;
	ue_addr.sin_addr.s_addr = inet_addr(data->ikev2.cfg->ueIPAddr);
	ue_addr.sin_port = htons(4500);

	wpa_printf(MSG_DEBUG, "bind to the client IP %s 4500", data->ikev2.cfg->ueIPAddr);
	if (bind(data->s_tcp, (struct sockaddr*) &ue_addr, sizeof(ue_addr)) != 0)
		wpa_printf(MSG_ERROR, "bind to the client IP fail...");
	else
		wpa_printf(MSG_DEBUG, "bind to the client IP %s", data->ikev2.cfg->ueIPAddr);

	struct sockaddr_in servaddr;
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr(data->ikev2.nas_ip_addr);
	servaddr.sin_port = htons(data->ikev2.nas_ip_port);

	// connect the client socket to server socket
	if (connect(data->s_tcp, (struct sockaddr*) &servaddr, sizeof(servaddr)) != 0)
		wpa_printf(MSG_ERROR, "connection with the server failed...");
	else
		wpa_printf(MSG_DEBUG, "connected to the server.. %s %d", data->ikev2.nas_ip_addr,
			data->ikev2.nas_ip_port);

	int sin_size = sizeof(servaddr), actual_size;
	u8 buf[BUF_SIZE];

	actual_size = read(data->s_tcp, (u8 *)buf, BUF_SIZE);
	struct wpabuf *resp = wpabuf_alloc(actual_size - 2);
	wpabuf_put_data(resp, &buf[2], actual_size - 2);

	resp = eap_vendor_test_process_5gnas(sm, data, 0, resp, 0);

	write(data->s_tcp, (u8 *)wpabuf_head(resp), wpabuf_len(resp));

	// sleep to wait for registration complete finish
	usleep(5000);
	eap_vendor_test_ulNasTransport(sm, data);
	/*
	// TCP connection
	struct sockaddr_nl sa;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_groups = XFRMNLGRP(ACQUIRE) | XFRMNLGRP(EXPIRE) |
				   XFRMNLGRP(MIGRATE) | XFRMNLGRP(MAPPING);
	data->ikev2.xfrm_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (bind(data->ikev2.xfrm_sock, (struct sockaddr*)&addr, sizeof(addr)))
	{
		wpa_printf(MSG_ERROR, "unable to bind XFRM event socket: %s (%d)",
			 strerror(errno), errno);
		destroy(this);
		return NULL;
	}
	*/

}

/* Ref TS 24.502 Clause 7.3A.3 */
static void eap_vendor_test_GRE_setup(struct eap_sm *sm, void *priv)
{
	wpa_printf(MSG_DEBUG, "I am GRE");
	struct eap_vendor_test_data *data = priv;

	data->ikev2.child_sa[data->ikev2.child_sa_idx].xfrmIfaceId = data->ikev2.child_sa_idx + 1;
	// generate key
	ikev2_generate_key_for_childSA(&data->ikev2);

	// insert state and policy
	char *state_add_init = malloc(200 * sizeof(char));
	sprintf(state_add_init, "ip xfrm state add src %s dst %s proto esp spi 0x%s mode tunnel auth \"hmac(sha1)\" 0x%s enc cipher_null \"\"",
			data->ipv4, data->NICIP, data->ikev2.child_sa[data->ikev2.child_sa_idx].i_spi, data->ikev2.child_sa[data->ikev2.child_sa_idx].integ_key_init_to_resp);
	wpa_printf(MSG_DEBUG, "state add: %s", state_add_init);
	system(state_add_init);
	free(state_add_init);

	char *state_add_resp = malloc(200 * sizeof(char));
	sprintf(state_add_resp, "ip xfrm state add src %s dst %s proto esp spi 0x%s mode tunnel auth \"hmac(sha1)\" 0x%s enc cipher_null \"\"",
			data->NICIP, data->ipv4, data->ikev2.sa.proposal[0].spi, data->ikev2.child_sa[data->ikev2.child_sa_idx].integ_key_resp_to_init);
	wpa_printf(MSG_DEBUG, "state add: %s", state_add_resp);
	system(state_add_resp);
	free(state_add_resp);

	char *policy_add_init = malloc(200 * sizeof(char));
	sprintf(policy_add_init, "ip xfrm policy add src %s dst %s proto gre dir out tmpl src %s dst %s proto esp spi 0x%s mode tunnel",
			data->ikev2.cfg->ueIPAddr, data->ikev2.up_ip_addr, data->NICIP, data->ipv4, data->ikev2.sa.proposal[0].spi);
	wpa_printf(MSG_DEBUG, "policy add: %s", policy_add_init);
	system(policy_add_init);
	free(policy_add_init);

	char *policy_add_resp = malloc(200 * sizeof(char));
	sprintf(policy_add_resp, "ip xfrm policy add src %s dst %s proto gre dir in tmpl src %s dst %s proto esp spi 0x%s mode tunnel",
			data->ikev2.up_ip_addr, data->ikev2.cfg->ueIPAddr, data->ipv4, data->NICIP, data->ikev2.child_sa[data->ikev2.child_sa_idx].i_spi);
	wpa_printf(MSG_DEBUG, "policy add: %s", policy_add_resp);
	system(policy_add_resp);
	free(policy_add_resp);

	system("ip xfrm state ls");
	system("ip xfrm policy ls");

	int actual_size;
	u8 buf[BUF_SIZE];

	actual_size = read(data->s_tcp, (u8 *)buf, BUF_SIZE);
	struct wpabuf *resp = wpabuf_alloc(actual_size - 2);
	wpabuf_put_data(resp, &buf[2], actual_size - 2);
	wpa_hexdump_buf(MSG_DEBUG, "my response is ", resp);

	eap_vendor_test_process_5gnas(sm, data, 0, resp, 0);
}

// the following ikev2 connection precedure after EAP_SUCCESS
void eap_vendor_test_ikev2_process(struct eap_sm *sm, void *priv)
{
	struct eap_vendor_test_data *data = priv;
	struct wpabuf *resp = wpabuf_alloc(0);
	wpa_printf(MSG_DEBUG, "Try to receive packet in IKE");
	int sin_size = sizeof(data->sin_tngf), actual_size;
	u8 buf[BUF_SIZE];
	if ( (actual_size = recvfrom(data->s, (u8 *)buf, BUF_SIZE, MSG_WAITALL, (struct sockaddr *) &data->sin_tngf,
			   &sin_size)) == SO_ERROR)
		wpa_printf(MSG_DEBUG, "Fail to receive from tngf socket");
	wpabuf_set(resp, buf, actual_size);
	ikev2_initiator_process(&data->ikev2, resp);
	if (data->ikev2.state == SA_AUTH)
	{
		resp = ikev2_initiator_build(&data->ikev2);
		sendto(data->s, resp->buf, resp->used, 0, (struct sockaddr *) &data->sin_tngf,
				sizeof(data->sin_tngf));
		eap_vendor_test_ikev2_process(sm, data);
	} else if (data->ikev2.state == NAS_REGISTER)
		eap_vendor_test_NWt_setup(sm, data);
	else if (data->ikev2.state == CHILD_SA)
	{
		data->ikev2.child_sa = realloc(data->ikev2.child_sa, (data->ikev2.child_sa_idx + 2) * sizeof (struct ikev2_child_sa));
		resp = ikev2_initiator_build(&data->ikev2);
		sendto(data->s, resp->buf, resp->used, 0, (struct sockaddr *) &data->sin_tngf,
				sizeof(data->sin_tngf));
		data->ikev2.child_sa_idx++;
		eap_vendor_test_GRE_setup(sm, data);
	}
}

void eap_vendor_test_ikev2_conn(struct eap_sm *sm, void *priv)
{
	struct eap_vendor_test_data *data = priv;
	struct wpabuf *resp;

	data->ikev2.state = SA_INIT;
	data->ikev2.peer_auth = PEER_AUTH_SECRET;
	data->ikev2.key_pad = (u8 *) os_strdup("Key Pad for IKEv2");
	if (data->ikev2.key_pad == NULL)
		wpa_printf(MSG_INFO, "EAP-IKEV2: BAD KEY PAD");
	data->ikev2.key_pad_len = 17;
	data->ikev2.IDi = os_memdup(&data->ueid[3], (sizeof(data->ueid) - 3) * sizeof(u8));
	data->ikev2.IDi_len = sizeof(data->ueid) - 3;
	data->ikev2.tsi = malloc(sizeof(struct ikev2_traffic_selector));
	data->ikev2.tsr = malloc(sizeof(struct ikev2_traffic_selector));
	data->ikev2.tsi->ts_ip[0] = malloc(4 * sizeof(u8));
	data->ikev2.tsi->ts_ip[1] = malloc(4 * sizeof(u8));
	data->ikev2.tsr->ts_ip[0] = malloc(4 * sizeof(u8));
	data->ikev2.tsr->ts_ip[1] = malloc(4 * sizeof(u8));
	for (int i = 0; i < 4; i++)
	{
		data->ikev2.tsi->ts_ip[0][i] = 0;
		data->ikev2.tsi->ts_ip[1][i] = 255;
		data->ikev2.tsr->ts_ip[0][i] = 0;
		data->ikev2.tsr->ts_ip[1][i] = 255;
	}
	for (int i = 0; i < 2; i++)
	{
		data->ikev2.tsi->ts_port[0][i] = 0;
		data->ikev2.tsi->ts_port[1][i] = 255;
		data->ikev2.tsr->ts_port[0][i] = 0;
		data->ikev2.tsr->ts_port[1][i] = 255;
	}

	// build up proposal: DH
	struct ikev2_proposal_data prop;

	data->ikev2.sa.proposal_cnt = 1;
	data->ikev2.sa.proposal = malloc(sizeof (struct ikev2_proposal_data));
	data->ikev2.sa.proposal[0].integ = 2; // AUTH_HMAC_SHA1_96
	data->ikev2.sa.proposal[0].prf = 2; // PRF_HMAC_SHA1
	data->ikev2.sa.proposal[0].encr = 12; // ENCR_AES_CBC
	data->ikev2.sa.proposal[0].dh = 14; // DH_2048_BIT_MODP
	data->ikev2.sa.proposal[0].esn = 0; // Extended Sequence Numbers
	data->ikev2.sa.proposal[0].proposal_num = 1;
	data->ikev2.child_sa = malloc(sizeof (struct ikev2_child_sa));
	data->ikev2.dh = dh_groups_get(data->ikev2.sa.proposal[0].dh);
	data->ikev2.r_dh_private = wpabuf_alloc(0);
	data->ikev2.child_sa_idx = 0;

	sleep(10);
	// build up proposal: Key Exchange
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;
	ifr.ifr_addr.sa_family = AF_INET;
	// reading wifiifname
	FILE *f = fopen("sec.conf", "r");
	if (f == NULL) {
		wpa_printf(MSG_ERROR, "File sec.conf not exist\n");
		exit(1);
	}
	char buffer[64];
	char wifiifname[IFNAMSIZ-1];
	memset(wifiifname, 0, IFNAMSIZ-1);
	while (fgets(buffer, 64, f) != NULL) {
		wpa_printf(MSG_DEBUG, "%s", buffer);
		char *token = strtok(buffer, ":");
		char *val = strtok(NULL, ":");
		val = strtok(val, "\n");
		if (strncmp(token, "wifiifname", 10) == 0) {
			strncpy(wifiifname, val, IFNAMSIZ-1);
		}
	}
	if (wifiifname[0] == 0) {
		wpa_printf(MSG_ERROR, "please set wifiifname in wpa_supplicant/sec.conf. ");
		exit(1);
	}
	strncpy(ifr.ifr_name, wifiifname, IFNAMSIZ-1);
	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);
	data->NICIP = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
	resp = ikev2_initiator_build(&data->ikev2);
	// IKEV2 socket setup
	struct protoent *ppe;
	ppe = getprotobyname("udp");
	data->s = socket(PF_INET, SOCK_DGRAM, ppe->p_proto);
	int enable = 1;
	setsockopt(data->s, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
	sendto(data->s, resp->buf, resp->used, 0, (struct sockaddr *) &data->sin_tngf,
				sizeof(data->sin_tngf));
	eap_vendor_test_ikev2_process(sm, data);
}

int eap_peer_vendor_test_register(void)
{
	struct eap_method *eap;

	eap = eap_peer_method_alloc(EAP_PEER_METHOD_INTERFACE_VERSION,
								EAP_VENDOR_ID, EAP_VENDOR_TYPE,
								"VENDOR-TEST");
	if (eap == NULL)
		return -1;

	eap->init = eap_vendor_test_init;
	eap->deinit = eap_vendor_test_deinit;
	eap->process = eap_vendor_test_process;
	eap->isKeyAvailable = eap_vendor_test_isKeyAvailable;
	eap->getKey = eap_vendor_test_getKey;
#ifdef EAP_VENDOR_TEST
	eap->ikev2_conn = eap_vendor_test_ikev2_conn;
#endif

	return eap_peer_method_register(eap);
}
