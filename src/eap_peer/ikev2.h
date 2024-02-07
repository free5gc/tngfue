/*
 * IKEv2 responder (RFC 4306) for EAP-IKEV2
 * Copyright (c) 2007, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef IKEV2_H
#define IKEV2_H

#include "eap_common/ikev2_common.h"

struct ikev2_security_association {
	size_t proposal_cnt;
	struct ikev2_proposal_data *proposal;
};

struct ikev2_child_sa_5G_QoS {
	u8 pduSessionID;
	u8 QFIListLen;
	u8 *QFIList;
	bool isDefault;
	bool isDSCPSpecified;
};

struct ikev2_child_sa {
	char i_spi[IKEV2_SPI_SIZE_AH_ESP * 2 + 1];
	char r_spi[IKEV2_SPI_SIZE_AH_ESP * 2 + 1];

	// int xfrm_sock;
	int xfrmIfaceId;

	// char tngf_public_ip[16];
	// char n3ue_public_ip[16];

	// char tngf_internal_ip[16];
	// char n3ue_internal_ip[16];

	// int integ;
	char integ_key_init_to_resp[200];
	// size_t integ_key_init_to_resp_len;
	char integ_key_resp_to_init[200];
	// size_t integ_key_resp_to_init_len;
	struct ikev2_child_sa_5G_QoS QoS;
};

struct ikev2_proposal_data {
	u8 proposal_num;
	char spi[IKEV2_SPI_SIZE_AH_ESP * 2 + 1];
	int integ;
	int prf;
	int encr;
	int dh;
	int esn;
};

struct ikev2_traffic_selector {
	u8 ts_type;
	u8 ts_ip_proto;
	u8 *ts_ip[2];
	u8 ts_port[2][2];
	size_t ts_len;
};

struct ikev2_configuration {
	u8 cfg_type;
	// size_t attri_num;
	char ueIPAddr[16];
	u8 *ueIPNetMask;
	// u8* attri_type;
	// u8 ** cfg;
	// size_t* attri_len;
};

struct ikev2_responder_data {
	enum { SA_INIT, SA_AUTH, NAS_REGISTER, CHILD_SA, NOTIFY, IKEV2_DONE, IKEV2_FAILED }
		state;
	u8 i_spi[IKEV2_SPI_LEN];
	u8 r_spi[IKEV2_SPI_LEN];
	u8 i_nonce[IKEV2_NONCE_MAX_LEN];
	size_t i_nonce_len;
	u8 r_nonce[IKEV2_NONCE_MAX_LEN];
	size_t r_nonce_len;
	struct wpabuf *i_dh_public;
	struct wpabuf *r_dh_private;
	struct ikev2_security_association sa;
	const struct dh_group *dh;
	struct ikev2_keys keys;
	u8 *IDi;
	size_t IDi_len;
	u8 IDi_type;
	u8 *IDr;
	size_t IDr_len;
	u8 IDr_type;
	struct wpabuf *r_sign_msg;
	struct wpabuf *i_sign_msg;
	u8 *shared_secret;
	size_t shared_secret_len;
	enum { PEER_AUTH_CERT, PEER_AUTH_SECRET } peer_auth;
	u8 *key_pad;
	size_t key_pad_len;
	struct ikev2_traffic_selector *tsi;
	struct ikev2_traffic_selector *tsr;
	struct ikev2_configuration *cfg;
	char nas_ip_addr[16];
	char up_ip_addr[16];
	int nas_ip_port;
	u16 error_type;
	enum { LAST_MSG_SA_INIT, LAST_MSG_SA_AUTH } last_msg;
	struct ikev2_child_sa *child_sa;
	int child_sa_idx;
};


void ikev2_responder_deinit(struct ikev2_responder_data *data);
int ikev2_initiator_process(struct ikev2_responder_data *data,
			    const struct wpabuf *buf);
int ikev2_responder_process(struct ikev2_responder_data *data,
			    const struct wpabuf *buf);
struct wpabuf * ikev2_responder_build(struct ikev2_responder_data *data);
struct wpabuf * ikev2_initiator_build(struct ikev2_responder_data *data);

void ikev2_generate_key_for_childSA(struct ikev2_responder_data *data);

#endif /* IKEV2_H */
