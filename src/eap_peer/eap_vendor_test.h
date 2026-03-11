#include "includes.h"
#include "common.h"
#include "eap_i.h"
#include "eloop.h"
#include "count.h"
#include "crypto/milenage.h"
#include "crypto/sha256.h"
#include "crypto/aes_wrap.h"
#include "crypto/dh_groups.h"
#include <strings.h>
#include <netinet/in.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>
#include "ikev2.h"
#include <stdio.h>
#include <regex.h>

/**
 * Create ORable bitfield of XFRM NL groups
 */
#define XFRMNLGRP(x) (1<<(XFRMNLGRP_##x-1))
#define BUF_SIZE 65535

struct ue_info{
	u8 typeBytes[1];
	u8 plmnBytes[3];
	u8 ridBytes[2];
	u8 schidBytes[1];
	u8 hnPubKeyIdBytes[1];
	u8 msinBytes[5];
};

struct eap_vendor_test_data {
	enum { INIT, CONFIRM, SUCCESS} state;
	char supi[17]; //length may be 15 or 16 digits 
	int first_try;
	u8 cipher, integrity;
	u8 ueid[16];
	struct ue_info ueinfo;
	char ipv4[16];
	char ipv6[17];
	u8 * kamf;
	// key derivation
	u8 *nas_uplink_cnt;
	struct cnt uplink_cnt;
	struct cnt downlink_cnt;
	// security nas
	u8 * k_nas_enc;
	u8 * k_nas_int;
	u8 * ktngf;
	u8 * ktnap;
	struct ikev2_responder_data ikev2;
	struct sockaddr_in sin_tngf;	/* an Internet endpoint address		*/
	char *NICIP;
	int s; /* socket */
	int s_tcp; /* socket for IPSec */
	int pduSessionId;
	u8 * pdu_address;
};

// FC for UE Auth
#define FC_FOR_KSEAF_DERIVATION              0x6C
#define FC_FOR_RES_STAR_XRES_STAR_DERIVATION 0x6B
#define FC_FOR_KAUSF_DERIVATION              0x6A
#define FC_FOR_KAMF_DERIVATION               0x6D
#define FC_FOR_KTNGF_DERIVATION              0x6E
#define FC_FOR_ALGORITHM_KEY_DERIVATION      0x69
#define FC_FOR_KTIPSEC_KTNAP_DERIVATION      0x84

// EPD 5GS Type
#define Epd5GSMobilityManagementMessage 0x7e
#define Epd5GSSessionManagementMessage  0x2e

// NAS Message Type
#define MsgTypeRegistrationRequest                              65
#define MsgTypeRegistrationAccept                               66
#define MsgTypeRegistrationComplete                             67
#define MsgTypeRegistrationReject                               68
#define MsgTypeDeregistrationRequestUEOriginatingDeregistration 69
#define MsgTypeDeregistrationAcceptUEOriginatingDeregistration  70
#define MsgTypeDeregistrationRequestUETerminatedDeregistration  71
#define MsgTypeDeregistrationAcceptUETerminatedDeregistration   72
#define MsgTypeServiceRequest                                   76
#define MsgTypeServiceReject                                    77
#define MsgTypeServiceAccept                                    78
#define MsgTypeConfigurationUpdateCommand                       84
#define MsgTypeConfigurationUpdateComplete                      85
#define MsgTypeAuthenticationRequest                            86
#define MsgTypeAuthenticationResponse                           87
#define MsgTypeAuthenticationReject                             88
#define MsgTypeAuthenticationFailure                            89
#define MsgTypeAuthenticationResult                             90
#define MsgTypeIdentityRequest                                  91
#define MsgTypeIdentityResponse                                 92
#define MsgTypeSecurityModeCommand                              93
#define MsgTypeSecurityModeComplete                             94
#define MsgTypeSecurityModeReject                               95
#define MsgTypeStatus5GMM                                       100
#define MsgTypeNotification                                     101
#define MsgTypeNotificationResponse                             102
#define MsgTypeULNASTransport                                   103
#define MsgTypeDLNASTransport                                   104
#define MsgTypePDUSessionEstablishmentRequest					193
#define MsgTypePDUSessionEstablishmentAccept					194

#define SecurityHeaderTypePlainNas                                                 0x00
#define	SecurityHeaderTypeIntegrityProtected                                       0x01
#define	SecurityHeaderTypeIntegrityProtectedAndCiphered                            0x02
#define	SecurityHeaderTypeIntegrityProtectedWithNew5gNasSecurityContext            0x03
#define	SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext 0x04

#define PDUSessionEstablishmentRequestPDUSessionTypeType						0x09
#define PDUSessionEstablishmentRequestSSCModeType								0x0A
#define PDUSessionEstablishmentRequestCapability5GSMType						0x28
#define PDUSessionEstablishmentRequestMaximumNumberOfSupportedPacketFiltersType	0x55
#define PDUSessionEstablishmentRequestAlwaysonPDUSessionRequestedType			0x0B
#define PDUSessionEstablishmentRequestSMPDUDNRequestContainerType				0x39
#define PDUSessionEstablishmentRequestExtendedProtocolConfigurationOptionsType	0x7B

// TS 24.008 Clause 10.5.6.3
#define IPAddressAllocationViaNASSignallingUL					0x000a
#define DNSServerIPv4AddressRequestUL							0x000d
#define DNSServerIPv6AddressRequestUL							0x0003

#define PayloadContainerTypeN1SMInfo							0x1

#define ULNASTransportPduSessionID2ValueType					0x12
#define ULNASTransportRequestTypeType							0x80
#define ULNASTransportRequestTypeInitialRequest					0x01
#define ULNASTransportDNNType									0x25
#define ULNASTransportSNSSAIType								0x22
// Registration request message content
typedef struct _nas_5GMMCapability {
	u8 iei;
	u8 len;
	u8 val[13];
} nas_5GMMCapability;

typedef struct _nas_UESecurityCapability {
	u8 iei;
	u8 len;
	u8 val[8];
} nas_UESecurityCapability;

typedef struct _RegexMatchRes{
	int start;
	int end;
} RegexMatchRes;

/* Function declarations for UE deregistration */

/**
 * eap_vendor_test_initiate_deregistration - Initiate UE deregistration sequence
 * @sm: EAP state machine pointer
 * @priv: Private data (eap_vendor_test_data structure)
 * 
 * Initiates the complete UE-originated deregistration flow:
 * 1. Builds and sends Deregistration Request
 * 2. Handles IKE DELETE message from TNGF
 * 3. Processes Deregistration Accept response
 */
void eap_vendor_test_initiate_deregistration(struct eap_sm *sm, void *priv);

/* Deregistration Type */
#define DEREG_TYPE_NORMAL                                           0x01
#define DEREG_TYPE_NORMAL_SWITCH_OFF                                0x09

/* Deregistration context for UE-originated deregistration */
struct ue_deregister_context {
	int state;  /* 0=init, 1=deregistering, 2=deregistered */
	
	/* Security context */
	u8 *k_nas_int;
	u8 *k_nas_enc;
	u8 ngksi;
	
	/* UE identity - 5G-GUTI */
	u8 *guti;
	size_t guti_length;
	
	/* NAS counter */
	u32 uplink_count;
	u32 downlink_count;
	
	/* Cipher and integrity algorithm */
	int cipher_alg;
	int integ_alg;
};