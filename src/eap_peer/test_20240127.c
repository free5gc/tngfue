
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
#include "../utils/wpa_debug.h"
#include <stdio.h>


typedef uint8_t u8;


struct eap_vendor_test_data {
	enum { INIT, CONFIRM, SUCCESS} state;
	char supi[17]; //length may be 15 or 16 digits
	char suci[64]; 
	int first_try;
	u8 cipher, integrity;
	u8 ueid[15];
	char ipv4[16];
	char ipv6[17];
	u8 * kamf;
	// key derivation
	u8 *nas_uplink_cnt;
	// security nas
	u8 * k_nas_enc;
	u8 * k_nas_int;
	u8 * ktngf;
	u8 * ktnap;
	struct sockaddr_in sin_tngf;	/* an Internet endpoint address		*/
	char *NICIP;
	int s; /* socket */
	int s_tcp; /* socket for IPSec */
	int pduSessionId;
	u8 * pdu_address;
};

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

void get_ue_info(struct eap_vendor_test_data *data)
{
    FILE *f = fopen("../wpa_supplicant.conf", "r");
	if (f == NULL) {
		wpa_printf(MSG_ERROR, "File wpa_supplicant.conf not exist\n");
		exit(1);
	}
	char buffer[64];
	u8 *supi;
	while (fgets(buffer, 64, f) != NULL) {
		wpa_printf(MSG_DEBUG, "%s", buffer);
		char *token = strtok(buffer, ":");
		char *val = strtok(NULL, ":");
		val = strtok(val, "\n");
        
		if (strncmp(token, "imsi_identity", 13) == 0) {
			supi = malloc((strlen(val) / 2) * sizeof(u8));
			convert_byte(supi, val, strlen(val));
		}
	}
	fclose(f);
    printf("supi: ");
    for (int i=0;i<16;i++){
        printf("0x%02x", supi);
    }
}

int main(){
    struct eap_vendor_test_data *data;
    get_ue_info(data);
    return 0;
}

