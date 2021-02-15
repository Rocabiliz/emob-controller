/*
 * slac.h
 *
 *  Created on: 14 Apr 2019
 *      Author: Roque
 */

#ifndef SLAC_SLAC_H_
#define SLAC_SLAC_H_

#include <stdbool.h>
#include "stdint.h"

#include "OpenV2G/codec/v2gEXIDatatypes.h"

#include "charger/charger.h"

/* Configs */

/* Size related defines */
#define ETHER_ADDR_LEN 6
#define SLAC_RUNID_LEN 8
#define SLAC_UNIQUE_ID_LEN 17
#define SLAC_NID_LEN 7
#define SLAC_NMK_LEN 16
#define QCA_OUI_LEN 3
#define QCA_OUI 0x00B052
#define QCA_MAC 0x00B0520102
#define SLAC_BUFF_SIZE 258

/* ID related defines */
#define HPGP_TYPE_ID 0x88E1
#define HPGP_MMV_0 0x00
#define HPGP_MMV_1 0x01

#define MMTYPE_REQ 0x0000
#define MMTYPE_CNF 0x0001
#define MMTYPE_IND 0x0002
#define MMTYPE_RSP 0x0003

#define CC_CCO_APPOINT 0x0000
#define CC_BACKUP_APPOINT 0x0004
#define CC_LINK_INFO 0x0008
#define CC_HANDOVER 0x000C
#define CC_HANDOVER_INFO 0x0010
#define CC_DISCOVER_LIST 0x0014
#define CC_LINK_NEW 0x0018
#define CC_LINK_MOD 0x001C
#define CC_LINK_SQZ 0x0020
#define CC_LINK_REL 0x0024
#define CC_DETECT_REPORT 0x0028
#define CC_WHO_RU 0x002C
#define CC_ASSOC 0x0030
#define CC_LEAVE 0x0034
#define CC_SET_TEI_MAP 0x0038
#define CC_RELAY 0x003C
#define CC_BEACON_RELIABILITY 0x0040
#define CC_ALLOC_MOVE 0x0044
#define CC_ACCESS_NEW 0x0048
#define CC_ACCESS_REL 0x004C
#define CC_DCPPC 0x0050
#define CC_HP1_DET 0x0054
#define CC_BLE_UPDATE 0x0058
#define CP_PROXY_APPOINT 0x2000
#define PH_PROXY_APPOINT 0x2004
#define CP_PROXY_WAKE 0x2008
#define NN_INL 0x4000
#define NN_NEW_NET 0x4004
#define NN_ADD_ALLOC 0x4008
#define NN_REL_ALLOC 0x400C
#define NN_REL_NET 0x4010
#define CM_ASSOCIATED_STA 0x6000
#define CM_ENCRYPTED_PAYLOAD 0x6004
#define CM_SET_KEY 0x6008
#define CM_GET_KEY 0x600C
#define CM_SC_JOIN 0x6010
#define CM_CHAN_EST 0x6014
#define CM_TM_UPDATE 0x6018
#define CM_AMP_MAP 0x601C
#define CM_BRG_INFO 0x6020
#define CM_CONN_NEW 0x6024
#define CM_CONN_REL 0x6028
#define CM_CONN_MOD 0x602C
#define CM_CONN_INFO 0x6030
#define CM_STA_CAP 0x6034
#define CM_NW_INFO 0x6038
#define CM_GET_BEACON 0x603C
#define CM_HFID 0x6040
#define CM_MME_ERROR 0x6044
#define CM_NW_STATS 0x6048
#define CM_SLAC_PARAM 0x6064
#define CM_START_ATTEN_CHAR 0x6068
#define CM_ATTEN_CHAR 0x606C
#define CM_PKCS_CERT 0x6070
#define CM_MNBC_SOUND 0x6074
#define CM_VALIDATE 0x6078
#define CM_SLAC_MATCH 0x607C
#define CM_SLAC_USER_DATA 0x6080
#define CM_ATTEN_PROFILE 0x6084
#define VS_PL_LINK_STATUS 0xA0B8

/* SLAC protocol related defines */
#define NUM_RX_START_ATTEN_CHAR_IND 3
#define NUM_RX_MNBC_SOUNDS_IND 10

/* Header Structs */
struct __attribute__((packed)) ethernet_hdr {
	uint8_t ODA [ETHER_ADDR_LEN];
	uint8_t OSA [ETHER_ADDR_LEN];
	uint16_t MTYPE;
};

struct __attribute__((packed)) homeplug_hdr {
	uint8_t MMV;
	uint16_t MMTYPE;
};

struct __attribute__((packed)) homeplug_fmi {
	uint8_t MMV;
	uint16_t MMTYPE;
	uint8_t FMSN;
	uint8_t FMID;
};

struct __attribute__((packed)) qualcomm_hdr {
	uint8_t MMV;
	uint16_t MMTYPE;
	uint8_t OUI [QCA_OUI_LEN];
};

struct __attribute__((packed)) qualcomm_fmi {
	uint8_t MMV;
	uint16_t MMTYPE;
	uint8_t FMSN;
	uint8_t FMID;
	uint8_t OUI [QCA_OUI_LEN];
};

/* SLAC Protocol Structs */
struct __attribute__((packed)) cm_slac_param_request_t {
	struct ethernet_hdr ethernet;
	struct homeplug_fmi homeplug;
	uint8_t APPLICATION_TYPE;
	uint8_t SECURITY_TYPE;
	uint8_t RunID [SLAC_RUNID_LEN];
	uint8_t CipherSuiteSetSize;
	uint16_t CipherSuite [1];
};

struct __attribute__((packed)) cm_slac_param_confirm_t {
	struct ethernet_hdr ethernet;
	struct homeplug_fmi homeplug;
	uint8_t MSOUND_TARGET [ETHER_ADDR_LEN];
	uint8_t NUM_SOUNDS;
	uint8_t TIME_OUT;
	uint8_t RESP_TYPE;
	uint8_t FORWARDING_STA [ETHER_ADDR_LEN];
	uint8_t APPLICATION_TYPE;
	uint8_t SECURITY_TYPE;
	uint8_t RunID [SLAC_RUNID_LEN];
	uint16_t CipherSuite;
};

struct __attribute__((packed)) cm_start_atten_char_indicate_t {
	struct ethernet_hdr ethernet;
	struct homeplug_fmi homeplug;
	uint8_t APPLICATION_TYPE;
	uint8_t SECURITY_TYPE;
	struct __attribute__((packed)) {
		uint8_t NUM_SOUNDS;
		uint8_t TIME_OUT;
		uint8_t RESP_TYPE;
		uint8_t FORWARDING_STA [ETHER_ADDR_LEN];
		uint8_t RunID [SLAC_RUNID_LEN]; 
    } ACVarField;
};

struct __attribute__((packed)) cm_start_atten_char_response_t {
	struct ethernet_hdr ethernet;
	struct homeplug_fmi homeplug;
};

struct __attribute__((packed)) cm_atten_char_indicate_t {
	struct ethernet_hdr ethernet;
	struct homeplug_fmi homeplug;
	uint8_t APPLICATION_TYPE;
	uint8_t SECURITY_TYPE;
	struct __attribute__((packed)) {
		uint8_t SOURCE_ADDRESS [ETHER_ADDR_LEN];
		uint8_t RunID [SLAC_RUNID_LEN];
		uint8_t SOURCE_ID [SLAC_UNIQUE_ID_LEN];
		uint8_t RESP_ID [SLAC_UNIQUE_ID_LEN];
		uint8_t NUM_SOUNDS;
		struct __attribute__((packed)) {
			uint8_t NumGroups;
			uint8_t AAG [255];
		} ATTEN_PROFILE;
	} ACVarField;
};

struct __attribute__((packed)) cm_atten_char_response_t {
	struct ethernet_hdr ethernet;
	struct homeplug_fmi homeplug;
	uint8_t APPLICATION_TYPE;
	uint8_t SECURITY_TYPE;
	struct __attribute__((packed)) {
		uint8_t SOURCE_ADDRESS [ETHER_ADDR_LEN];
		uint8_t RunID [SLAC_RUNID_LEN];
		uint8_t SOURCE_ID [SLAC_UNIQUE_ID_LEN];
		uint8_t RESP_ID [SLAC_UNIQUE_ID_LEN];
		uint8_t Result;
	} ACVarField;
};

struct __attribute__((packed)) cm_mnbc_sound_indicate_t {
	struct ethernet_hdr ethernet;
	struct homeplug_fmi homeplug;
	uint8_t APPLICATION_TYPE;
	uint8_t SECURITY_TYPE;
	struct __attribute__((packed)) {
		uint8_t SenderID [SLAC_UNIQUE_ID_LEN];
		uint8_t CNT;
		uint8_t RunID [SLAC_RUNID_LEN];
		uint8_t RSVD;
		uint8_t RND [SLAC_UNIQUE_ID_LEN-1];
	} MSVarField;
};

struct __attribute__((packed)) cm_validate_request_t {
	struct ethernet_hdr ethernet;
	struct homeplug_fmi homeplug;
	uint8_t SignalType;
	struct __attribute__((packed)) {
		uint8_t Timer;
		uint8_t Result;
	} VRVarField;
};

struct __attribute__((packed)) cm_validate_confirm_t {
	struct ethernet_hdr ethernet;
	struct homeplug_fmi homeplug;
	uint8_t SignalType;
	struct __attribute__((packed)) {
		uint8_t ToggleNum;
		uint8_t Result;
	} VCVarField;
};

struct __attribute__((packed)) cm_slac_match_request_t {
	struct ethernet_hdr ethernet;
	struct homeplug_fmi homeplug;
	uint8_t APPLICATION_TYPE;
	uint8_t SECURITY_TYPE;
	uint16_t MVFLength;
	struct __attribute__((packed)) {
		uint8_t PEV_ID [SLAC_UNIQUE_ID_LEN];
		uint8_t PEV_MAC [ETHER_ADDR_LEN];
		uint8_t EVSE_ID [SLAC_UNIQUE_ID_LEN];
		uint8_t EVSE_MAC [ETHER_ADDR_LEN];
		uint8_t RunID [SLAC_RUNID_LEN];
		uint8_t RSVD [8];
	} MatchVarField;
};

struct __attribute__((packed)) cm_slac_match_confirm_t {
	struct ethernet_hdr ethernet;
	struct homeplug_fmi homeplug;
	uint8_t APPLICATION_TYPE;
	uint8_t SECURITY_TYPE;
	uint16_t MVFLength;
	struct __attribute__((packed)) {
		uint8_t PEV_ID [SLAC_UNIQUE_ID_LEN];
		uint8_t PEV_MAC [ETHER_ADDR_LEN];
		uint8_t EVSE_ID [SLAC_UNIQUE_ID_LEN];
		uint8_t EVSE_MAC [ETHER_ADDR_LEN];
		uint8_t RunID [SLAC_RUNID_LEN];
		uint8_t RSVD1 [8];
		uint8_t NID [SLAC_NID_LEN];
		uint8_t RSVD2;
		uint8_t NMK [SLAC_NMK_LEN];
	} MatchVarField;
};

struct __attribute__((packed)) cm_atten_profile_indicate_t {
	struct ethernet_hdr ethernet;
	struct homeplug_fmi homeplug;
	uint8_t PEV_MAC [ETHER_ADDR_LEN];
	uint8_t NumGroups;
	uint8_t RSVD;
	uint8_t AAG [255];
};

struct __attribute__((packed)) cm_set_key_request_t {
    struct ethernet_hdr ethernet;
    struct homeplug_fmi homeplug;
    uint8_t KEYTYPE;
    uint32_t MYNOUNCE;
    uint32_t YOURNOUNCE;
    uint8_t PID;
    uint16_t PRN;
    uint8_t PMN;
    uint8_t CCOCAP;
    uint8_t NID [SLAC_NID_LEN];
    uint8_t NEWEKS;
    uint8_t NEWKEY [SLAC_NMK_LEN];
    uint8_t RSVD [3];
};

struct __attribute__((packed)) cm_set_key_confirm_t {
    struct ethernet_hdr ethernet;
    struct homeplug_fmi homeplug;
    uint8_t RESULT;
    uint32_t MYNOUNCE;
    uint32_t YOURNOUNCE;
    uint8_t PID;
    uint16_t PRN;
    uint8_t PMN;
    uint8_t CCOCAP;
    uint8_t RSVD [27];
};

/* Qualcomm specific messages */
struct __attribute__((packed)) link_status_req_t {
    struct ethernet_hdr ethernet;
    struct qualcomm_hdr qualcomm;
};

struct __attribute__((packed)) link_status_cnf_t {
    struct ethernet_hdr ethernet;
    struct qualcomm_hdr qualcomm;
	uint8_t mmeStatus;
	uint8_t linkStatus;
};

/* Custom structs */
struct ev_data_t {
    uint8_t mac[ETHER_ADDR_LEN];
};

struct slac_rsp_t {
    uint8_t *frame;
    uint16_t len;
};

/* Functions */
bool checkBroadcastDestMacAddr(uint8_t *frame);
struct slac_rsp_t handleSlacFrame(uint8_t *frame, uint16_t len, uint8_t* dev_mac);
void getSlacRsp(uint16_t rx_msg_id, uint8_t *rx_frame, struct slac_rsp_t *rsp, struct charge_session_t *charging_session);
uint8_t cm_set_key_cnf(uint8_t *rx_frame);
uint8_t cm_slac_param_req(uint8_t *rx_frame, struct cm_slac_param_confirm_t *cm_slac_param_cnf, struct charge_session_t *charge_session);
uint8_t cm_start_atten_char_ind(uint8_t *rx_frame, struct charge_session_t *charge_session);
uint8_t cm_mnbc_sound_ind(uint8_t *rx_frame, struct charge_session_t *charge_session);
uint8_t cm_atten_profile_ind(uint8_t *rx_frame, struct charge_session_t *charge_session);
void cm_atten_char_ind(struct cm_atten_char_indicate_t *cm_atten_char_ind, struct charge_session_t *charge_session);
uint8_t cm_atten_char_rsp(uint8_t *rx_frame, struct charge_session_t *charge_session);
uint8_t cm_validate_req(uint8_t *rx_frame, struct charge_session_t *charge_session);
void cm_validate_cnf(struct cm_validate_confirm_t *cm_validate_cnf, struct charge_session_t *charge_session, uint8_t toggleNum, uint8_t result);
uint8_t cm_slac_match_req(uint8_t *rx_frame, struct cm_slac_match_confirm_t *cm_slac_match_cnf, struct charge_session_t *charge_session);
void link_status_req(struct charge_session_t *charge_session, struct link_status_req_t *link_status_req);
bool link_status_cnf(uint8_t *rx_frame);
void fill_slac_rsp(struct slac_rsp_t *rsp, uint8_t *frame, uint16_t len);

#endif /* SLAC_SLAC_H_ */
