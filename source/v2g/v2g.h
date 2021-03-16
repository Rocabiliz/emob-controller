#ifndef V2G_V2G_H_
#define V2G_V2G_H_

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include "stdint.h"
#include <stdbool.h>

#include "OpenV2G/codec/EXITypes.h"
#include "OpenV2G/codec/v2gEXIDatatypes.h"
#include "OpenV2G/codec/v2gEXIDatatypesEncoder.h"
#include "OpenV2G/xmldsig/xmldsigEXIDatatypes.h"
#include "OpenV2G/xmldsig/xmldsigEXIDatatypesEncoder.h"

#include "charger/charger.h"

#include "lwip/netif.h"
#include "lwip/netbuf.h"
#include "lwip/tcp.h"

#define V2G_HEADER_PROTO 0x01
#define V2G_SDP_SERVER_PORT 15118
#define TCP_BUFF_SIZE 6144

#define SDP_REQ_PAYLOAD_TYPE 0x9000
#define SDP_RES_PAYLOAD_TYPE 0x9001

#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))

struct __attribute__((packed)) v2g_header_t {
    uint8_t v2g_proto_version;
    uint8_t inverse_v2g_proto_version;
    uint8_t payload_type [2];
    uint8_t payload_length [4];
};

struct __attribute__((packed)) sdp_req_t {
    struct v2g_header_t v2g_header;
    uint8_t security;
    uint8_t transport_proto;
};

struct __attribute__((packed)) sdp_res_t {
    struct v2g_header_t v2g_header;
    uint8_t secc_ip_addr [16];
    uint8_t secc_port [2];
    uint8_t security;
    uint8_t transport_proto;
};

// Functions
void v2g_init();
void sdp_init();
double v2g_physical_val_get(struct v2gPhysicalValueType val1);
bool check_ev_session_id(struct v2gMessageHeaderType v2gHeader);
void supported_app_protocol_req(bitstream_t *stream);
void handle_session_setup(struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut);
void handle_service_discovery(struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut);
void handle_service_detail(struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut);
void handle_payment_service_selection(struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut);
void handle_payment_details(struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut);
void handle_certificate_installation(struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut);
void handle_certificate_update(struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut);
void handle_authorization(struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut);
void handle_charge_param_discovery(struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut);
void handle_cable_check(struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut);
void handle_pre_charge(struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut);
void handle_power_delivery(struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut);
void handle_current_demand(struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut);
void handle_welding_detection(struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut);
void handle_charging_status(struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut);
void handle_metering_receipt(struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut);
void handle_session_stop(struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut);

#endif
