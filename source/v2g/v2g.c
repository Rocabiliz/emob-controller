/*
 * v2g.c
 *
 *  Created on: 30 Sep 2020
 *      Author: Roque
 */
#include <stdio.h>
#include <string.h>
#include "stdint.h"
#include <time.h>
#include <math.h>
#include <stdbool.h>
#include <stdlib.h>

// V2G Includes
#include "OpenV2G/codec/EXITypes.h"
#include "OpenV2G/codec/v2gEXIDatatypes.h"
#include "OpenV2G/codec/v2gEXIDatatypesEncoder.h"
#include "OpenV2G/codec/v2gEXIDatatypesDecoder.h"
#include "OpenV2G/appHandshake/appHandEXIDatatypes.h"
#include "OpenV2G/appHandshake/appHandEXIDatatypesDecoder.h"
#include "OpenV2G/appHandshake/appHandEXIDatatypesEncoder.h"
#include "OpenV2G/transport/v2gtp.h"
#include "appHandEXIDatatypesDecoder.h"

// Custom includes
#include "slac/slac.h"
#include "v2g/v2g.h"
#include "charger/charger.h"
#include "v2g/v2g_comm.h"
#include "v2g/v2g_security.h"

// FreeRTOS
//#include "mpu_wrappers.h"

// lwip include
#include "lwip/sys.h"
#include "lwip/api.h"
#include "lwip/sockets.h"

// mbed tls 
#include "ksdk_mbedtls.h"
#include "mbedtls/certs.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_cache.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/base64.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"

static struct v2gEXIDocument exiIn, exiOut;

static void init_v2gExiDoc_response(struct v2gEXIDocument *exiDoc) {
	init_v2gEXIDocument(exiDoc);
	init_v2gMessageHeaderType(&exiDoc->V2G_Message.Header);
	memcpy(exiDoc->V2G_Message.Header.SessionID.bytes, charge_session.v2g.SessionID.bytes, charge_session.v2g.SessionID.bytesLen);
	exiDoc->V2G_Message.Header.SessionID.bytesLen = charge_session.v2g.SessionID.bytesLen;
	exiDoc->V2G_Message.Header.Notification_isUsed = 0u;
	exiDoc->V2G_Message.Header.Signature_isUsed = 0u;
    init_v2gBodyType(&exiDoc->V2G_Message.Body);
	exiDoc->V2G_Message_isUsed = 1u;
}

static int serializeEXI2Stream(struct v2gEXIDocument *exiIn, bitstream_t *stream) {
	int errn;
	*stream->pos = V2GTP_HEADER_LENGTH;  // v2gtp header
	if ((errn = encode_v2gExiDocument(stream, exiIn)) == 0) {
		errn = write_v2gtpHeader(stream->data, (*stream->pos)-V2GTP_HEADER_LENGTH, V2GTP_EXI_TYPE);
	}
	return errn;
}

// deserializes V2G TP header and decodes right away EXI stream
static int deserializeStream2EXI(bitstream_t *streamIn, struct v2gEXIDocument *exi) {
	int errn;
	uint16_t payloadLength;

	*streamIn->pos = 0;
	if ((errn = read_v2gtpHeader(streamIn->data, &payloadLength)) == 0) {
		*streamIn->pos += V2GTP_HEADER_LENGTH;

		errn = decode_v2gExiDocument(streamIn, exi);
	}
	return errn;
}

int secc_discovery_protocol(void* arg) {
    struct netconn *sdp_conn;
	struct netbuf *udp_buf;
	err_t err;
	int ret = 0;
    struct sdp_req_t *sdp_req;
    struct sdp_res_t sdp_res;

	LWIP_UNUSED_ARG(arg);
	PRINTF("*****************************\r\n");
	PRINTF("SDP - SECC Discovery Protocol\r\n");
	PRINTF("*****************************\r\n");
	/************************************
     * SDP - SECC DISCOVERY PROTOCOL
     * **********************************/
	// Prepare UDP/IPv6 connection
	/*
	// Do not restart SDP server while V2G session is active
	if (charge_session.v2g.session_active) {
		continue;
	}*/
	
	PRINTF("[SDP] Creating SDP/UDP socket...\r\n");
	sdp_conn = (struct netconn*)netconn_new(NETCONN_UDP_IPV6);
	if ((err = netconn_bind(sdp_conn, IP6_ADDR_ANY, V2G_SDP_SERVER_PORT)) != ERR_OK) { // port: 15118
		PRINTF("[SDP] SDP/UDP bind error: %err\r\n", err);
	}
	
	// Wait for SDP Request
	while (1) {
		PRINTF("[SDP] Waiting to receive UDP...\r\n");

		// Parse received message
		if ((err = netconn_recv(sdp_conn, &udp_buf)) == ERR_OK) {
			PRINTF("[SDP] Received SDP!\r\n");
			sdp_req = udp_buf->p->payload;

			if (sdp_req->v2g_header.v2g_proto_version != V2G_HEADER_PROTO) {
				PRINTF("[SDP] ERR: SDP REQ V2G Protocol version\r\n");
				continue;
			}
			else if (	sdp_req->v2g_header.inverse_v2g_proto_version != 
						(0xFF - sdp_req->v2g_header.v2g_proto_version)) {
				PRINTF("[SDP] ERR: SDP REQ V2G Inverse Protocol version\r\n");
				continue;
			}
			else if ((	(uint16_t)(sdp_req->v2g_header.payload_type[0] << 8) | 
						(uint16_t)(sdp_req->v2g_header.payload_type[1])) != SDP_REQ_PAYLOAD_TYPE) {
				PRINTF("[SDP] ERR: SDP REQ Payload Type: %u:%u\r\n", sdp_req->v2g_header.payload_type[0], sdp_req->v2g_header.payload_type[1]);
				continue;
			}
			else if (	((uint32_t)(sdp_req->v2g_header.payload_length[0] << 24) |
						(uint32_t)(sdp_req->v2g_header.payload_length[1] << 16) |
						(uint32_t)(sdp_req->v2g_header.payload_length[2] << 8) |
						(uint32_t)(sdp_req->v2g_header.payload_length[3])) != 
						(uint32_t)(sizeof(struct sdp_req_t) - sizeof(struct v2g_header_t))) {
				PRINTF("[SDP] ERR: SDP REQ Payload Length\r\n");
				continue;
			}

			// Save EV IPv6 ADDR
			memcpy(	charge_session.v2g.ev_ip_addr, 
					udp_buf->addr.u_addr.ip6.addr, 
					sizeof(udp_buf->addr.u_addr.ip6.addr));

			// SDP Response Header
			sdp_res.v2g_header.v2g_proto_version = V2G_HEADER_PROTO;
			sdp_res.v2g_header.inverse_v2g_proto_version = (0xFF - V2G_HEADER_PROTO);
			sdp_res.v2g_header.payload_type[0] = (uint8_t)(SDP_RES_PAYLOAD_TYPE >> 8);
			sdp_res.v2g_header.payload_type[1] = (uint8_t)SDP_RES_PAYLOAD_TYPE;
			sdp_res.v2g_header.payload_length[0] = (uint8_t)((uint32_t)(sizeof(struct sdp_res_t) - 
																		sizeof(struct v2g_header_t)) >> 24);
			sdp_res.v2g_header.payload_length[1] = (uint8_t)((uint32_t)(sizeof(struct sdp_res_t) - 
																		sizeof(struct v2g_header_t)) >> 16);
			sdp_res.v2g_header.payload_length[2] = (uint8_t)((uint32_t)(sizeof(struct sdp_res_t) - 
																		sizeof(struct v2g_header_t)) >> 8);
			sdp_res.v2g_header.payload_length[3] = (uint8_t)(sizeof(struct sdp_res_t) - sizeof(struct v2g_header_t));

			// SDP Response Body
			memcpy(sdp_res.secc_ip_addr, charge_session.charger.secc_ip_addr, 16);
			sdp_res.secc_port[0] = (uint8_t)(charge_session.charger.secc_v2g_port >> 8);
			sdp_res.secc_port[1] = (uint8_t)(charge_session.charger.secc_v2g_port);

			// TLS requested from EV?
			if (sdp_req->security == 0x00) {
				sdp_res.security = 0x00;
				charge_session.v2g.tls = true;
			}
			else {
				sdp_res.security = 0x10;
				charge_session.v2g.tls = false;
			}
			sdp_res.transport_proto = 0x00;

			// Prepare buffer to send
			PRINTF("[SDP] Sending SDP response..\r\n");
			netbuf_ref(udp_buf, &sdp_res, sizeof(struct sdp_res_t));

			if ((err = netconn_send(sdp_conn, udp_buf)) != ERR_OK) {
				PRINTF("[SDP] ERR: could not send SDP_Res: %d\r\n", err);
				ret = 1;
			}

			// Cleanup
			netbuf_delete(udp_buf);
			netconn_close(sdp_conn);
			netconn_delete(sdp_conn);

			charge_session.v2g.session_active = true; // engage V2G/TCP-IPv6
			PRINTF("[SDP] SDP DONE!\r\n");
			break;
		}
		else {
			PRINTF("[SDP] Error receiving message: %d\r\n", err);
			charge_session.v2g.session_active = false;
			ret = 2;
		}
	} 

	PRINTF("[SDP] Breaking SDP\r\n");
	//vTaskDelete(NULL);
	return ret;
}

void v2g_session(void *arg) {

  	LWIP_UNUSED_ARG(arg);

	uint8_t buffer[TCP_BUFF_SIZE];
	uint16_t len;
	struct netconn *conn, *newconn;
	err_t err;
	int ret;
	uint8_t v2g_state = 0; 
	uint16_t buffer_pos = 0;
	bitstream_t stream = {
        .size = TCP_BUFF_SIZE,
		.data = buffer,
        .pos  = &buffer_pos,
        .buffer = 0,
        .capacity = 0, // Set to 8 for send and 0 for recv
    };

	PRINTF("********************\r\n");
	PRINTF("V2G Protocol Session\r\n");
	PRINTF("********************\r\n");
/* TIMER EXAMPLE
	TickType_t xStart, xEnd, xDifference;
	for( ;; ) {
		xStart = xTaskGetTickCount();
		PRINTF("Delaying..\r\n");
		vTaskDelay( pdMS_TO_TICKS( 1000UL ) );
		PRINTF("Delay done!\r\n");
		xEnd = xTaskGetTickCount();
		xDifference = xEnd - xStart;
		PRINTF("Time diff: %lu ticks\n", xDifference );
	}
*/
    // Create a new connection identifier. 
	if ((conn = netconn_new(NETCONN_TCP_IPV6)) == NULL) {
		PRINTF("[V2G] New TCP Conn error\r\n");
	}
	if ((err = netconn_bind(conn, IP6_ADDR_ANY, charge_session.charger.secc_v2g_port)) != ERR_OK) {
		PRINTF("[V2G] TCP Conn bind error\r\n");
	}

	// Tell connection to go into listening mode.
	if ((err = netconn_listen(conn)) != ERR_OK) {
		PRINTF("[V2G] TCP Conn listen error\r\n");
	}
	PRINTF("[V2G] LISTEN OK\r\n");

	while (1) {

		PRINTF("[V2G] Starting V2G cycle\r\n");

		// Engage SDP (non-blocking)
		//sdp_init();
		if ((ret = secc_discovery_protocol(NULL)) != 0) {
			continue;
		}

		// Grab new TCP connection (blocking until SDP is over and new TCP connection is requested)
		if ((err = netconn_accept(conn, &newconn)) == ERR_OK) {
			//PRINTF("ACCEPT OK\r\n");
			;
		}
		else {
			PRINTF("[V2G] ACCEPT ERROR!\r\n");

			/* HANDLE ACCEPT ERROR! */
			/*
			***************************
			*/
		}

		// Enable TLS
		// Initialize TLS stack and Handshake
		if (charge_session.v2g.tls) {

			if ((ret = tls_conn_init(newconn)) != ERR_OK) {
				PRINTF("[V2G] TLS init has failed! Ret = %d\r\n", ret);
			}
			if ((ret = tls_handshake()) != ERR_OK) {
				PRINTF("[V2G] TLS handshake has failed! Ret = %d\r\n", ret);
			}
			else {
				/*PRINTF("###############################\r\n");
				PRINTF("### TLS socket creation OK! ###\r\n");
				PRINTF("###############################\r\n");*/
			}

		}
		else {
			ret = ERR_OK;
		}

		// Process the new connection.
		if (ret == ERR_OK) {

			// Clear previous states
			memset(&charge_session.v2g.stateFlow, 0, sizeof(charge_session.v2g.stateFlow));
			v2g_state = 0;

			while ((err = v2g_recv(newconn, buffer, &len)) == ERR_OK) {	

				//////////////////////////////////////////
				// STATE FLOW FOR MESSAGE PROTOCOL
				buffer_pos = 0;
				stream.capacity = 0; // rx
				stream.size = len;

				// Supported App Protocol (handshake message)
				if (v2g_state == 0) {
					supported_app_protocol_req(&stream);
					v2g_state++;
				}
				else {

					// Decode input data
					memset(&exiIn, 0, sizeof(exiIn));
					if ((err = deserializeStream2EXI(&stream, &exiIn)) != ERR_OK) {
						PRINTF("[V2G] Deserializing EXI err: %d\r\n", err);
					}

					// Init V2G output structure
					init_v2gExiDoc_response(&exiOut);

					if (exiIn.V2G_Message.Body.SessionSetupReq_isUsed) {
						handle_session_setup(&exiIn, &exiOut);
						memset(&charge_session.v2g.stateFlow, 0, sizeof(charge_session.v2g.stateFlow)); // clear previous states
						charge_session.v2g.stateFlow.sessionSetup_ok = 1;
					}
					else if (exiIn.V2G_Message.Body.ServiceDiscoveryReq_isUsed) {
						handle_service_discovery(&exiIn, &exiOut);
						memset(&charge_session.v2g.stateFlow, 0, sizeof(charge_session.v2g.stateFlow));
						charge_session.v2g.stateFlow.serviceDiscovery_ok = 1;
					}
					else if (exiIn.V2G_Message.Body.ServiceDetailReq_isUsed) {
						handle_service_detail(&exiIn, &exiOut);
						memset(&charge_session.v2g.stateFlow, 0, sizeof(charge_session.v2g.stateFlow));
						charge_session.v2g.stateFlow.serviceDetail_ok = 1;
					}
					else if (exiIn.V2G_Message.Body.PaymentServiceSelectionReq_isUsed) {
						handle_payment_service_selection(&exiIn, &exiOut);
						memset(&charge_session.v2g.stateFlow, 0, sizeof(charge_session.v2g.stateFlow));
						charge_session.v2g.stateFlow.paymentServiceSelection_ok = 1;
					}
					else if (exiIn.V2G_Message.Body.PaymentDetailsReq_isUsed) {
						handle_payment_details(&exiIn, &exiOut);
						memset(&charge_session.v2g.stateFlow, 0, sizeof(charge_session.v2g.stateFlow));
						charge_session.v2g.stateFlow.paymentDetails_ok = 1;
					}
					else if (exiIn.V2G_Message.Body.CertificateInstallationReq_isUsed) {
						handle_certificate_installation(&exiIn, &exiOut);
						memset(&charge_session.v2g.stateFlow, 0, sizeof(charge_session.v2g.stateFlow));
						charge_session.v2g.stateFlow.certificateInstallation_ok = 1;
					}
					else if (exiIn.V2G_Message.Body.AuthorizationReq_isUsed) {
						handle_authorization(&exiIn, &exiOut);
						memset(&charge_session.v2g.stateFlow, 0, sizeof(charge_session.v2g.stateFlow));
						charge_session.v2g.stateFlow.authorization_ok = 1;
					}
					else if (exiIn.V2G_Message.Body.ChargeParameterDiscoveryReq_isUsed) {
						handle_charge_param_discovery(&exiIn, &exiOut);
						memset(&charge_session.v2g.stateFlow, 0, sizeof(charge_session.v2g.stateFlow));
						charge_session.v2g.stateFlow.chargeParamDiscovery_ok = 1;
					}
					else if (exiIn.V2G_Message.Body.CableCheckReq_isUsed) {
						handle_cable_check(&exiIn, &exiOut);
						memset(&charge_session.v2g.stateFlow, 0, sizeof(charge_session.v2g.stateFlow));
						charge_session.v2g.stateFlow.cableCheck_ok = 1;
					}
					else if (exiIn.V2G_Message.Body.PreChargeReq_isUsed) {
						handle_pre_charge(&exiIn, &exiOut);
						memset(&charge_session.v2g.stateFlow, 0, sizeof(charge_session.v2g.stateFlow));
						charge_session.v2g.stateFlow.preCharge_ok = 1;
					}
					else if (exiIn.V2G_Message.Body.PowerDeliveryReq_isUsed) {
						handle_power_delivery(&exiIn, &exiOut);
						memset(&charge_session.v2g.stateFlow, 0, sizeof(charge_session.v2g.stateFlow));
						charge_session.v2g.stateFlow.powerDelivery_ok = 1;
					}
					else if (exiIn.V2G_Message.Body.CurrentDemandReq_isUsed) {
						handle_current_demand(&exiIn, &exiOut);
						memset(&charge_session.v2g.stateFlow, 0, sizeof(charge_session.v2g.stateFlow));
						charge_session.v2g.stateFlow.currentDemand_ok = 1;
					}
					else if (exiIn.V2G_Message.Body.WeldingDetectionReq_isUsed) {
						handle_welding_detection(&exiIn, &exiOut);
						memset(&charge_session.v2g.stateFlow, 0, sizeof(charge_session.v2g.stateFlow));
						charge_session.v2g.stateFlow.weldingDetection_ok = 1;
					}
					else if (exiIn.V2G_Message.Body.ChargingStatusReq_isUsed) {
						handle_charging_status(&exiIn, &exiOut);
						memset(&charge_session.v2g.stateFlow, 0, sizeof(charge_session.v2g.stateFlow));
						charge_session.v2g.stateFlow.chargingStatus_ok = 1;
					}
					else if (exiIn.V2G_Message.Body.SessionStopReq_isUsed) {
						PRINTF("[V2G] ## Session Stop ##\r\n");
						handle_session_stop(&exiIn, &exiOut);
						memset(&charge_session.v2g.stateFlow, 0, sizeof(charge_session.v2g.stateFlow));
						charge_session.v2g.stateFlow.sessionStop_ok = 1;
					}
					else {
						PRINTF("[V2G] Invalid V2G message?\r\n");
						continue;
					}

					// Encode output data
					stream.size = TCP_BUFF_SIZE;
					stream.capacity = 8; // tx
					buffer_pos = 0;
					memset(buffer, 0, sizeof(buffer));
					if ((err = serializeEXI2Stream(&exiOut, &stream)) != 0) {
						PRINTF("[V2G] StreamPos: %d\r\n", buffer_pos);
						PRINTF("[V2G] EXI Encoding err: %d\r\n", err);
					}

				}

				// Send data to the connection
				if ((err = v2g_send(newconn, buffer, buffer_pos)) != ERR_OK) {
					PRINTF("[V2G] TCP WRITE ERROR: %d\r\n", err);
				}

			}

			// Close connection and discard connection identifier. 
			netconn_close(newconn);
			netconn_delete(newconn);

			if (charge_session.v2g.tls) {
				tls_close_conn();
			}
			charge_session.v2g.session_active = false;
		}
	}
	
	vTaskDelete(NULL);

}

// Handshake Supported App Protocol
void supported_app_protocol_req(bitstream_t *stream) {

	uint16_t i, k;
	struct appHandEXIDocument handshake_req;
	struct appHandEXIDocument handshake_res;
	uint8_t err = 0;
	uint8_t max_priority = 21;

	// Decode buf as supportedAppProtocolReq
	*stream->pos = V2GTP_HEADER_LENGTH;
	decode_appHandExiDocument(stream, &handshake_req);

	/* DEBUG HANDSHAKE_REQ */
	PRINTF("[V2G] *** HANDSHAKE DEBUG ***\r\n");
	PRINTF("\t\tVersion=%d.%d\n", handshake_req.supportedAppProtocolReq.AppProtocol.array[0].VersionNumberMajor, handshake_req.supportedAppProtocolReq.AppProtocol.array[0].VersionNumberMinor);
	PRINTF("\t\tSchemaID=%d\n", handshake_req.supportedAppProtocolReq.AppProtocol.array[0].SchemaID);
	PRINTF("\t\tPriority=%d\n", handshake_req.supportedAppProtocolReq.AppProtocol.array[0].Priority);
	PRINTF("\t\tArrayLen=%d\n", handshake_req.supportedAppProtocolReq.AppProtocol.arrayLen);
	/**********************/

	// Init response
	init_appHandEXIDocument(&handshake_res);
	handshake_res.supportedAppProtocolRes_isUsed = 1u;
	handshake_res.supportedAppProtocolRes.SchemaID_isUsed = 1u;
	handshake_res.supportedAppProtocolRes.ResponseCode = appHandresponseCodeType_Failed_NoNegotiation; // Default response

	// Go through all EVSE protocols, should the one with highest priority and implemented by this EVSE
	// Priority 1: Highest ; Priority 20: Lowest
	PRINTF("[V2G] SupportedAppProtocol Len: %d\r\n", handshake_req.supportedAppProtocolReq.AppProtocol.arrayLen);
	for (i = 0; i < handshake_req.supportedAppProtocolReq.AppProtocol.arrayLen; i++) {

		// Go through this EVSE's protocols
		for (k = 0; k < sizeof(charge_session.v2g.secc_app_protocols) / sizeof(charge_session.v2g.secc_app_protocols[0]); k++) {
			// Check if this EV protocol exists in the EVSE
			if (memcmp(	handshake_req.supportedAppProtocolReq.AppProtocol.array[i].ProtocolNamespace.characters, 
						charge_session.v2g.secc_app_protocols[k].protocol_namespace, 
						handshake_req.supportedAppProtocolReq.AppProtocol.array[i].ProtocolNamespace.charactersLen) == 0) {
				PRINTF("[V2G] MATCHED PROTOCOL: %s\r\n", charge_session.v2g.secc_app_protocols[k].protocol_namespace);

				// Fill response with highest priority protocol
				if (handshake_req.supportedAppProtocolReq.AppProtocol.array[i].Priority < max_priority) { // lower value is higher priority
					max_priority = handshake_req.supportedAppProtocolReq.AppProtocol.array[i].Priority;
					handshake_res.supportedAppProtocolRes.SchemaID = handshake_req.supportedAppProtocolReq.AppProtocol.array[i].SchemaID;

					// Check major/minor versions
					if (handshake_req.supportedAppProtocolReq.AppProtocol.array[i].VersionNumberMajor == charge_session.v2g.secc_app_protocols[k].major_version) {
						if (handshake_req.supportedAppProtocolReq.AppProtocol.array[i].VersionNumberMinor == charge_session.v2g.secc_app_protocols[k].minor_version) {
							handshake_res.supportedAppProtocolRes.ResponseCode = appHandresponseCodeType_OK_SuccessfulNegotiation;
						}
						else {
							handshake_res.supportedAppProtocolRes.ResponseCode = appHandresponseCodeType_OK_SuccessfulNegotiationWithMinorDeviation;
						}
					}
					else {
						handshake_res.supportedAppProtocolRes.ResponseCode = appHandresponseCodeType_Failed_NoNegotiation;
					}
				}
			}
		}
	}
	
	// Encode data to EXI format
	*stream->pos = V2GTP_HEADER_LENGTH;
	stream->capacity = 8; // as it should be for send
	if ((err = encode_appHandExiDocument(stream, &handshake_res)) != 0) {
		PRINTF("[V2G] Encode appHandExiDoc err: %d\r\n", err);
	}

	// Write V2G header
	if ((err = write_v2gtpHeader(stream->data, sizeof(struct appHandAnonType_supportedAppProtocolRes), V2GTP_EXI_TYPE)) != 0) {
		PRINTF("[V2G] Write V2GTPHeader err: %d\r\n", err);
	}

	stream->size = V2GTP_HEADER_LENGTH + sizeof(struct appHandAnonType_supportedAppProtocolRes);
	return;
}

void handle_session_setup(struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut) {

	uint64_t sessionID, zeroSessionId;
	uint8_t i, saScheduleLen;
	bool saScheduleOk = false;
	bool prevPaymentSelected_isAvailable;
    v2gpaymentOptionType prevPaymentSelected;
	bool prevChargeService_isAvailable;
    struct v2gChargeServiceType prevChargeService;
	bool prevSaSchedule_isAvailable;
	struct v2gSAScheduleTupleType prevSaSchedule;

	PRINTF("[V2G] SESSION_SETUP#evccID: %x %x %x %x %x %x\r\n", 	exiIn->V2G_Message.Body.SessionSetupReq.EVCCID.bytes[0], 
																	exiIn->V2G_Message.Body.SessionSetupReq.EVCCID.bytes[1], 
																	exiIn->V2G_Message.Body.SessionSetupReq.EVCCID.bytes[2], 
																	exiIn->V2G_Message.Body.SessionSetupReq.EVCCID.bytes[3], 
																	exiIn->V2G_Message.Body.SessionSetupReq.EVCCID.bytes[4], 
																	exiIn->V2G_Message.Body.SessionSetupReq.EVCCID.bytes[5]);

	// Prepare Response
	init_v2gSessionSetupResType(&exiOut->V2G_Message.Body.SessionSetupRes);
	exiOut->V2G_Message.Body.SessionSetupRes_isUsed = 1u;

	// SessionID handling
	// EVCC trying to resume previous session?
	memset(&zeroSessionId, 0, sizeof(zeroSessionId));
	if (memcmp(exiIn->V2G_Message.Header.SessionID.bytes, &zeroSessionId, exiIn->V2G_Message.Header.SessionID.bytesLen) != 0) {
		PRINTF("[V2G] SessionSetup EV SessionID is not zero\r\n");
		/****************************************************************
		 * Rejoin previous SessionID
		 * **************************************************************/
		if (memcmp(exiIn->V2G_Message.Header.SessionID.bytes, charge_session.v2g.SessionID.bytes, sizeof(charge_session.v2g.SessionID.bytes)) == 0) {
			PRINTF("[V2G] SessionSetup loading previous SessionID\r\n");
			// Use same parameters as previous Session
			prevPaymentSelected_isAvailable = charge_session.v2g.prev_payment_selected_isAvailable;
			memcpy(	&prevPaymentSelected, 
					&charge_session.v2g.payment_selected, 
					sizeof(charge_session.v2g.payment_selected));

			prevChargeService_isAvailable = charge_session.v2g.prev_charge_service_isAvailable;
			memcpy(	&prevChargeService, 
					&charge_session.v2g.charge_service, 
					sizeof(charge_session.v2g.charge_service));

			prevSaSchedule_isAvailable = charge_session.v2g.prev_ev_sa_schedule_isAvailable;
			memcpy(&prevSaSchedule, &charge_session.v2g.ev_sa_schedule, sizeof(prevSaSchedule));

			// Re-load V2G session with default values
			load_v2g_session();

			// Override with the previous sessions values, if available. Else, use default values
			memcpy(&charge_session.v2g.SessionID, &exiIn->V2G_Message.Header.SessionID, sizeof(charge_session.v2g.SessionID));
			if (prevPaymentSelected_isAvailable) {
				charge_session.v2g.payment_options.PaymentOption.arrayLen = 1;
				charge_session.v2g.payment_options.PaymentOption.array[0] = prevPaymentSelected;
			}
			if (prevChargeService_isAvailable) {
				charge_session.v2g.charge_service = prevChargeService; // This should always be AC_DC_Charging
			}
			if (prevSaSchedule_isAvailable) {
				memcpy(&charge_session.v2g.ev_sa_schedule, &prevSaSchedule, sizeof(prevSaSchedule)); // Remove elapsed time
			
				// Check if that the previously selected ScheduleTuple is present
				for (i = 0; i < charge_session.charger.evse_sa_schedules.SAScheduleTuple.arrayLen; i++) {
					if (charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[i].SAScheduleTupleID == 
						charge_session.v2g.ev_sa_schedule.SAScheduleTupleID) {
						saScheduleOk = true;
						PRINTF("[V2G] REJOIN: SA Schedule ok!\r\n");
						break;
					}
				}
				if (!saScheduleOk) {
					// The previously selected Schedule is not there - add it in the last position if array already full
					saScheduleLen = charge_session.charger.evse_sa_schedules.SAScheduleTuple.arrayLen;
					if (saScheduleLen == v2gSAScheduleListType_SAScheduleTuple_ARRAY_SIZE) {
						charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[saScheduleLen-1] = charge_session.v2g.ev_sa_schedule;
						PRINTF("[V2G] REJOIN: Replaced last SA Shedule!\r\n");
					}
					else {
						charge_session.charger.evse_sa_schedules.SAScheduleTuple.arrayLen++;
						charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[saScheduleLen+1] = charge_session.v2g.ev_sa_schedule;
						PRINTF("[V2G] REJOIN: added new SA Schedule!\r\n");
					}
				}
			}

			exiOut->V2G_Message.Body.SessionSetupRes.ResponseCode = v2gresponseCodeType_OK_OldSessionJoined;
		}
		else {
			/****************************************************************
			 * Generate new SessionID, different from the provided by the EV
			 * **************************************************************/
			PRINTF("[V2G] SessionSetup generating new SessionID\r\n");
			// Generate new SessionID which is different from the EV provided SessionID
			memcpy(&sessionID, charge_session.v2g.SessionID.bytes, sizeof(sessionID));
			do {
				sessionID = htonll(sessionID);
				if (sessionID++ == 0){
					 sessionID++;
				}
				sessionID = ntohll(sessionID);
			} while (memcmp(&sessionID, exiIn->V2G_Message.Header.SessionID.bytes, exiIn->V2G_Message.Header.SessionID.bytesLen) == 0);
			
			// Re-load V2G session with default values, update SessionID
			load_v2g_session();
			memcpy(charge_session.v2g.SessionID.bytes, &sessionID, sizeof(sessionID));
			charge_session.v2g.SessionID.bytesLen = sizeof(sessionID);

			exiOut->V2G_Message.Body.SessionSetupRes.ResponseCode = v2gresponseCodeType_OK_NewSessionEstablished;
		}
	}
	else {
		/****************************************************************
	 	* Generate new SessionID
		* **************************************************************/
		PRINTF("[V2G] SessionSetup EV SessionID is zero\r\n");

		// Generate new SessionID
		memcpy(&sessionID, charge_session.v2g.SessionID.bytes, charge_session.v2g.SessionID.bytesLen);
		do {
			sessionID = htonll(sessionID);
			sessionID++;
			sessionID = ntohll(sessionID);
		} while (sessionID == 0);

		// Re-load V2G session with default values, update SessionID
		load_v2g_session();
		memcpy(charge_session.v2g.SessionID.bytes, &sessionID, sizeof(sessionID));
		charge_session.v2g.SessionID.bytesLen = sizeof(sessionID);

		memcpy(	&charge_session.v2g.charge_service, 
				&charge_session.charger.evse_charge_service, 
				sizeof(charge_session.charger.evse_charge_service));

		exiOut->V2G_Message.Body.SessionSetupRes.ResponseCode = v2gresponseCodeType_OK_NewSessionEstablished;
	}

	memcpy(exiOut->V2G_Message.Header.SessionID.bytes, charge_session.v2g.SessionID.bytes, charge_session.v2g.SessionID.bytesLen);
	exiOut->V2G_Message.Header.SessionID.bytesLen = charge_session.v2g.SessionID.bytesLen;
	memcpy(&exiOut->V2G_Message.Body.SessionSetupRes.EVSEID, &charge_session.charger.EVSEID, sizeof(charge_session.charger.EVSEID));

	PRINTF("[V2G] SESSION_ID: %x %x\r\n", exiOut->V2G_Message.Header.SessionID.bytes[6], exiOut->V2G_Message.Header.SessionID.bytes[7]);
	PRINTF("[V2G] SESSION_ID_LEN: %d\r\n", exiOut->V2G_Message.Header.SessionID.bytesLen);

	exiOut->V2G_Message.Body.SessionSetupRes.EVSETimeStamp_isUsed = 0; // ONLY FOR RISE-V2G !!
	exiOut->V2G_Message.Body.SessionSetupRes.EVSETimeStamp = 0; // ONLY FOR RISE-V2G !!
	return;
}

void handle_service_discovery(struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut) {
	uint8_t i;
	bool serviceScope_ok, serviceCategory_ok;
	
	// Prepare response
	init_v2gServiceDiscoveryResType(&exiOut->V2G_Message.Body.ServiceDiscoveryRes);
	exiOut->V2G_Message.Body.ServiceDiscoveryRes_isUsed = 1u;

	// Process request
	exiOut->V2G_Message.Body.ServiceDiscoveryRes.ResponseCode = v2gresponseCodeType_OK;
	if (!charge_session.v2g.stateFlow.sessionSetup_ok) {
		exiOut->V2G_Message.Body.ServiceDiscoveryRes.ResponseCode = v2gresponseCodeType_FAILED_SequenceError;
	}
	if (!check_ev_session_id(exiIn->V2G_Message.Header)) {
		exiOut->V2G_Message.Body.ServiceDiscoveryRes.ResponseCode = v2gresponseCodeType_FAILED_UnknownSession;
	}

	// PnC and VAS are only possible with TLS
	if (charge_session.v2g.tls) {
		exiOut->V2G_Message.Body.ServiceDiscoveryRes.ServiceList_isUsed = 1u;

		// Payment options (Contract, EIM)
		memcpy(	&charge_session.v2g.payment_options, 
				&charge_session.charger.evse_payment_options,
				sizeof(charge_session.charger.evse_payment_options));

		// Service list provided by the SECC - filtered from ServiceScope and ServiceCategory from EV
		serviceCategory_ok = 0;
		serviceScope_ok = 0;
		charge_session.v2g.service_list.Service.arrayLen = 0;
		// Check if the request category & scope exists in the ServiceList SECC
		for (i = 0; i < charge_session.charger.evse_service_list.Service.arrayLen; i++) {

			// No filters - return all available SECC services
			if (!exiIn->V2G_Message.Body.ServiceDiscoveryReq.ServiceCategory_isUsed &&
				!exiIn->V2G_Message.Body.ServiceDiscoveryReq.ServiceScope_isUsed) {
				memcpy(	&charge_session.v2g.service_list.Service, 
						&charge_session.charger.evse_service_list.Service, 
						sizeof(charge_session.charger.evse_service_list.Service));
				break;
			}
			
			// Service Category Filter
			if (exiIn->V2G_Message.Body.ServiceDiscoveryReq.ServiceCategory_isUsed) {
				serviceCategory_ok = 0;
				if (charge_session.charger.evse_service_list.Service.array[i].ServiceCategory == 
					exiIn->V2G_Message.Body.ServiceDiscoveryReq.ServiceCategory) {
					serviceCategory_ok = 1;
				}
			}
			else {
				serviceCategory_ok = 1; // Do not filter by category
			}

			// Service Scope Filter
			if (exiIn->V2G_Message.Body.ServiceDiscoveryReq.ServiceScope_isUsed) {
				serviceScope_ok = 0;
				if (memcmp(	&charge_session.charger.evse_service_list.Service.array[i].ServiceScope, 
							&exiIn->V2G_Message.Body.ServiceDiscoveryReq.ServiceScope,
							sizeof(charge_session.charger.evse_service_list.Service.array[i].ServiceScope)) == 0) {
					serviceScope_ok = 1;
				}
			}
			else {
				serviceScope_ok = 1; // Do not filter by scope
			}
			
			// Store this service in the V2G session (will be provided by the SECC to the EV)
			if (serviceCategory_ok & serviceScope_ok) {
				memcpy(	&charge_session.v2g.service_list.Service.array[charge_session.v2g.service_list.Service.arrayLen], 
						&charge_session.charger.evse_service_list.Service.array[i], 
						sizeof(charge_session.charger.evse_service_list.Service.array[i]));
				charge_session.v2g.service_list.Service.arrayLen++;
			}
		}
	}
	else {
		// V2G2-632
		charge_session.v2g.payment_options.PaymentOption.array[0] = v2gpaymentOptionType_ExternalPayment;
		charge_session.v2g.payment_options.PaymentOption.arrayLen = 1;
		exiOut->V2G_Message.Body.ServiceDiscoveryRes.ServiceList_isUsed = 0u;
		exiOut->V2G_Message.Body.ServiceDiscoveryRes.ServiceList.Service.arrayLen = 0;
		memset(&charge_session.v2g.service_list, 0, sizeof(charge_session.v2g.service_list)); // arrayLen = 0
	}

	charge_session.v2g.prev_charge_service_isAvailable = 1;
	memcpy(	&charge_session.v2g.charge_service, 
			&charge_session.charger.evse_charge_service, 
			sizeof(charge_session.charger.evse_charge_service));

	// Copy to output structure
	memcpy(	&exiOut->V2G_Message.Body.ServiceDiscoveryRes.ChargeService, 
			&charge_session.v2g.charge_service, 
			sizeof(charge_session.v2g.charge_service));	

	memcpy(	&exiOut->V2G_Message.Body.ServiceDiscoveryRes.PaymentOptionList, 
			&charge_session.v2g.payment_options,
			sizeof(charge_session.v2g.payment_options));

	memcpy(	&exiOut->V2G_Message.Body.ServiceDiscoveryRes.ServiceList, 
			&charge_session.v2g.service_list, 
			sizeof(charge_session.v2g.service_list));
			
	return;
}

void handle_service_detail(struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut) {

	uint8_t i;
	bool serviceIdOk = false;
	PRINTF("[V2G] ServiceListLen: %d\r\n", charge_session.v2g.service_list.Service.arrayLen);

	// Prepare response
	init_v2gServiceDetailResType(&exiOut->V2G_Message.Body.ServiceDetailRes);
	exiOut->V2G_Message.Body.ServiceDetailRes_isUsed = 1u;

	// Process request
	exiOut->V2G_Message.Body.ServiceDetailRes.ResponseCode = v2gresponseCodeType_OK;
	if (!charge_session.v2g.stateFlow.serviceDiscovery_ok) {
		exiOut->V2G_Message.Body.ServiceDetailRes.ResponseCode = v2gresponseCodeType_FAILED_SequenceError;
	}
	if (!check_ev_session_id(exiIn->V2G_Message.Header)) {
		exiOut->V2G_Message.Body.ServiceDetailRes.ResponseCode = v2gresponseCodeType_FAILED_UnknownSession;
	}

	// Handle ServiceID request
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceID = exiIn->V2G_Message.Body.ServiceDetailReq.ServiceID;
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList_isUsed = 0u;
	// Does the ServiceID exist in our V2G session?
	for (i = 0; i < charge_session.v2g.service_list.Service.arrayLen; i++) {
		
		if (charge_session.v2g.service_list.Service.array[i].ServiceID == exiIn->V2G_Message.Body.ServiceDetailReq.ServiceID) {
			serviceIdOk = true;

			// Fill ParameterSetID with this Service's data
			exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList_isUsed = 1u;
			exiOut->V2G_Message.Body.ServiceDetailRes.ServiceID = charge_session.v2g.service_list.Service.array[i].ServiceID;

			// Find which ServiceID was requested
			if (charge_session.v2g.service_list.Service.array[i].ServiceCategory == v2gserviceCategoryType_ContractCertificate) {
				exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.arrayLen = 2;
	
				exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].ParameterSetID = 1; // Table 106
				exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.arrayLen = 1;
				exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[0].Name.charactersLen = 7;
				memcpy(	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[0].Name.characters,
						"Service",
						exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[0].Name.charactersLen);
				exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[0].stringValue_isUsed = 1u;
				exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[0].stringValue.charactersLen = 12;
				memcpy(	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[0].stringValue.characters,
						"Installation",
						exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[0].stringValue.charactersLen);

				// ******** Update requires an Online connection to request certificate to SA ********************
				exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].ParameterSetID = 2; // Table 106
				exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].Parameter.arrayLen = 1;
				exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].Parameter.array[0].Name.charactersLen = 7;
				memcpy(	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].Parameter.array[0].Name.characters,
						"Service",
						exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].Parameter.array[0].Name.charactersLen);
				exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].Parameter.array[0].stringValue_isUsed = 1u;
				exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].Parameter.array[0].stringValue.charactersLen = 6;
				memcpy(	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].Parameter.array[0].stringValue.characters,
						"Update",
						exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].Parameter.array[0].stringValue.charactersLen);
				
			}
			else if (charge_session.v2g.service_list.Service.array[i].ServiceCategory == v2gserviceCategoryType_Internet) {
				memcpy(	&exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList,
						&charge_session.charger.evse_service_parameters,
						sizeof(charge_session.charger.evse_service_parameters));
			}
			else {
				serviceIdOk = false;
				exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList_isUsed = 0u;
			}

			break;
		}
	}

	if (!serviceIdOk) {
		exiOut->V2G_Message.Body.ServiceDetailRes.ResponseCode = v2gresponseCodeType_FAILED_ServiceIDInvalid;
	}

	return;
}

void handle_payment_service_selection(struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut) {

	uint8_t i, k;
	bool chargeServiceOk = false;
	bool serviceOk = false;
	bool paymentOk = false;
	bool serviceEn = false;

	// Prepare response
	init_v2gPaymentServiceSelectionResType(&exiOut->V2G_Message.Body.PaymentServiceSelectionRes);
	exiOut->V2G_Message.Body.PaymentServiceSelectionRes_isUsed = 1u;

	// Process request
	exiOut->V2G_Message.Body.PaymentServiceSelectionRes.ResponseCode = v2gresponseCodeType_OK;
	if (!charge_session.v2g.stateFlow.serviceDiscovery_ok && !charge_session.v2g.stateFlow.serviceDetail_ok) {
		exiOut->V2G_Message.Body.PaymentServiceSelectionRes.ResponseCode = v2gresponseCodeType_FAILED_SequenceError;
	}
	if (!check_ev_session_id(exiIn->V2G_Message.Header)) {
		exiOut->V2G_Message.Body.PaymentServiceSelectionRes.ResponseCode = v2gresponseCodeType_FAILED_UnknownSession;
	}

	// Check if selected Services are available once again
	PRINTF("[V2G] V2G SERVICES len: %d\r\n", charge_session.v2g.service_list.Service.arrayLen);
	PRINTF("[V2G] ServicesReq len: %d\r\n", exiIn->V2G_Message.Body.PaymentServiceSelectionReq.SelectedServiceList.SelectedService.arrayLen);
	for (i = 0; i < exiIn->V2G_Message.Body.PaymentServiceSelectionReq.SelectedServiceList.SelectedService.arrayLen; i++) {

		// Is it the ChargeService?
		if (exiIn->V2G_Message.Body.PaymentServiceSelectionReq.SelectedServiceList.SelectedService.array[i].ServiceID ==
			charge_session.v2g.charge_service.ServiceID) {
			chargeServiceOk = true;
		}
		else {
			serviceEn = true;
			// Go through all Services available in this V2G session
			for (k = 0; k < charge_session.v2g.service_list.Service.arrayLen; k++) {
				PRINTF("[V2G] > ServiceID %d: %d\r\n", k, charge_session.v2g.service_list.Service.array[k].ServiceID);
				if (exiIn->V2G_Message.Body.PaymentServiceSelectionReq.SelectedServiceList.SelectedService.array[i].ServiceID == 
					charge_session.v2g.service_list.Service.array[k].ServiceID) {
					serviceOk = true;
					break;
				}
			}
		}
	}

	// Service was not found
	if (!serviceOk & serviceEn) {
		exiOut->V2G_Message.Body.PaymentServiceSelectionRes.ResponseCode = v2gresponseCodeType_FAILED_ServiceSelectionInvalid;
	}
	// Charging Service was not present
	if (!chargeServiceOk) {
		exiOut->V2G_Message.Body.PaymentServiceSelectionRes.ResponseCode = v2gresponseCodeType_FAILED_NoChargeServiceSelected;
	}

	// Check if Payment Selection is available in this V2G session
	for (i = 0; i < charge_session.v2g.payment_options.PaymentOption.arrayLen; i++) {
		if (exiIn->V2G_Message.Body.PaymentServiceSelectionReq.SelectedPaymentOption == 
			charge_session.v2g.payment_options.PaymentOption.array[i]) {
			paymentOk = true;
			break;
		}
	}
	if (!paymentOk) {
		exiOut->V2G_Message.Body.PaymentServiceSelectionRes.ResponseCode = v2gresponseCodeType_FAILED_PaymentSelectionInvalid;
	}

	charge_session.v2g.prev_payment_selected_isAvailable = 1;
	memcpy(&charge_session.v2g.payment_selected, &exiIn->V2G_Message.Body.PaymentServiceSelectionReq.SelectedPaymentOption, 
			sizeof(charge_session.v2g.payment_selected));

	return;
}

// Only when 'CONTRACT' was chosen instead of 'EXTERNAL PAYMENT'
void handle_payment_details(struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut) {
	PRINTF("[V2G] PAYMENT DETAILS\r\n");
	// Prepare response
	init_v2gPaymentDetailsResType(&exiOut->V2G_Message.Body.PaymentDetailsRes);
	exiOut->V2G_Message.Body.PaymentDetailsRes_isUsed = 1u;

	// Process request
	exiOut->V2G_Message.Body.PaymentDetailsRes.ResponseCode = v2gresponseCodeType_OK;
	if (exiIn->V2G_Message.Body.PaymentDetailsReq_isUsed == 0) {
		exiOut->V2G_Message.Body.PaymentDetailsRes.ResponseCode = v2gresponseCodeType_FAILED_SequenceError;
	}
	if (!check_ev_session_id(exiIn->V2G_Message.Header)) {
		exiOut->V2G_Message.Body.PaymentDetailsRes.ResponseCode = v2gresponseCodeType_FAILED_UnknownSession;
	}

	memcpy(exiOut->V2G_Message.Body.PaymentDetailsRes.GenChallenge.bytes, charge_session.v2g.challenge, 
			sizeof(exiOut->V2G_Message.Body.PaymentDetailsRes.GenChallenge.bytes));
	exiOut->V2G_Message.Body.PaymentDetailsRes.GenChallenge.bytesLen = sizeof(charge_session.v2g.challenge);
	exiOut->V2G_Message.Body.PaymentDetailsRes.EVSETimeStamp = charge_session.v2g.timestamp;

	return;
}

void handle_certificate_installation(struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut) {

	uint16_t i;
	int ret;
	const char pers[] = "ecdh";
	size_t dhPubkeyLen, eMAIDLen, secretLen, certLen;
	unsigned char dhPukeyBuf[128];
	unsigned char 	iv[16], 
					contractPkeyBytes[32], 
					privKeyBuf[48], 
					encryptBuf[48],
					certBuffer[256],
					secretBuffer[512],
					eMAID[64],
					sessionKey[32];// 128 bits V2G-818
	const uint8_t keyInfo[3] = {0x01, 0x55, 0x56}; // Salt - V2G-818 
	mbedtls_md_context_t md_ctx;
	mbedtls_ecdh_context ecdh, ctx_ev;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;
	mbedtls_pk_context contractPkey;
	mbedtls_ecp_keypair *keypair;
	mbedtls_x509_crt oemProvCrt, contractCrt;
	mbedtls_aes_context aes_ctx;

	PRINTF("[V2G] ### Certificate Installation\r\n");

	// Prepare response
	init_v2gCertificateInstallationResType(&exiOut->V2G_Message.Body.CertificateInstallationRes);
	exiOut->V2G_Message.Body.CertificateInstallationRes_isUsed = 1u;

	// Process request
	exiOut->V2G_Message.Body.CertificateInstallationRes.ResponseCode = v2gresponseCodeType_OK;
	if (!charge_session.v2g.stateFlow.paymentServiceSelection_ok) {
		exiOut->V2G_Message.Body.CertificateInstallationRes.ResponseCode = v2gresponseCodeType_FAILED_SequenceError;
	}
	if (!check_ev_session_id(exiIn->V2G_Message.Header)) {
		exiOut->V2G_Message.Body.CertificateInstallationRes.ResponseCode = v2gresponseCodeType_FAILED_UnknownSession;
	}

	// Structure inits
	mbedtls_ecdh_init(&ecdh);
	mbedtls_ecdh_init(&ctx_ev);
	mbedtls_x509_crt_init(&oemProvCrt);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_ecdh_init(&ecdh);
	mbedtls_md_init(&md_ctx); 
	mbedtls_pk_init(&contractPkey);
	mbedtls_aes_init(&aes_ctx);
	mbedtls_x509_crt_init(&contractCrt);

	/*****************************************
	 * CLIENT CERTIFICATE HANDLING (EV)
	 * ***************************************/
	// Step 1: load client certificate (OEMProvisioning - DER encoded)
	if ((ret = mbedtls_x509_crt_parse_der(	&oemProvCrt, 
											exiIn->V2G_Message.Body.CertificateInstallationReq.OEMProvisioningCert.bytes, 
											exiIn->V2G_Message.Body.CertificateInstallationReq.OEMProvisioningCert.bytesLen)) != 0) {
		PRINTF("CERT LOAD ERR : %d\r\n", ret);
	}
	// Get public key of OEMProvisioning
	if ((ret = mbedtls_pk_write_pubkey_pem(&oemProvCrt.pk, certBuffer, sizeof(certBuffer))) != 0) {
		PRINTF("PUBKEY WRITE ERR : %d\r\n", ret);
	}
	certLen = strlen((char *)certBuffer);

	/*****************************************
	 * SERVER KEYPAIR CREATION(EVSE)
	 * ***************************************/
	// Step 2: create new ECDH context for server
	if ((ret = mbedtls_ctr_drbg_seed(	&ctr_drbg, mbedtls_entropy_func, 
										&entropy, (const unsigned char *) pers, strlen(pers))) != 0) {
		PRINTF("EC ERR 1 : %d\r\n", ret);
	}
	if ((ret = mbedtls_ecp_group_load(&ecdh.grp, MBEDTLS_ECP_DP_SECP256R1)) != 0) {
		PRINTF("EC ERR 2 : %d\r\n", ret);
	}
	if ((ret = mbedtls_ecdh_gen_public(	&ecdh.grp, &ecdh.d, &ecdh.Q,
                                   		mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
		PRINTF("EC ERR 3 : %d\r\n", ret);
	}
	if ((ret = mbedtls_mpi_lset(&ecdh.Qp.Z, 1)) != 0) {
		PRINTF("EC ERR 5 : %d\r\n", ret);
	}
	
	// Step 3: confirm that the EV public key exists in our 'server curve' (valid point)
	// Create ECP point from EV public key
	keypair = mbedtls_pk_ec(oemProvCrt.pk); /* quick access to public key */
	ecdh.Qp = keypair->Q;
	if ((ret = mbedtls_ecp_check_pubkey(&ecdh.grp, &ecdh.Qp)) != 0) {
		PRINTF("ECP CHECK ERR : %d\r\n", ret);
	}

	// Step 4: compute shared secret
	if ((ret = mbedtls_ecdh_compute_shared( &ecdh.grp, &ecdh.z,
											&ecdh.Qp, &ecdh.d,
											mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
		PRINTF("EC ERR 7 : %d\r\n", ret);
	}
	if ((ret = mbedtls_ecdh_calc_secret(	&ecdh, &secretLen,
											secretBuffer, 512,
											mbedtls_ctr_drbg_random,
											&ctr_drbg)) != 0) {
		PRINTF("EC ERR 8 : %d\r\n", ret);
	}

	// Step 5: Generate shared key based on shared secret
	md_ctx.md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	/*
	* THIS SHOULD BE A DIFFERENT FUNCTION (concatKDF) !!!!!!!!!!!
	*/
	if ((ret = mbedtls_hkdf(	md_ctx.md_info, 
								NULL, 0, 
								secretBuffer, secretLen, 
								keyInfo, sizeof(keyInfo), 
								sessionKey, sizeof(sessionKey))) != 0) {
		PRINTF("HMAC KDF ERR: %d\r\n", ret);
	}

	// Step 6: encrypt EV private key with the computed secret key
	// 		6.1. Extract PrivateKey component
	// 		6.2. Add the IV in the first bytes (MSB), along with the ContractPrivKey
	// 		6.3. Encrypt buffer composed of (IV + ContractPrivKey) » final length should be 48
	if ((ret = mbedtls_pk_parse_key(&contractPkey, Contract_pkey,
									Contract_pkey_len, "123456", strlen("123456"))) != 0) {
		PRINTF("CONTRACT PKEY PARSE ERR: %d\r\n", ret);
	}
	// Get actual Private Key 
	mbedtls_ecp_keypair *privKeyRaw = mbedtls_pk_ec(contractPkey);
	if ((ret = mbedtls_mpi_write_binary(&privKeyRaw->d, contractPkeyBytes, sizeof(contractPkeyBytes))) != 0) {
		PRINTF("PRIV KEY MP WRITE ERR: %d\r\n", ret);
	}
	// Compose buffer with [IV, Key]
	memset(iv, 0xCC, sizeof(iv)); // INITIALIZE WITH RANDOM DATA
	memcpy(privKeyBuf, iv, sizeof(iv));
	memcpy(&privKeyBuf[sizeof(iv)], contractPkeyBytes, sizeof(contractPkeyBytes));
	// Encrypt buffer
	if ((ret = mbedtls_aes_setkey_enc(&aes_ctx, sessionKey, 128)) != 0) { // 128 keybits
		PRINTF("AES SETKEY ERR: %d\r\n", ret);
	}
	// Encryption must be with an input buffer of %16 bytes
	if ((ret = mbedtls_aes_crypt_cbc(	&aes_ctx, MBEDTLS_AES_ENCRYPT, 
										sizeof(privKeyBuf), iv, 
										privKeyBuf, encryptBuf)) != 0) {
		PRINTF("AES ENCRYPT ERR: %d\r\n", ret);
	}

	// Free unnecessary structures from this point on
	mbedtls_x509_crt_free(&oemProvCrt);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	mbedtls_aes_free(&aes_ctx);
	mbedtls_ecdh_free(&ctx_ev);
	mbedtls_pk_free(&contractPkey);
	mbedtls_md_free(&md_ctx);

	/*******************************
	* Check Signature from Request 
	********************************/
	PRINTF("[V2G] Checking Signature..\r\n");
	if (exiIn->V2G_Message.Header.Signature_isUsed) {
		struct v2gSignatureType *sig = &exiIn->V2G_Message.Header.Signature;

		mbedtls_ecdsa_context oemprov_ctx;
		mbedtls_ecdsa_init(&oemprov_ctx);

		// Use provided OEMProvisioning certificate 
		if ((ret = mbedtls_ecdsa_from_keypair(&oemprov_ctx, keypair)) != 0) {
			PRINTF("ECDSA from keypair error: %d\r\n", ret);
		}

		if ((ret = verify_v2g_signature(&exiIn, &oemprov_ctx)) != 0) {
			PRINTF("CERTIFICATE INSTALLATION SIGNATURE INVALID\r\n");
			exiOut->V2G_Message.Body.CertificateInstallationRes.ResponseCode = v2gresponseCodeType_FAILED_SignatureError;
		}
		mbedtls_ecdsa_free(&oemprov_ctx);
	}
	else {
		PRINTF("[V2G] V2G SIGNATURE NOT PRESENT IN REQUEST!\r\n");
		exiOut->V2G_Message.Body.CertificateInstallationRes.ResponseCode = v2gresponseCodeType_FAILED_SignatureError;
	}
	PRINTF("[V2G] Signature check performed!\r\n");
	exiOut->V2G_Message.Body.CertificateInstallationRes.ResponseCode = v2gresponseCodeType_OK;

	//mbedtls_ecp_keypair_free(keypair);

	/*************************************
	 * WRITE TO OUTPUT STRUCTURE
	 * ***********************************/
	// Uncompressed DH public key (ISO 15118-2)
	if ((ret = mbedtls_ecp_point_write_binary(	&ecdh.grp, &ecdh.Q, 
												MBEDTLS_ECP_PF_UNCOMPRESSED, &dhPubkeyLen, 
												dhPukeyBuf, sizeof(dhPukeyBuf))) != 0) {
		PRINTF("WRITE BINARY PUB KEY ERR: %d\r\n", ret);
	}
	mbedtls_ecdh_free(&ecdh);

	// SAProvisioningCertificateChain
	exiOut->V2G_Message.Body.CertificateInstallationRes.SAProvisioningCertificateChain.Id_isUsed = 0u;
	//exiOut->V2G_Message.Body.CertificateInstallationRes.SAProvisioningCertificateChain.Id.charactersLen = 3;
	//memcpy(exiOut->V2G_Message.Body.CertificateInstallationRes.SAProvisioningCertificateChain.Id.characters, "id1", 3);

	exiOut->V2G_Message.Body.CertificateInstallationRes.SAProvisioningCertificateChain.SubCertificates_isUsed = 1;
	exiOut->V2G_Message.Body.CertificateInstallationRes.SAProvisioningCertificateChain.SubCertificates.Certificate.arrayLen = 2; // 2 sub-certificates
	exiOut->V2G_Message.Body.CertificateInstallationRes.SAProvisioningCertificateChain.SubCertificates.Certificate.array[0].bytesLen = CPS_Inter_1_Cert_len;
	memcpy(	exiOut->V2G_Message.Body.CertificateInstallationRes.SAProvisioningCertificateChain.SubCertificates.Certificate.array[0].bytes,
			CPS_Inter_1_Cert,
			exiOut->V2G_Message.Body.CertificateInstallationRes.SAProvisioningCertificateChain.SubCertificates.Certificate.array[0].bytesLen);

	exiOut->V2G_Message.Body.CertificateInstallationRes.SAProvisioningCertificateChain.SubCertificates.Certificate.array[1].bytesLen = CPS_Inter_2_Cert_len;
	memcpy(	exiOut->V2G_Message.Body.CertificateInstallationRes.SAProvisioningCertificateChain.SubCertificates.Certificate.array[1].bytes,
			CPS_Inter_2_Cert,
			exiOut->V2G_Message.Body.CertificateInstallationRes.SAProvisioningCertificateChain.SubCertificates.Certificate.array[1].bytesLen);

	exiOut->V2G_Message.Body.CertificateInstallationRes.SAProvisioningCertificateChain.Certificate.bytesLen = CPS_Leaf_Cert_len;
	memcpy(	exiOut->V2G_Message.Body.CertificateInstallationRes.SAProvisioningCertificateChain.Certificate.bytes,
			CPS_Leaf_Cert,
			exiOut->V2G_Message.Body.CertificateInstallationRes.SAProvisioningCertificateChain.Certificate.bytesLen);

	// ContractSignatureCertChain
	exiOut->V2G_Message.Body.CertificateInstallationRes.ContractSignatureCertChain.Id_isUsed = 1u;
	exiOut->V2G_Message.Body.CertificateInstallationRes.ContractSignatureCertChain.Id.charactersLen = 3;
	memcpy(	exiOut->V2G_Message.Body.CertificateInstallationRes.ContractSignatureCertChain.Id.characters, 
			"id1", 
			exiOut->V2G_Message.Body.CertificateInstallationRes.ContractSignatureCertChain.Id.charactersLen);

	exiOut->V2G_Message.Body.CertificateInstallationRes.ContractSignatureCertChain.SubCertificates_isUsed = 1;
	exiOut->V2G_Message.Body.CertificateInstallationRes.ContractSignatureCertChain.SubCertificates.Certificate.arrayLen = 2; // 2 sub-certificates
	exiOut->V2G_Message.Body.CertificateInstallationRes.ContractSignatureCertChain.SubCertificates.Certificate.array[0].bytesLen = Contract_Inter_1_Cert_len;
	memcpy(	exiOut->V2G_Message.Body.CertificateInstallationRes.ContractSignatureCertChain.SubCertificates.Certificate.array[0].bytes,
			Contract_Inter_1_Cert,
			exiOut->V2G_Message.Body.CertificateInstallationRes.ContractSignatureCertChain.SubCertificates.Certificate.array[0].bytesLen);

	exiOut->V2G_Message.Body.CertificateInstallationRes.ContractSignatureCertChain.SubCertificates.Certificate.array[1].bytesLen = Contract_Inter_2_Cert_len;
	memcpy(	exiOut->V2G_Message.Body.CertificateInstallationRes.ContractSignatureCertChain.SubCertificates.Certificate.array[1].bytes,
			Contract_Inter_2_Cert,
			exiOut->V2G_Message.Body.CertificateInstallationRes.ContractSignatureCertChain.SubCertificates.Certificate.array[1].bytesLen);

	exiOut->V2G_Message.Body.CertificateInstallationRes.ContractSignatureCertChain.Certificate.bytesLen = Contract_Leaf_Cert_len;
	memcpy(	exiOut->V2G_Message.Body.CertificateInstallationRes.ContractSignatureCertChain.Certificate.bytes,
			Contract_Leaf_Cert,
			exiOut->V2G_Message.Body.CertificateInstallationRes.ContractSignatureCertChain.Certificate.bytesLen);

	// Encrypted Contract Private Key
	exiOut->V2G_Message.Body.CertificateInstallationRes.ContractSignatureEncryptedPrivateKey.Id.charactersLen = 3;
	memcpy(exiOut->V2G_Message.Body.CertificateInstallationRes.ContractSignatureEncryptedPrivateKey.Id.characters, "id2", 3);
	exiOut->V2G_Message.Body.CertificateInstallationRes.ContractSignatureEncryptedPrivateKey.CONTENT.bytesLen = sizeof(encryptBuf);
	memcpy(	exiOut->V2G_Message.Body.CertificateInstallationRes.ContractSignatureEncryptedPrivateKey.CONTENT.bytes,
			encryptBuf,
			sizeof(encryptBuf));

	// DH Public Key
	exiOut->V2G_Message.Body.CertificateInstallationRes.DHpublickey.Id.charactersLen = 3;
	memcpy(	exiOut->V2G_Message.Body.CertificateInstallationRes.DHpublickey.Id.characters,
			"id3",
			exiOut->V2G_Message.Body.CertificateInstallationRes.DHpublickey.Id.charactersLen);
	exiOut->V2G_Message.Body.CertificateInstallationRes.DHpublickey.CONTENT.bytesLen = dhPubkeyLen;
	memcpy(	exiOut->V2G_Message.Body.CertificateInstallationRes.DHpublickey.CONTENT.bytes, 
			dhPukeyBuf, dhPubkeyLen);

	// eMAID
	// ContractCertificateChain, find DN of certificate
	// TODO: remove hyphens from eMAID?
	if ((ret = mbedtls_x509_crt_parse(	&contractCrt, 
										(const unsigned char *)Contract_Leaf_Cert,
										Contract_Leaf_Cert_len)) != 0) {
		PRINTF("CERT LOAD ERR : %d\r\n", ret);
	}
	
	eMAIDLen = find_oid_value_in_name(&contractCrt.subject, "CN", eMAID, sizeof(eMAID));
	exiOut->V2G_Message.Body.CertificateInstallationRes.eMAID.Id.charactersLen = 3;
	memcpy(	exiOut->V2G_Message.Body.CertificateInstallationRes.eMAID.Id.characters, 
			"id4", 
			exiOut->V2G_Message.Body.CertificateInstallationRes.eMAID.Id.charactersLen);
	exiOut->V2G_Message.Body.CertificateInstallationRes.eMAID.CONTENT.charactersLen = eMAIDLen;
	memcpy(	exiOut->V2G_Message.Body.CertificateInstallationRes.eMAID.CONTENT.characters,
			eMAID,
			eMAIDLen);
	mbedtls_x509_crt_free(&contractCrt);

	/*************************************
	 * CREATING V2G SIGNATURE
	 * ***********************************/
	//struct v2gEXIFragment *auth_fragment_create = (struct v2gEXIFragment*) pvPortMalloc(sizeof(struct v2gEXIFragment));
    /*struct v2gEXIFragment auth_fragment_create;

	init_v2gEXIFragment(&auth_fragment_create);
    auth_fragment_create.CertificateInstallationRes_isUsed = 1u;
	PRINTF("SIZE OF CERTIFICATE INSTALL RES: %d\r\n", sizeof(auth_fragment_create.CertificateInstallationRes));
    memcpy(	&auth_fragment_create.CertificateInstallationRes, 
			&exiOut->V2G_Message.Body.CertificateInstallationRes, 
			sizeof(auth_fragment_create.CertificateInstallationRes));
			
	if ((ret = create_v2g_signature(&auth_fragment_create, 
									&exiOut->V2G_Message.Header.Signature,
									&ctr_drbg)) != 0) {
		PRINTF("[V2G] CREATING V2G ERR: %d\r\n", ret);
	}
	else {
		exiOut->V2G_Message.Header.Signature_isUsed = 1u;
	}
	//vPortFree(auth_fragment_create);*/

	PRINTF("Certificate Installation DONE!\r\n");

	return;
}

void handle_authorization(struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut) {

	PRINTF("[V2G] AUTHORIZATION\r\n");
	// Prepare response
	init_v2gAuthorizationResType(&exiOut->V2G_Message.Body.AuthorizationRes);
	exiOut->V2G_Message.Body.AuthorizationRes_isUsed = 1u;

	// Process request
	exiOut->V2G_Message.Body.AuthorizationRes.ResponseCode = v2gresponseCodeType_OK;
	if (!charge_session.v2g.stateFlow.paymentDetails_ok && !charge_session.v2g.stateFlow.paymentServiceSelection_ok) {
		exiOut->V2G_Message.Body.AuthorizationRes.ResponseCode = v2gresponseCodeType_FAILED_SequenceError;
	}
	if (!check_ev_session_id(exiIn->V2G_Message.Header)) {
		exiOut->V2G_Message.Body.AuthorizationRes.ResponseCode = v2gresponseCodeType_FAILED_UnknownSession;
	}
	if (charge_session.v2g.payment_selected == v2gpaymentOptionType_Contract) {
		if (memcmp(exiIn->V2G_Message.Body.AuthorizationReq.GenChallenge.bytes, charge_session.v2g.challenge, 
					sizeof(charge_session.v2g.challenge) != 0)) {
			exiOut->V2G_Message.Body.AuthorizationRes.ResponseCode = v2gresponseCodeType_FAILED_ChallengeInvalid;
		}
	}

	exiOut->V2G_Message.Body.AuthorizationRes.EVSEProcessing = v2gEVSEProcessingType_Finished;
	return;
}

void handle_charge_param_discovery(struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut) {
	
	uint8_t i;
	bool energy_mode_ok = false;

	// Prepare response
	init_v2gChargeParameterDiscoveryResType(&exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes);
	exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes_isUsed = 1u;

	// Process request
	exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes.ResponseCode = v2gresponseCodeType_OK;
	if (!charge_session.v2g.stateFlow.authorization_ok && (charge_session.vehicle.ev_charge_progress != v2gchargeProgressType_Renegotiate)) {
		exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes.ResponseCode = v2gresponseCodeType_FAILED_SequenceError;
	}
	if (!check_ev_session_id(exiIn->V2G_Message.Header)) {
		exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes.ResponseCode = v2gresponseCodeType_FAILED_UnknownSession;
	}

	// Verify requested energy transfer modes from EV
	for (i = 0; i < charge_session.charger.energyTransferModeList.EnergyTransferMode.arrayLen; i++) {
		if (exiIn->V2G_Message.Body.ChargeParameterDiscoveryReq.RequestedEnergyTransferMode == 
			charge_session.charger.energyTransferModeList.EnergyTransferMode.array[i]) {
			energy_mode_ok = true;
			charge_session.v2g.energyTransferMode.EnergyTransferMode.array[0] = charge_session.charger.energyTransferModeList.EnergyTransferMode.array[i];
			charge_session.v2g.energyTransferMode.EnergyTransferMode.arrayLen = 1;
		}
	}
	if (!energy_mode_ok) {
		exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes.ResponseCode = v2gresponseCodeType_FAILED_WrongEnergyTransferMode;
	}

	exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes_isUsed = 1u;
	exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes.EVSEProcessing = charge_session.charger.evse_processing;
	exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes.EVSEChargeParameter_isUsed = 0u;

	// AC Charging
	if (charge_session.v2g.energyTransferMode.EnergyTransferMode.array[0] == v2gEnergyTransferModeType_AC_single_phase_core ||
		charge_session.v2g.energyTransferMode.EnergyTransferMode.array[0] == v2gEnergyTransferModeType_AC_three_phase_core) {
		if (exiIn->V2G_Message.Body.ChargeParameterDiscoveryReq.AC_EVChargeParameter_isUsed) {
			charge_session.vehicle.ev_max_line_voltage = exiIn->V2G_Message.Body.ChargeParameterDiscoveryReq.AC_EVChargeParameter.EVMaxVoltage;
			charge_session.vehicle.ev_max_line_current = exiIn->V2G_Message.Body.ChargeParameterDiscoveryReq.AC_EVChargeParameter.EVMaxCurrent;
			charge_session.vehicle.ev_min_line_current = exiIn->V2G_Message.Body.ChargeParameterDiscoveryReq.AC_EVChargeParameter.EVMinCurrent;
			charge_session.vehicle.energy_request = exiIn->V2G_Message.Body.ChargeParameterDiscoveryReq.AC_EVChargeParameter.EAmount;
			if (exiIn->V2G_Message.Body.ChargeParameterDiscoveryReq.AC_EVChargeParameter.DepartureTime_isUsed) {
				charge_session.vehicle.departure_time = exiIn->V2G_Message.Body.ChargeParameterDiscoveryReq.AC_EVChargeParameter.DepartureTime;
			}
		}
		else {
			exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes.ResponseCode = v2gresponseCodeType_FAILED_WrongChargeParameter;
		}

		exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes.AC_EVSEChargeParameter_isUsed = 1u;
		exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes.DC_EVSEChargeParameter_isUsed = 0u;
		exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes.AC_EVSEChargeParameter.EVSEMaxCurrent = charge_session.charger.evse_max_line_current;
		exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes.AC_EVSEChargeParameter.EVSENominalVoltage = charge_session.charger.evse_line_voltage;
		exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes.AC_EVSEChargeParameter.AC_EVSEStatus = charge_session.charger.AC_EVSEStatus; 
	}
	// DC Charging
	else {
		if (exiIn->V2G_Message.Body.ChargeParameterDiscoveryReq.DC_EVChargeParameter_isUsed) {
			charge_session.vehicle.ev_max_voltage = exiIn->V2G_Message.Body.ChargeParameterDiscoveryReq.DC_EVChargeParameter.EVMaximumVoltageLimit;
			charge_session.vehicle.ev_max_current = exiIn->V2G_Message.Body.ChargeParameterDiscoveryReq.DC_EVChargeParameter.EVMaximumCurrentLimit;
			if (exiIn->V2G_Message.Body.ChargeParameterDiscoveryReq.DC_EVChargeParameter.EVMaximumPowerLimit_isUsed) {
				charge_session.vehicle.ev_max_power = exiIn->V2G_Message.Body.ChargeParameterDiscoveryReq.DC_EVChargeParameter.EVMaximumPowerLimit;
			}
			if (exiIn->V2G_Message.Body.ChargeParameterDiscoveryReq.DC_EVChargeParameter.DepartureTime_isUsed) {
				charge_session.vehicle.departure_time = exiIn->V2G_Message.Body.ChargeParameterDiscoveryReq.DC_EVChargeParameter.DepartureTime;
			}
			if (exiIn->V2G_Message.Body.ChargeParameterDiscoveryReq.DC_EVChargeParameter.EVEnergyRequest_isUsed) {
				charge_session.vehicle.energy_request = exiIn->V2G_Message.Body.ChargeParameterDiscoveryReq.DC_EVChargeParameter.EVEnergyRequest;
			}
		}
		else {
			exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes.ResponseCode = v2gresponseCodeType_FAILED_WrongChargeParameter;
		}
		
		exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes.AC_EVSEChargeParameter_isUsed = 0u;
		exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes.DC_EVSEChargeParameter_isUsed = 1u;
		exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes.DC_EVSEChargeParameter.DC_EVSEStatus = charge_session.charger.DC_EVSEStatus;
		exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes.DC_EVSEChargeParameter.EVSEMaximumCurrentLimit = charge_session.charger.evse_max_current;
		exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes.DC_EVSEChargeParameter.EVSEMaximumPowerLimit = charge_session.charger.evse_max_power;
		exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes.DC_EVSEChargeParameter.EVSEMaximumVoltageLimit = charge_session.charger.evse_max_voltage;
		exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes.DC_EVSEChargeParameter.EVSEMinimumCurrentLimit = charge_session.charger.evse_min_current;
		exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes.DC_EVSEChargeParameter.EVSEMinimumVoltageLimit = charge_session.charger.evse_min_voltage;
		exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes.DC_EVSEChargeParameter.EVSECurrentRegulationTolerance_isUsed = 1u;
		exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes.DC_EVSEChargeParameter.EVSECurrentRegulationTolerance = charge_session.charger.evse_current_regulation_tol;
		exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes.DC_EVSEChargeParameter.EVSEPeakCurrentRipple = charge_session.charger.evse_peak_current_ripple;
		exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes.DC_EVSEChargeParameter.EVSEEnergyToBeDelivered_isUsed = 1u;
		exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes.DC_EVSEChargeParameter.EVSEEnergyToBeDelivered = charge_session.charger.evse_delivery_energy;
	}
	
	// Predefined schedule
	exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes.SAScheduleList_isUsed = 1u;
	exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes.SAScheduleList.SAScheduleTuple.arrayLen = charge_session.charger.evse_sa_schedules.SAScheduleTuple.arrayLen;
	
	memcpy(	&exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes.SAScheduleList,
			&charge_session.charger.evse_sa_schedules,
			sizeof(exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes.SAScheduleList)); // this is not showing correctly in Wireshark, but RISE-V2G reads OK
	
	return;
}

void handle_cable_check(struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut) {
	static uint8_t processing = 0; // FOR TESTING!!!
	
	// Prepare response
	init_v2gCableCheckResType(&exiOut->V2G_Message.Body.CableCheckRes);
	exiOut->V2G_Message.Body.CableCheckRes_isUsed = 1u;

	// Process request
	exiOut->V2G_Message.Body.CableCheckRes.ResponseCode = v2gresponseCodeType_OK;
	if (!charge_session.v2g.stateFlow.chargeParamDiscovery_ok && !charge_session.v2g.stateFlow.cableCheck_ok) {
		exiOut->V2G_Message.Body.CableCheckRes.ResponseCode = v2gresponseCodeType_FAILED_SequenceError;
	}
	if (!check_ev_session_id(exiIn->V2G_Message.Header)) {
		exiOut->V2G_Message.Body.CableCheckRes.ResponseCode = v2gresponseCodeType_FAILED_UnknownSession;
	}

	processing++;// FOR TESTING!!!
	if (processing < 10) {
		exiOut->V2G_Message.Body.CableCheckRes.EVSEProcessing = v2gEVSEProcessingType_Ongoing;
	}
	else {
		processing = 0;
		exiOut->V2G_Message.Body.CableCheckRes.EVSEProcessing = v2gEVSEProcessingType_Finished;
	}
	//exiOut->V2G_Message.Body.CableCheckRes.EVSEProcessing = charge_session.charger.evse_processing;
	exiOut->V2G_Message.Body.CableCheckRes.DC_EVSEStatus.EVSENotification = charge_session.charger.DC_EVSEStatus.EVSENotification;
	exiOut->V2G_Message.Body.CableCheckRes.DC_EVSEStatus.EVSEIsolationStatus_isUsed = charge_session.charger.DC_EVSEStatus.EVSEIsolationStatus_isUsed;
	exiOut->V2G_Message.Body.CableCheckRes.DC_EVSEStatus.EVSEIsolationStatus = charge_session.charger.DC_EVSEStatus.EVSEIsolationStatus;
	exiOut->V2G_Message.Body.CableCheckRes.DC_EVSEStatus.EVSEStatusCode = charge_session.charger.DC_EVSEStatus.EVSEStatusCode;

	return;
}

void handle_pre_charge(struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut) {
	static uint8_t processing = 0; // FOR TESTING!!!

	// Prepare response
	init_v2gPreChargeResType(&exiOut->V2G_Message.Body.PreChargeRes);
	exiOut->V2G_Message.Body.PreChargeRes_isUsed = 1u;

	// Process request
	exiOut->V2G_Message.Body.PreChargeRes.ResponseCode = v2gresponseCodeType_OK;
	if (!charge_session.v2g.stateFlow.cableCheck_ok && !charge_session.v2g.stateFlow.preCharge_ok) {
		exiOut->V2G_Message.Body.PreChargeRes.ResponseCode = v2gresponseCodeType_FAILED_SequenceError;
	}
	if (!check_ev_session_id(exiIn->V2G_Message.Header)) {
		exiOut->V2G_Message.Body.PreChargeRes.ResponseCode = v2gresponseCodeType_FAILED_UnknownSession;
	}

	// Update EV data
	charge_session.vehicle.ev_target_voltage = exiIn->V2G_Message.Body.PreChargeReq.EVTargetVoltage;
	charge_session.vehicle.ev_target_current = exiIn->V2G_Message.Body.PreChargeReq.EVTargetCurrent;
	charge_session.vehicle.ev_error_code = exiIn->V2G_Message.Body.PreChargeReq.DC_EVStatus.EVErrorCode;

	processing++;// FOR TESTING!!!
	if (processing < 10) {
		exiOut->V2G_Message.Body.PreChargeRes.EVSEPresentVoltage = charge_session.charger.evse_present_voltage; // 0.0V
	}
	else {
		processing = 0;
		exiOut->V2G_Message.Body.PreChargeRes.EVSEPresentVoltage = exiIn->V2G_Message.Body.PreChargeReq.EVTargetVoltage; // !!! Match target voltage
	}
	//exiOut->V2G_Message.Body.PreChargeRes.EVSEPresentVoltage = charge_session.charger.evse_present_voltage;
	exiOut->V2G_Message.Body.PreChargeRes.DC_EVSEStatus.EVSENotification = charge_session.charger.DC_EVSEStatus.EVSENotification;
	exiOut->V2G_Message.Body.PreChargeRes.DC_EVSEStatus.EVSEIsolationStatus_isUsed = charge_session.charger.DC_EVSEStatus.EVSEIsolationStatus_isUsed;
	exiOut->V2G_Message.Body.PreChargeRes.DC_EVSEStatus.EVSEIsolationStatus = charge_session.charger.DC_EVSEStatus.EVSEIsolationStatus;
	exiOut->V2G_Message.Body.PreChargeRes.DC_EVSEStatus.EVSEStatusCode = charge_session.charger.DC_EVSEStatus.EVSEStatusCode;

	return;
}

void handle_power_delivery(struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut) {
	
	uint8_t i;

	// Prepare response
	init_v2gPowerDeliveryResType(&exiOut->V2G_Message.Body.PowerDeliveryRes);
	exiOut->V2G_Message.Body.PowerDeliveryRes_isUsed = 1u;

	// Process request
	exiOut->V2G_Message.Body.PowerDeliveryRes.ResponseCode = v2gresponseCodeType_OK;
	if (!check_ev_session_id(exiIn->V2G_Message.Header)) {
		exiOut->V2G_Message.Body.PowerDeliveryRes.ResponseCode = v2gresponseCodeType_FAILED_UnknownSession;
	}

	// Store SAScheduleTuple requested by the EV
	for (i = 0; i < charge_session.charger.evse_sa_schedules.SAScheduleTuple.arrayLen; i++) {

		if (charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[i].SAScheduleTupleID == 
			exiIn->V2G_Message.Body.PowerDeliveryReq.SAScheduleTupleID) {

			charge_session.v2g.prev_ev_sa_schedule_isAvailable = 1;
			memcpy(	&charge_session.v2g.ev_sa_schedule, 
					&charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[i], 
					sizeof(charge_session.v2g.ev_sa_schedule));
			break;
		}
	}

	// Validate EV Charging profile
	if (exiIn->V2G_Message.Body.PowerDeliveryReq.ChargingProfile_isUsed) {
		for (i = 0; i < exiIn->V2G_Message.Body.PowerDeliveryReq.ChargingProfile.ProfileEntry.arrayLen; i++) {
			/*exiIn->V2G_Message.Body.PowerDeliveryReq.ChargingProfile.ProfileEntry.array[i].ChargingProfileEntryStart // Start Time
			exiIn->V2G_Message.Body.PowerDeliveryReq.ChargingProfile.ProfileEntry.array[i].ChargingProfileEntryMaxPower
			exiOut->V2G_Message.Body.PowerDeliveryRes.ResponseCode = v2gresponseCodeType_FAILED_ChargingProfileInvalid;
			*/
		}
	}
	else {
		;
	}

	// AC Charging sequence
	if (charge_session.v2g.energyTransferMode.EnergyTransferMode.array[0] == v2gEnergyTransferModeType_AC_single_phase_core ||
		charge_session.v2g.energyTransferMode.EnergyTransferMode.array[0] == v2gEnergyTransferModeType_AC_three_phase_core) {
		
		if (!charge_session.v2g.stateFlow.chargeParamDiscovery_ok && !charge_session.v2g.stateFlow.chargingStatus_ok) {
			exiOut->V2G_Message.Body.PowerDeliveryRes.ResponseCode = v2gresponseCodeType_FAILED_SequenceError;
		}

		exiOut->V2G_Message.Body.PowerDeliveryRes.AC_EVSEStatus_isUsed = 1u;
		exiOut->V2G_Message.Body.PowerDeliveryRes.DC_EVSEStatus_isUsed = 0u;
		exiOut->V2G_Message.Body.PowerDeliveryRes.AC_EVSEStatus = charge_session.charger.AC_EVSEStatus; 
		
	}
	// DC Charging sequence
	else {

		if (!charge_session.v2g.stateFlow.preCharge_ok && !charge_session.v2g.stateFlow.currentDemand_ok) {
			exiOut->V2G_Message.Body.PowerDeliveryRes.ResponseCode = v2gresponseCodeType_FAILED_SequenceError;
		}

		exiOut->V2G_Message.Body.PowerDeliveryRes.AC_EVSEStatus_isUsed = 0u;
		exiOut->V2G_Message.Body.PowerDeliveryRes.DC_EVSEStatus_isUsed = 1u;
		exiOut->V2G_Message.Body.PowerDeliveryRes.DC_EVSEStatus = charge_session.charger.DC_EVSEStatus;
	}

	// Update EV data
	charge_session.vehicle.ev_charge_progress = exiIn->V2G_Message.Body.PowerDeliveryReq.ChargeProgress;

	return;
}

void handle_current_demand(struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut) {
	
	// Prepare response
	init_v2gCurrentDemandResType(&exiOut->V2G_Message.Body.CurrentDemandRes);
	exiOut->V2G_Message.Body.CurrentDemandRes_isUsed = 1u;

	// Process request
	exiOut->V2G_Message.Body.CurrentDemandRes.ResponseCode = v2gresponseCodeType_OK;
	if (!charge_session.v2g.stateFlow.powerDelivery_ok && !charge_session.v2g.stateFlow.currentDemand_ok &&
		(charge_session.vehicle.ev_charge_progress != v2gchargeProgressType_Start)) {
		exiOut->V2G_Message.Body.CurrentDemandRes.ResponseCode = v2gresponseCodeType_FAILED_SequenceError;
	}
	if (!check_ev_session_id(exiIn->V2G_Message.Header)) {
		exiOut->V2G_Message.Body.CurrentDemandRes.ResponseCode = v2gresponseCodeType_FAILED_UnknownSession;
	}

	// Update EV data
	charge_session.vehicle.ev_target_voltage = exiIn->V2G_Message.Body.CurrentDemandReq.EVTargetVoltage;
	charge_session.vehicle.ev_target_current = exiIn->V2G_Message.Body.CurrentDemandReq.EVTargetCurrent;
	charge_session.vehicle.ev_error_code = exiIn->V2G_Message.Body.CurrentDemandReq.DC_EVStatus.EVErrorCode;

	// Max and limit values
	exiOut->V2G_Message.Body.CurrentDemandRes.EVSECurrentLimitAchieved = 0u;
	if (v2g_physical_val_get(charge_session.charger.evse_present_current) >= 
		v2g_physical_val_get(charge_session.charger.evse_max_current)) {
		exiOut->V2G_Message.Body.CurrentDemandRes.EVSECurrentLimitAchieved = 1u;
	}
	exiOut->V2G_Message.Body.CurrentDemandRes.EVSEVoltageLimitAchieved = 0u;
	if (v2g_physical_val_get(charge_session.charger.evse_present_voltage) >= 
		v2g_physical_val_get(charge_session.charger.evse_max_voltage)) {
		exiOut->V2G_Message.Body.CurrentDemandRes.EVSEVoltageLimitAchieved = 1u;
	}
	exiOut->V2G_Message.Body.CurrentDemandRes.EVSEPowerLimitAchieved = 0u;
	if (	(v2g_physical_val_get(charge_session.charger.evse_present_voltage) * 
			v2g_physical_val_get(charge_session.charger.evse_present_current)) >= 
			v2g_physical_val_get(charge_session.charger.evse_max_power)) {
		exiOut->V2G_Message.Body.CurrentDemandRes.EVSEPowerLimitAchieved = 1u;
	}

	exiOut->V2G_Message.Body.CurrentDemandRes.EVSEMaximumCurrentLimit_isUsed = 1u;
	exiOut->V2G_Message.Body.CurrentDemandRes.EVSEMaximumCurrentLimit = charge_session.charger.evse_max_current;
	exiOut->V2G_Message.Body.CurrentDemandRes.EVSEMaximumVoltageLimit_isUsed = 1u;
	exiOut->V2G_Message.Body.CurrentDemandRes.EVSEMaximumVoltageLimit = charge_session.charger.evse_max_voltage;
	exiOut->V2G_Message.Body.CurrentDemandRes.EVSEMaximumPowerLimit_isUsed = 1u;
	exiOut->V2G_Message.Body.CurrentDemandRes.EVSEMaximumPowerLimit = charge_session.charger.evse_max_power;
	exiOut->V2G_Message.Body.CurrentDemandRes.EVSEPresentCurrent = charge_session.charger.evse_present_current;
	exiOut->V2G_Message.Body.CurrentDemandRes.EVSEPresentVoltage = charge_session.charger.evse_present_voltage;

	exiOut->V2G_Message.Body.CurrentDemandRes.DC_EVSEStatus.EVSENotification = charge_session.charger.DC_EVSEStatus.EVSENotification;
	exiOut->V2G_Message.Body.CurrentDemandRes.DC_EVSEStatus.EVSEIsolationStatus_isUsed = charge_session.charger.DC_EVSEStatus.EVSEIsolationStatus_isUsed;
	exiOut->V2G_Message.Body.CurrentDemandRes.DC_EVSEStatus.EVSEIsolationStatus = charge_session.charger.DC_EVSEStatus.EVSEIsolationStatus;
	exiOut->V2G_Message.Body.CurrentDemandRes.DC_EVSEStatus.EVSEStatusCode = charge_session.charger.DC_EVSEStatus.EVSEStatusCode;

	memcpy(&exiOut->V2G_Message.Body.CurrentDemandRes.EVSEID, &charge_session.charger.EVSEID, sizeof(charge_session.charger.EVSEID));
	
	return;
}

void handle_welding_detection(struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut) {
	
	// Prepare response
	init_v2gWeldingDetectionResType(&exiOut->V2G_Message.Body.WeldingDetectionRes);
	exiOut->V2G_Message.Body.WeldingDetectionRes_isUsed = 1u;

	// Process request
	exiOut->V2G_Message.Body.WeldingDetectionRes.ResponseCode = v2gresponseCodeType_OK;
	if (!charge_session.v2g.stateFlow.currentDemand_ok && (charge_session.vehicle.ev_charge_progress != v2gchargeProgressType_Stop)) {
		exiOut->V2G_Message.Body.WeldingDetectionRes.ResponseCode = v2gresponseCodeType_FAILED_SequenceError;
	}
	if (!check_ev_session_id(exiIn->V2G_Message.Header)) {
		exiOut->V2G_Message.Body.WeldingDetectionRes.ResponseCode = v2gresponseCodeType_FAILED_UnknownSession;
	}
	exiOut->V2G_Message.Body.WeldingDetectionRes.EVSEPresentVoltage = charge_session.charger.evse_present_voltage;
	exiOut->V2G_Message.Body.WeldingDetectionRes.DC_EVSEStatus.EVSENotification = charge_session.charger.DC_EVSEStatus.EVSENotification;
	exiOut->V2G_Message.Body.WeldingDetectionRes.DC_EVSEStatus.EVSEIsolationStatus_isUsed = charge_session.charger.DC_EVSEStatus.EVSEIsolationStatus_isUsed;
	exiOut->V2G_Message.Body.WeldingDetectionRes.DC_EVSEStatus.EVSEIsolationStatus = charge_session.charger.DC_EVSEStatus.EVSEIsolationStatus;
	exiOut->V2G_Message.Body.WeldingDetectionRes.DC_EVSEStatus.EVSEStatusCode = charge_session.charger.DC_EVSEStatus.EVSEStatusCode;

	return;
}

void handle_charging_status(struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut) {
	
	// Prepare response
	init_v2gChargingStatusResType(&exiOut->V2G_Message.Body.ChargingStatusRes);
	exiOut->V2G_Message.Body.ChargingStatusRes_isUsed = 1u;

	// Process request
	exiOut->V2G_Message.Body.ChargingStatusRes.ResponseCode = v2gresponseCodeType_OK;
	if (!charge_session.v2g.stateFlow.powerDelivery_ok && !charge_session.v2g.stateFlow.chargingStatus_ok) {
		exiOut->V2G_Message.Body.ChargingStatusRes.ResponseCode = v2gresponseCodeType_FAILED_SequenceError;
	}
	if (!check_ev_session_id(exiIn->V2G_Message.Header)) {
		exiOut->V2G_Message.Body.ChargingStatusRes.ResponseCode = v2gresponseCodeType_FAILED_UnknownSession;
	}

	memcpy(&exiOut->V2G_Message.Body.ChargingStatusRes.EVSEID, &charge_session.charger.EVSEID, sizeof(charge_session.charger.EVSEID));
	exiOut->V2G_Message.Body.ChargingStatusRes.SAScheduleTupleID = 10; // !!! check current Schedule ID
	exiOut->V2G_Message.Body.ChargingStatusRes.EVSEMaxCurrent_isUsed = 1u;
	exiOut->V2G_Message.Body.ChargingStatusRes.EVSEMaxCurrent = charge_session.charger.evse_max_line_current;
	exiOut->V2G_Message.Body.ChargingStatusRes.MeterInfo_isUsed = 0;
	exiOut->V2G_Message.Body.ChargingStatusRes.ReceiptRequired_isUsed = 1u;
	exiOut->V2G_Message.Body.ChargingStatusRes.ReceiptRequired = 0;
	exiOut->V2G_Message.Body.ChargingStatusRes.AC_EVSEStatus = charge_session.charger.AC_EVSEStatus;

	return;
}

void handle_session_stop(struct v2gEXIDocument *exiIn, struct v2gEXIDocument *exiOut) {
	
	// Prepare response
	init_v2gSessionStopResType(&exiOut->V2G_Message.Body.SessionStopRes);
	exiOut->V2G_Message.Body.SessionStopRes_isUsed = 1u;

	// Process request
	exiOut->V2G_Message.Body.SessionStopRes.ResponseCode = v2gresponseCodeType_OK;
	if (!check_ev_session_id(exiIn->V2G_Message.Header)) {
		exiOut->V2G_Message.Body.SessionStopRes.ResponseCode = v2gresponseCodeType_FAILED_UnknownSession;
	}

	return;
}

double v2g_physical_val_get(struct v2gPhysicalValueType val) {
	return (double)(((double)val.Value) * (double)pow(10, (double)val.Multiplier));
}

bool check_ev_session_id(struct v2gMessageHeaderType v2gHeader) {

	if (	(memcmp(v2gHeader.SessionID.bytes, 
					charge_session.v2g.SessionID.bytes, 
					charge_session.v2g.SessionID.bytesLen) != 0) || 
			v2gHeader.SessionID.bytesLen != charge_session.v2g.SessionID.bytesLen) {

		return false; // v2gresponseCodeType_FAILED_UnknownSession
	}
	return true;

}

void v2g_init() {
	PRINTF("V2G_INIT\r\n");
	int err = 0;
	// TLS Stack Init
	if ((err = tls_stack_init()) != 0) {
		PRINTF("[V2G] TLS Init error: %d\r\n", err);
	}    

	// V2G Thread
    if (sys_thread_new("v2g_session", v2g_session, NULL, 8500, 4) == NULL) { // 7000
		PRINTF("V2G thread failed\r\n");
	}
	/* Quick calculations: 
	- 40KB for V2G/TCP
	- 32KB for mbedtls
	*/
}

void sdp_init() {
	PRINTF("SDP_INIT\r\n");
	
	// SDP Thread
	if (sys_thread_new("sdp_session", secc_discovery_protocol, NULL, 300, 2) == NULL) {
		PRINTF("SDP thread failed\r\n");
	}
	// ~10KB
}
