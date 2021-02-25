/*
 * charger.h
 *
 *  Created on: 23 Apr 2019
 *      Author: Roque
 */

#ifndef CHARGER_CHARGER_H_
#define CHARGER_CHARGER_H_

#include <stdbool.h>
#include "stdint.h"

#include "OpenV2G/codec/v2gEXIDatatypes.h"
#include "lwip/ip6_addr.h"
#include "mbedtls/ecdsa.h"

// Variables
extern struct charge_session_t charge_session;

struct charger_t {
    struct {
		exi_string_character_t characters[v2gSessionSetupResType_EVSEID_CHARACTERS_SIZE];
		uint16_t charactersLen;
	}  EVSEID ;
    struct v2gPhysicalValueType evse_max_line_current;
    struct v2gPhysicalValueType evse_line_voltage;
	struct v2gPhysicalValueType evse_max_voltage;
    struct v2gPhysicalValueType evse_min_voltage;
    struct v2gPhysicalValueType evse_max_current;
    struct v2gPhysicalValueType evse_min_current;
    struct v2gPhysicalValueType evse_max_power;
    struct v2gPhysicalValueType evse_current_regulation_tol;
    struct v2gPhysicalValueType evse_peak_current_ripple;
    struct v2gPhysicalValueType evse_delivery_energy;
    bool evse_processing;
    uint16_t notification_max_delay;
    struct v2gPhysicalValueType evse_present_voltage;
    struct v2gPhysicalValueType evse_present_current;
    struct v2gAC_EVSEStatusType AC_EVSEStatus;
	struct v2gDC_EVSEStatusType DC_EVSEStatus;
    struct v2gSAScheduleListType evse_sa_schedules;
    struct v2gSupportedEnergyTransferModeType energyTransferModeList;
    uint16_t secc_v2g_port;
    uint8_t secc_ip_addr[16];
    struct v2gServiceListType evse_service_list;
    struct v2gChargeServiceType evse_charge_service;
    struct v2gPaymentOptionListType evse_payment_options;
    struct v2gServiceParameterListType evse_service_parameters;
};

struct vehicle_t {
    struct v2gPhysicalValueType ev_max_line_voltage;
    struct v2gPhysicalValueType ev_max_line_current;
    struct v2gPhysicalValueType ev_min_line_current;
    struct v2gPhysicalValueType ev_max_voltage;
    struct v2gPhysicalValueType ev_max_current;
    struct v2gPhysicalValueType ev_max_power;
    uint32_t departure_time;
    struct v2gPhysicalValueType energy_request;
    struct v2gPhysicalValueType ev_target_current;
    struct v2gPhysicalValueType ev_target_voltage;
    v2gDC_EVErrorCodeType ev_error_code;
    v2gchargeProgressType ev_charge_progress;
};

struct supported_app_protocols_t {
    char protocol_namespace [256];
    uint8_t major_version;
    uint8_t minor_version;
};

struct slac_session_t {
	uint8_t EVSE_MAC_ADDR [6];
    uint8_t EV_MAC_ADDR [6];
    uint8_t numAttenCharIndCnt;
    uint8_t RunID [8];
    uint8_t numSoundCnt;
    uint8_t numAttenProfileCnt;
    uint8_t numAttenGroups;
    uint8_t avgGroupAtten [255];
    uint8_t numValidateMsg;
    uint16_t timeBCBToggle; // in ms
    bool initBCBToggleTimer;
    bool BCBTimerOver;
    uint8_t numBCBToggles;
    struct {
        bool slacParam_ok;
        bool startAttenChar_ok;
        bool mnbcSound_ok;
        bool attenProfile_ok;
        bool attenChar_ok;
        bool validate_ok;
        bool slacMatch_ok;
        bool linkStatus_ok;
    } stateFlow;
};

struct v2g_session_t {
    struct {
        bool supportedAppProto_ok;
        bool sessionSetup_ok;
        bool serviceDiscovery_ok;
        bool serviceDetail_ok;
        bool paymentDetails_ok;
        bool paymentServiceSelection_ok;
        bool certificateInstallation_ok;
        bool authorization_ok;
        bool chargeParamDiscovery_ok;
        bool cableCheck_ok;
        bool preCharge_ok;
        bool powerDelivery_ok;
        bool currentDemand_ok;
        bool weldingDetection_ok;
        bool chargingStatus_ok;
        bool sessionStop_ok;
    } stateFlow;
    uint8_t ev_ip_addr[16];

    // TLS Session related
    bool tls;
    mbedtls_ecdsa_context contract_ctx;
    //

    struct v2gSupportedEnergyTransferModeType energyTransferMode;
    struct supported_app_protocols_t secc_app_protocols [8];
    uint8_t challenge [16];
    struct v2gPaymentOptionListType payment_options;
    int64_t timestamp;
    struct {
		uint8_t bytes[v2gMessageHeaderType_SessionID_BYTES_SIZE];
		uint16_t bytesLen;
	}  SessionID;
    bool prev_sa_schedule_isAvailable;
    struct v2gSAScheduleTupleType ev_sa_schedule;
    v2gpaymentOptionType payment_selected;
    bool prev_payment_selected_isAvailable;
    bool session_active;
    bool prev_ev_sa_schedule_isAvailable;
    struct v2gServiceListType service_list;
    bool prev_charge_service_isAvailable;
    struct v2gChargeServiceType charge_service;
};

struct charge_session_t {
    struct charger_t charger;
    struct slac_session_t slac;
    struct v2g_session_t v2g;
    struct vehicle_t vehicle;
};

void set_supported_app_protocols();
void load_charger_config(struct ip6_addr *ip_addr);
void load_v2g_session();

#endif /* CHARGER_CHARGER_H_ */
