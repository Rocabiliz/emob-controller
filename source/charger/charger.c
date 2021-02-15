#include <stdio.h>
#include <string.h>
#include "stdint.h"
#include <time.h>
#include <math.h>
#include <stdbool.h>

// Custom includes
#include "slac/slac.h"
#include "v2g/v2g.h"
#include "charger/charger.h"

// Definition of supported App Protocol
void set_supported_app_protocols() {

	memcpy(charge_session.v2g.secc_app_protocols[0].protocol_namespace, "urn:iso:15118:2:2013:MsgDef", 28);
	charge_session.v2g.secc_app_protocols[0].major_version = 2;
	charge_session.v2g.secc_app_protocols[0].minor_version = 0;

	memcpy(charge_session.v2g.secc_app_protocols[1].protocol_namespace, "urn:iso:15118:2:2010:MsgDef", 28);
	charge_session.v2g.secc_app_protocols[1].major_version = 1;
	charge_session.v2g.secc_app_protocols[1].minor_version = 0;

	memcpy(charge_session.v2g.secc_app_protocols[2].protocol_namespace, "urn:din:70121:2012:MsgDef", 25);
	charge_session.v2g.secc_app_protocols[2].major_version = 2;
	charge_session.v2g.secc_app_protocols[2].minor_version = 0;

	return;
}

void load_charger_config(struct ip6_addr *ip_addr) {
    memset(&charge_session.charger, 0, sizeof(charge_session.charger));

    charge_session.charger.secc_v2g_port = 4550;
    memcpy(charge_session.charger.secc_ip_addr, ip_addr, 16);

    charge_session.charger.EVSEID.characters[0] = 0x43;
    charge_session.charger.EVSEID.characters[1] = 0x45;
    charge_session.charger.EVSEID.characters[2] = 0x47;
    charge_session.charger.EVSEID.characters[3] = 0x4F;
    charge_session.charger.EVSEID.characters[4] = 0x4F;
    charge_session.charger.EVSEID.characters[5] = 0x4F;
    charge_session.charger.EVSEID.characters[6] = 0x4F;
    charge_session.charger.EVSEID.charactersLen = 7;

    // Charger generic configurations
    charge_session.charger.energyTransferModeList.EnergyTransferMode.array[0] = v2gEnergyTransferModeType_DC_core;
    charge_session.charger.energyTransferModeList.EnergyTransferMode.array[1] = v2gEnergyTransferModeType_DC_extended;
    charge_session.charger.energyTransferModeList.EnergyTransferMode.array[2] = v2gEnergyTransferModeType_DC_combo_core;
    charge_session.charger.energyTransferModeList.EnergyTransferMode.array[3] = v2gEnergyTransferModeType_DC_unique;
    charge_session.charger.energyTransferModeList.EnergyTransferMode.array[4] = v2gEnergyTransferModeType_AC_three_phase_core;
    charge_session.charger.energyTransferModeList.EnergyTransferMode.array[5] = v2gEnergyTransferModeType_AC_single_phase_core;
    charge_session.charger.energyTransferModeList.EnergyTransferMode.arrayLen = 6;

    // Present values
    charge_session.charger.evse_present_voltage.Unit = v2gunitSymbolType_V;
    charge_session.charger.evse_present_voltage.Multiplier = 0;
    charge_session.charger.evse_present_voltage.Value = 0;
    charge_session.charger.evse_present_current.Unit = v2gunitSymbolType_A;
    charge_session.charger.evse_present_current.Multiplier = 0;
    charge_session.charger.evse_present_voltage.Value = 0;

    // Maximum values and constants
    charge_session.charger.evse_line_voltage.Unit = v2gunitSymbolType_V;
    charge_session.charger.evse_line_voltage.Multiplier = 0;
    charge_session.charger.evse_line_voltage.Value = 230;
    charge_session.charger.evse_max_line_current.Unit = v2gunitSymbolType_A;
    charge_session.charger.evse_max_line_current.Multiplier = 0;
    charge_session.charger.evse_max_line_current.Value = 64;
    charge_session.charger.evse_max_voltage.Unit = v2gunitSymbolType_V;
    charge_session.charger.evse_max_voltage.Multiplier = 1;
    charge_session.charger.evse_max_voltage.Value = 90;
    charge_session.charger.evse_min_voltage.Unit = v2gunitSymbolType_V;
    charge_session.charger.evse_min_voltage.Multiplier = 0;
    charge_session.charger.evse_min_voltage.Value = 400;
    charge_session.charger.evse_max_current.Unit = v2gunitSymbolType_A;
    charge_session.charger.evse_max_current.Multiplier = 0;
    charge_session.charger.evse_max_current.Value = 200;
    charge_session.charger.evse_min_current.Unit = v2gunitSymbolType_A;
    charge_session.charger.evse_min_current.Multiplier = 0;
    charge_session.charger.evse_min_current.Value = 0;
    charge_session.charger.evse_max_power.Unit = v2gunitSymbolType_W;
    charge_session.charger.evse_max_power.Multiplier = 3;
    charge_session.charger.evse_max_power.Value = 150;
    charge_session.charger.evse_current_regulation_tol.Unit = v2gunitSymbolType_A;
    charge_session.charger.evse_current_regulation_tol.Multiplier = 0;
    charge_session.charger.evse_current_regulation_tol.Value = 5;
    charge_session.charger.evse_peak_current_ripple.Unit = v2gunitSymbolType_A;
    charge_session.charger.evse_peak_current_ripple.Multiplier = 0;
    charge_session.charger.evse_peak_current_ripple.Value = 2;
    charge_session.charger.evse_delivery_energy.Unit = v2gunitSymbolType_Wh;
    charge_session.charger.evse_delivery_energy.Multiplier = 3;
    charge_session.charger.evse_delivery_energy.Value = 100;

    charge_session.charger.evse_processing = v2gEVSEProcessingType_Finished;
    charge_session.charger.notification_max_delay = 10;

    // DCStatus
    charge_session.charger.DC_EVSEStatus.NotificationMaxDelay = 10;
	charge_session.charger.DC_EVSEStatus.EVSENotification = v2gEVSENotificationType_None;
	charge_session.charger.DC_EVSEStatus.EVSEIsolationStatus_isUsed = 1u;
	charge_session.charger.DC_EVSEStatus.EVSEIsolationStatus = v2gisolationLevelType_Valid;
	charge_session.charger.DC_EVSEStatus.EVSEStatusCode = v2gDC_EVSEStatusCodeType_EVSE_Ready;

    // AC Status
    charge_session.charger.AC_EVSEStatus.RCD = false;
    charge_session.charger.AC_EVSEStatus.EVSENotification = v2gEVSENotificationType_None;

    // Charging schedules
    memset(&charge_session.charger.evse_sa_schedules, 0, sizeof(charge_session.charger.evse_sa_schedules));
    charge_session.charger.evse_sa_schedules.SAScheduleTuple.arrayLen = 2;

	charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[0].SAScheduleTupleID = 10;
	charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[0].SalesTariff_isUsed = 0; // Necessary for PnC!
	charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleEntry.arrayLen = 2; 
	charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleEntry.array[0].PMax.Value = 10;
	charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleEntry.array[0].PMax.Unit = v2gunitSymbolType_W;
	charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleEntry.array[0].PMax.Multiplier = 0;
	charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleEntry.array[0].TimeInterval_isUsed = 0;
	charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleEntry.array[0].RelativeTimeInterval_isUsed = 1u;
	charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleEntry.array[0].RelativeTimeInterval.start = 0;
	charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleEntry.array[0].RelativeTimeInterval.duration_isUsed = 0;

	charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleEntry.array[1].PMax.Value = 20;
	charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleEntry.array[1].PMax.Unit = v2gunitSymbolType_W;
	charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleEntry.array[1].PMax.Multiplier = 1;
	charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleEntry.array[1].TimeInterval_isUsed = 0;
	charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleEntry.array[1].RelativeTimeInterval_isUsed = 1u;
	charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleEntry.array[1].RelativeTimeInterval.start = 1200; 
	charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleEntry.array[1].RelativeTimeInterval.duration_isUsed = 0;

	charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[1].SAScheduleTupleID = 15;
	charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[1].SalesTariff_isUsed = 0;
	charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[1].PMaxSchedule.PMaxScheduleEntry.arrayLen = 2;
	charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[1].PMaxSchedule.PMaxScheduleEntry.array[0].PMax.Value = 30;
	charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[1].PMaxSchedule.PMaxScheduleEntry.array[0].PMax.Unit = v2gunitSymbolType_W;
	charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[1].PMaxSchedule.PMaxScheduleEntry.array[0].PMax.Multiplier = 2;
	charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[1].PMaxSchedule.PMaxScheduleEntry.array[0].TimeInterval_isUsed = 0;
	charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[1].PMaxSchedule.PMaxScheduleEntry.array[0].RelativeTimeInterval_isUsed = 1;
	charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[1].PMaxSchedule.PMaxScheduleEntry.array[0].RelativeTimeInterval.start = 1600;
	charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[1].PMaxSchedule.PMaxScheduleEntry.array[0].RelativeTimeInterval.duration_isUsed = 0u;

	charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[1].PMaxSchedule.PMaxScheduleEntry.array[1].PMax.Value = 40;
	charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[1].PMaxSchedule.PMaxScheduleEntry.array[1].PMax.Unit = v2gunitSymbolType_W;
	charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[1].PMaxSchedule.PMaxScheduleEntry.array[1].PMax.Multiplier = 3;
	charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[1].PMaxSchedule.PMaxScheduleEntry.array[1].TimeInterval_isUsed = 0;
	charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[1].PMaxSchedule.PMaxScheduleEntry.array[1].RelativeTimeInterval_isUsed = 1u;
	charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[1].PMaxSchedule.PMaxScheduleEntry.array[1].RelativeTimeInterval.start = 1800; 
	charge_session.charger.evse_sa_schedules.SAScheduleTuple.array[1].PMaxSchedule.PMaxScheduleEntry.array[1].RelativeTimeInterval.duration_isUsed = 0u;

    /*
    * Service list
    */
    // Charge Service - should be copied (partially) from the ServiceList evse_service_list below
    charge_session.charger.evse_charge_service.ServiceID = 1; // AC_DC_Charging Table 105
    charge_session.charger.evse_charge_service.ServiceCategory = v2gserviceCategoryType_EVCharging;
    charge_session.charger.evse_charge_service.ServiceName_isUsed = 1u;
    charge_session.charger.evse_charge_service.ServiceName.charactersLen = 14;	
	memcpy( charge_session.charger.evse_charge_service.ServiceName.characters, 
	    "AC_DC_Charging", 
	    charge_session.charger.evse_charge_service.ServiceName.charactersLen);
    charge_session.charger.evse_charge_service.ServiceScope_isUsed = 1u;
    charge_session.charger.evse_charge_service.ServiceScope.characters[0] = 100;
    charge_session.charger.evse_charge_service.ServiceScope.characters[1] = "\0";
    charge_session.charger.evse_charge_service.ServiceScope.charactersLen = 1;
    charge_session.charger.evse_charge_service.FreeService = 1; // If false, the payment will be made with PaymentOption
    memcpy(	&charge_session.charger.evse_charge_service.SupportedEnergyTransferMode.EnergyTransferMode,
			&charge_session.charger.energyTransferModeList.EnergyTransferMode,
			sizeof(charge_session.charger.energyTransferModeList.EnergyTransferMode));

    charge_session.charger.evse_service_list.Service.arrayLen = 3; // 3!!!
	// Charging
 	charge_session.charger.evse_service_list.Service.array[0].ServiceID = 1; // EVCharging Table 105
    charge_session.charger.evse_service_list.Service.array[0].ServiceCategory = v2gserviceCategoryType_EVCharging;
    charge_session.charger.evse_service_list.Service.array[0].ServiceName_isUsed = 1u;
    charge_session.charger.evse_service_list.Service.array[0].ServiceName.charactersLen = 14;
    memcpy( charge_session.charger.evse_service_list.Service.array[0].ServiceName.characters, 
	    	"AC_DC_Charging",
	    	charge_session.charger.evse_service_list.Service.array[0].ServiceName.charactersLen);
    charge_session.charger.evse_service_list.Service.array[0].ServiceScope_isUsed = 0;
    charge_session.charger.evse_service_list.Service.array[0].FreeService = 1;
    // Certificate Installation
    charge_session.charger.evse_service_list.Service.array[1].ServiceID = 2; // Certificate Table 105
    charge_session.charger.evse_service_list.Service.array[1].ServiceCategory = v2gserviceCategoryType_ContractCertificate;
    charge_session.charger.evse_service_list.Service.array[1].ServiceName_isUsed = 1u;
    charge_session.charger.evse_service_list.Service.array[1].ServiceName.charactersLen = 11;
    memcpy( charge_session.charger.evse_service_list.Service.array[1].ServiceName.characters, 
	    	"Certificate",
	    	charge_session.charger.evse_service_list.Service.array[1].ServiceName.charactersLen);
    charge_session.charger.evse_service_list.Service.array[1].ServiceScope_isUsed = 0;
    charge_session.charger.evse_service_list.Service.array[1].FreeService = 1;
    // Internet Access
    charge_session.charger.evse_service_list.Service.array[2].ServiceID = 3; // InternetAccess Table 105
    charge_session.charger.evse_service_list.Service.array[2].ServiceCategory = v2gserviceCategoryType_Internet;
    charge_session.charger.evse_service_list.Service.array[2].ServiceName_isUsed = 1u;
    charge_session.charger.evse_service_list.Service.array[2].ServiceName.charactersLen = 14;
    memcpy( charge_session.charger.evse_service_list.Service.array[2].ServiceName.characters, 
	    	"InternetAccess",
	    	charge_session.charger.evse_service_list.Service.array[2].ServiceName.charactersLen);
    charge_session.charger.evse_service_list.Service.array[2].ServiceScope_isUsed = 0;
    charge_session.charger.evse_service_list.Service.array[2].FreeService = 1;
    
    // Service Parameters
    charge_session.charger.evse_service_parameters.ParameterSet.arrayLen = 4;
    // FTP:20
	charge_session.charger.evse_service_parameters.ParameterSet.array[0].ParameterSetID = 1;
    charge_session.charger.evse_service_parameters.ParameterSet.array[0].Parameter.arrayLen = 2;    
    charge_session.charger.evse_service_parameters.ParameterSet.array[0].Parameter.array[0].Name.charactersLen = 8;
	memcpy(	charge_session.charger.evse_service_parameters.ParameterSet.array[0].Parameter.array[0].Name.characters,
	    	"Protocol",
	    	charge_session.charger.evse_service_parameters.ParameterSet.array[0].Parameter.array[0].Name.charactersLen);
    charge_session.charger.evse_service_parameters.ParameterSet.array[0].Parameter.array[0].stringValue_isUsed = 1u;
    charge_session.charger.evse_service_parameters.ParameterSet.array[0].Parameter.array[0].stringValue.charactersLen = 3;
    memcpy( charge_session.charger.evse_service_parameters.ParameterSet.array[0].Parameter.array[0].stringValue.characters,
	    	"ftp",
	    	charge_session.charger.evse_service_parameters.ParameterSet.array[0].Parameter.array[0].stringValue.charactersLen);
    charge_session.charger.evse_service_parameters.ParameterSet.array[0].Parameter.array[1].Name.charactersLen = 4;
    memcpy( charge_session.charger.evse_service_parameters.ParameterSet.array[0].Parameter.array[1].Name.characters,
	    	"Port",
	    	charge_session.charger.evse_service_parameters.ParameterSet.array[0].Parameter.array[1].Name.charactersLen);
    charge_session.charger.evse_service_parameters.ParameterSet.array[0].Parameter.array[1].intValue_isUsed = 1u;
    charge_session.charger.evse_service_parameters.ParameterSet.array[0].Parameter.array[1].intValue = 20; // Table 107
    // FTP:21
	charge_session.charger.evse_service_parameters.ParameterSet.array[1].ParameterSetID = 2;
    charge_session.charger.evse_service_parameters.ParameterSet.array[1].Parameter.arrayLen = 2;    
    charge_session.charger.evse_service_parameters.ParameterSet.array[1].Parameter.array[0].Name.charactersLen = 8;
    memcpy( charge_session.charger.evse_service_parameters.ParameterSet.array[1].Parameter.array[0].Name.characters,
	    	"Protocol",
	    	charge_session.charger.evse_service_parameters.ParameterSet.array[1].Parameter.array[0].Name.charactersLen);
    charge_session.charger.evse_service_parameters.ParameterSet.array[1].Parameter.array[0].stringValue_isUsed = 1u;
    charge_session.charger.evse_service_parameters.ParameterSet.array[1].Parameter.array[0].stringValue.charactersLen = 3;
    memcpy( charge_session.charger.evse_service_parameters.ParameterSet.array[1].Parameter.array[0].stringValue.characters,
	    	"ftp",
	    	charge_session.charger.evse_service_parameters.ParameterSet.array[1].Parameter.array[0].stringValue.charactersLen);
    charge_session.charger.evse_service_parameters.ParameterSet.array[1].Parameter.array[1].Name.charactersLen = 4;
    memcpy( charge_session.charger.evse_service_parameters.ParameterSet.array[1].Parameter.array[1].Name.characters,
	    	"Port",
	    	charge_session.charger.evse_service_parameters.ParameterSet.array[1].Parameter.array[1].Name.charactersLen);
    charge_session.charger.evse_service_parameters.ParameterSet.array[1].Parameter.array[1].intValue_isUsed = 1u;
    charge_session.charger.evse_service_parameters.ParameterSet.array[1].Parameter.array[1].intValue = 21; // Table 107
    // HTTP:80
	charge_session.charger.evse_service_parameters.ParameterSet.array[2].ParameterSetID = 2;
    charge_session.charger.evse_service_parameters.ParameterSet.array[2].Parameter.arrayLen = 2;    
    charge_session.charger.evse_service_parameters.ParameterSet.array[2].Parameter.array[0].Name.charactersLen = 8;
    memcpy( charge_session.charger.evse_service_parameters.ParameterSet.array[2].Parameter.array[0].Name.characters,
	    	"Protocol",
	    	charge_session.charger.evse_service_parameters.ParameterSet.array[2].Parameter.array[0].Name.charactersLen);
    charge_session.charger.evse_service_parameters.ParameterSet.array[2].Parameter.array[0].stringValue_isUsed = 1u;
    charge_session.charger.evse_service_parameters.ParameterSet.array[2].Parameter.array[0].stringValue.charactersLen = 4;
    memcpy( charge_session.charger.evse_service_parameters.ParameterSet.array[2].Parameter.array[0].stringValue.characters,
	    	"http",
	    	charge_session.charger.evse_service_parameters.ParameterSet.array[2].Parameter.array[0].stringValue.charactersLen);
    charge_session.charger.evse_service_parameters.ParameterSet.array[2].Parameter.array[1].Name.charactersLen = 4;
    memcpy( charge_session.charger.evse_service_parameters.ParameterSet.array[2].Parameter.array[1].Name.characters,
	    	"Port",
	    	charge_session.charger.evse_service_parameters.ParameterSet.array[2].Parameter.array[1].Name.charactersLen);
    charge_session.charger.evse_service_parameters.ParameterSet.array[2].Parameter.array[1].intValue_isUsed = 1u;
    charge_session.charger.evse_service_parameters.ParameterSet.array[2].Parameter.array[1].intValue = 80; // Table 107
    // HTTPS:443
	charge_session.charger.evse_service_parameters.ParameterSet.array[3].ParameterSetID = 2;
    charge_session.charger.evse_service_parameters.ParameterSet.array[3].Parameter.arrayLen = 2;    
    charge_session.charger.evse_service_parameters.ParameterSet.array[3].Parameter.array[0].Name.charactersLen = 8;
    memcpy( charge_session.charger.evse_service_parameters.ParameterSet.array[3].Parameter.array[0].Name.characters,
	    	"Protocol",
	    	charge_session.charger.evse_service_parameters.ParameterSet.array[3].Parameter.array[0].Name.charactersLen);
    charge_session.charger.evse_service_parameters.ParameterSet.array[3].Parameter.array[0].stringValue_isUsed = 1u;
    charge_session.charger.evse_service_parameters.ParameterSet.array[3].Parameter.array[0].stringValue.charactersLen = 5;
    memcpy( charge_session.charger.evse_service_parameters.ParameterSet.array[3].Parameter.array[0].stringValue.characters,
	    	"https",
	    	charge_session.charger.evse_service_parameters.ParameterSet.array[3].Parameter.array[0].stringValue.charactersLen);
    charge_session.charger.evse_service_parameters.ParameterSet.array[3].Parameter.array[1].Name.charactersLen = 4;
    memcpy( charge_session.charger.evse_service_parameters.ParameterSet.array[3].Parameter.array[1].Name.characters,
	    	"Port",
	    	charge_session.charger.evse_service_parameters.ParameterSet.array[3].Parameter.array[1].Name.charactersLen);
    charge_session.charger.evse_service_parameters.ParameterSet.array[3].Parameter.array[1].intValue_isUsed = 1u;
    charge_session.charger.evse_service_parameters.ParameterSet.array[3].Parameter.array[1].intValue = 443; // Table 107

    // Payment Options list
    charge_session.charger.evse_payment_options.PaymentOption.array[0] = v2gpaymentOptionType_ExternalPayment; 
    charge_session.charger.evse_payment_options.PaymentOption.array[1] = v2gpaymentOptionType_Contract; // Contract only possible with TLS!
    charge_session.charger.evse_payment_options.PaymentOption.arrayLen = 2; // 2!!!

	/***************************
	 * V2G Session structure
	 * *************************/
	memset(&charge_session.v2g, 0, sizeof(charge_session.v2g));
    load_v2g_session();

    return;
}

void load_v2g_session() {

    charge_session.v2g.SessionID.bytes[6] = 20;
    charge_session.v2g.SessionID.bytes[7] = 21;
    charge_session.v2g.SessionID.bytesLen = 8;

    charge_session.v2g.session_active = false;
    
    set_supported_app_protocols();

    return;
}
