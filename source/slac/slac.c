/*
 * slac.c
 *
 *  Created on: 14 Apr 2019
 *      Author: Roque
 */
#include "stdint.h"
#include "string.h"
#include <stdbool.h>
#include "fsl_debug_console.h"

#include "slac/slac.h"
#include "v2g/v2g.h"

/*!
 * @brief Checks if the received destination MAC address of an ETH packet is broadcast:
 * (FF FF FF FF FF FF)
 */
bool checkBroadcastDestMacAddr(uint8_t *frame) {
	for (uint8_t i = 0; i < ETHER_ADDR_LEN; i++) {
		if (frame[i] != 0xFF) {
			return 0;
		}
	}

    return 1;
}

/*!
 * @brief Makes the necessary checks to received SLAC protocol's messages and 
 * produces a response based on the SLAC protocol's state machine. It also registers
 * the EV's MAC address for higher layer communication protocols (IPv6) to interact.
 */
struct slac_rsp_t handleSlacFrame(uint8_t *frame, uint16_t len, uint8_t *dev_mac) {
    uint8_t dest_mac[ETHER_ADDR_LEN];
    struct slac_rsp_t rsp;
    uint16_t rx_msg_id;
    struct charge_session_t charge_session;

    memset(&rsp, 0, sizeof(struct slac_rsp_t));

    /* Check len for ETH header */
    if (len < sizeof(struct ethernet_hdr)) {
        PRINTF("MME message short length\r\n");
    }
	else {
		/* Check destination MAC for this device's or broadcast MAC */
		memcpy(dest_mac, &(frame[0]), ETHER_ADDR_LEN);
		if ((memcmp(dest_mac, dev_mac, ETHER_ADDR_LEN) == 0) || (checkBroadcastDestMacAddr(frame) == 0)) {

			/* Check HPGP protocol */
			if ( (uint16_t)(((uint16_t)frame[13]) | (((uint16_t)frame[12]) << 8)) == HPGP_TYPE_ID ) {

				/* Confirm HPGP header length: V1.0 or V1.1 */
				if (len >= sizeof(struct ethernet_hdr) + sizeof(struct homeplug_hdr) ||
					len >= sizeof(struct ethernet_hdr) + sizeof(struct homeplug_fmi)) {

					rx_msg_id = (uint16_t)(((uint16_t)frame[16]) | (((uint16_t)frame[15]) << 8));

					/* Check received message, create response */
					getSlacRsp(rx_msg_id, frame, &rsp, &charge_session);

					/* Send rsp */
				}

			}


			/* Update EV_DATA structure */
		}
	}

    return rsp;

}

/*!
 * @brief Based on the received message and the previous state of the response, this function
 * will create a new message to be sent according to the SLAC protocol
 */
void getSlacRsp(uint16_t rx_msg_id, uint8_t *rx_frame, struct slac_rsp_t *rsp, struct charge_session_t *charge_session) {
    uint8_t* tx_frame = NULL;

    switch (rx_msg_id) {

    case (CM_SET_KEY | MMTYPE_CNF):
        if (cm_set_key_cnf(rx_frame) == 0) {
            ;
        }

        /* if res != 0, retry again within X seconds */

        break;

    case (CM_SLAC_PARAM | MMTYPE_REQ):
        /* Reset all previous states */
        memset(&(charge_session->slac), 0, sizeof(struct slac_session_t));

        tx_frame = malloc(sizeof(struct cm_slac_param_confirm_t));
        if (cm_slac_param_req(rx_frame, (struct cm_slac_param_confirm_t*)tx_frame, charge_session) == 0) {
            fill_slac_rsp(rsp, tx_frame, sizeof(struct cm_slac_param_confirm_t));
            charge_session->slac.stateFlow.slacParam_ok = 1;
        }

        break;

    case (CM_START_ATTEN_CHAR | MMTYPE_IND):
        if (charge_session->slac.stateFlow.slacParam_ok) {
            if (cm_start_atten_char_ind(rx_frame, charge_session) == 0) {
                charge_session->slac.numAttenCharIndCnt++;

                if (charge_session->slac.numAttenCharIndCnt == NUM_RX_START_ATTEN_CHAR_IND) {
                    charge_session->slac.stateFlow.startAttenChar_ok = 1;
                    charge_session->slac.stateFlow.slacParam_ok = 0;
                }
            }
        }
        break;

    case (CM_MNBC_SOUND | MMTYPE_IND):
        if (charge_session->slac.stateFlow.startAttenChar_ok) {
            if (cm_mnbc_sound_ind(rx_frame, charge_session) == 0) {
                charge_session->slac.numSoundCnt++;

                if (charge_session->slac.numSoundCnt <= NUM_RX_MNBC_SOUNDS_IND) {
                    charge_session->slac.stateFlow.mnbcSound_ok = 1; // trigger AttenProfile after each MNBC sound
                }
            }
        }
        break;

    case (CM_ATTEN_PROFILE | MMTYPE_IND):
        if (charge_session->slac.stateFlow.mnbcSound_ok) {
            // Only react to this message if a MNBC sound was received beforehand
            if(cm_atten_profile_ind(rx_frame, charge_session) == 0) {
                charge_session->slac.numAttenProfileCnt++;

                if (charge_session->slac.numAttenProfileCnt < NUM_RX_MNBC_SOUNDS_IND) {
                    charge_session->slac.stateFlow.mnbcSound_ok = 0; // retrigger MNBC message receive
                }
                else if (charge_session->slac.numAttenProfileCnt == NUM_RX_MNBC_SOUNDS_IND) {
                    tx_frame = malloc(sizeof(struct cm_atten_char_indicate_t));
                    cm_atten_char_ind((struct cm_atten_char_indicate_t*)tx_frame, charge_session);
                    fill_slac_rsp(rsp, tx_frame, sizeof(struct cm_atten_char_indicate_t));
                    charge_session->slac.stateFlow.attenProfile_ok = 1;
                    charge_session->slac.stateFlow.mnbcSound_ok = 0; 
                    charge_session->slac.stateFlow.startAttenChar_ok = 0; // don't allow MNBC trigger message again
                }
            }
        }

        break;

    case (CM_ATTEN_CHAR | MMTYPE_RSP):
        if (charge_session->slac.stateFlow.attenProfile_ok) {
            if (cm_atten_char_rsp(rx_frame, charge_session) == 0) {
                charge_session->slac.stateFlow.attenChar_ok = 1;
                charge_session->slac.stateFlow.attenProfile_ok = 0;
            }
        }
        break;

    case (CM_VALIDATE | MMTYPE_REQ):
        if (charge_session->slac.stateFlow.attenChar_ok) {
            if(cm_validate_req(rx_frame, charge_session) == 0) {
                charge_session->slac.numValidateMsg++;
                if (charge_session->slac.numValidateMsg == 1) {
                    tx_frame = malloc(sizeof(struct cm_validate_confirm_t));
                    cm_validate_cnf((struct cm_validate_confirm_t*)tx_frame, charge_session, 0x00, 0x01);
                    fill_slac_rsp(rsp, tx_frame, sizeof(struct cm_validate_confirm_t));
                }
                else if (charge_session->slac.numValidateMsg == 2) {

                    /* CALL COUNT OF BCB TOGGLES WITHIN :
                        charge_session->timeBCBToggle (in ms) */
                    /* STORE IN :
                    charge_session->numBCBToggles */
                	charge_session->slac.initBCBToggleTimer = 1;

                    /* .... */

                    if (charge_session->slac.BCBTimerOver) {
                        tx_frame = malloc(sizeof(struct cm_validate_confirm_t));
                        cm_validate_cnf((struct cm_validate_confirm_t*)tx_frame, charge_session, charge_session->slac.numBCBToggles, 0x01);
                        fill_slac_rsp(rsp, tx_frame, sizeof(struct cm_validate_confirm_t));

                        charge_session->slac.stateFlow.validate_ok = 1;
                        charge_session->slac.stateFlow.attenChar_ok = 0;
                    }
                }
            
            }

        }

        break;

    case (CM_SLAC_MATCH | MMTYPE_REQ):
        if (charge_session->slac.stateFlow.validate_ok) {
            tx_frame = malloc(sizeof(struct cm_slac_match_confirm_t));
            if (cm_slac_match_req(rx_frame, (struct cm_slac_match_confirm_t*)tx_frame, charge_session) == 0) {
                fill_slac_rsp(rsp, tx_frame, sizeof(struct cm_slac_match_confirm_t));
                charge_session->slac.stateFlow.slacMatch_ok = 1;
                charge_session->slac.stateFlow.validate_ok = 0;
            }
        }

        /* Link Status Request must be called from higher layer, when slacMatch_ok == 1 */
        // link_status_req(charge_session, (struct link_status_req_t*) tx_frame);

        break;

    case (CM_AMP_MAP | MMTYPE_CNF):
        /* NOT IMPLEMENTED */
        break;

    case (CM_AMP_MAP | MMTYPE_REQ):
        /* NOT IMPLEMENTED */
        break;

    case (VS_PL_LINK_STATUS | MMTYPE_CNF):
        if (charge_session->slac.stateFlow.slacMatch_ok) {
            if (link_status_cnf(rx_frame) == 0) {
                charge_session->slac.stateFlow.linkStatus_ok = 1;
                // no need to clear slacMatch_ok for future linkStatus check
            }
        }
        break;

    default:
        break;
    }

    if (tx_frame != NULL) {
        free(tx_frame);
    }
}

void fill_slac_rsp(struct slac_rsp_t *rsp, uint8_t *frame, uint16_t len) {
    rsp->frame = frame;
    rsp->len = len;
}

uint8_t cm_set_key_cnf(uint8_t *rx_frame) {
    struct cm_set_key_confirm_t* cm_set_key_cnf = (struct cm_set_key_confirm_t*)rx_frame;

    /* Checks all contents */
    if (cm_set_key_cnf->RESULT != 0) {
        return 1;
    }

    return 0;
}

uint8_t cm_slac_param_req(uint8_t *rx_frame, struct cm_slac_param_confirm_t *cm_slac_param_cnf, struct charge_session_t *charge_session) {
    struct cm_slac_param_request_t* cm_slac_param_req = (struct cm_slac_param_request_t*)rx_frame;

    /* Checks all contents */
    if (cm_slac_param_req->APPLICATION_TYPE != 0x00) {
        return 1;
    }
    else if (cm_slac_param_req->SECURITY_TYPE != 0x00) {
        return 2;
    }

    /* Store EV data */
    memcpy(charge_session->slac.RunID, cm_slac_param_req->RunID, sizeof(charge_session->slac.RunID));

    /* Response */
    /* Fill in header */
    memcpy(cm_slac_param_cnf->ethernet.ODA, cm_slac_param_req->ethernet.OSA, sizeof(cm_slac_param_cnf->ethernet.ODA));
    memcpy(cm_slac_param_cnf->ethernet.OSA, charge_session->slac.EVSE_MAC_ADDR, sizeof(cm_slac_param_cnf->ethernet.OSA));
    cm_slac_param_cnf->ethernet.MTYPE = HPGP_TYPE_ID;

    cm_slac_param_cnf->homeplug.MMV = HPGP_MMV_1;
    cm_slac_param_cnf->homeplug.MMTYPE = CM_SLAC_PARAM | MMTYPE_CNF;

    /* Fill in body */
    memset(cm_slac_param_cnf->MSOUND_TARGET, 0xFF, sizeof(cm_slac_param_cnf->MSOUND_TARGET));
    cm_slac_param_cnf->NUM_SOUNDS = 0x0A;
    cm_slac_param_cnf->TIME_OUT = 0x06;
    cm_slac_param_cnf->RESP_TYPE = 0x01;
    memcpy(cm_slac_param_cnf->FORWARDING_STA, cm_slac_param_req->ethernet.OSA, sizeof(cm_slac_param_cnf->FORWARDING_STA));
    cm_slac_param_cnf->APPLICATION_TYPE = 0x00;
    cm_slac_param_cnf->SECURITY_TYPE = 0x00;
    memcpy(cm_slac_param_cnf->RunID, cm_slac_param_req->RunID, sizeof(cm_slac_param_cnf->RunID));
    
    return 0;
}

uint8_t cm_start_atten_char_ind(uint8_t *rx_frame, struct charge_session_t *charge_session) {
    struct cm_start_atten_char_indicate_t* cm_start_atten_char_ind = (struct cm_start_atten_char_indicate_t*)rx_frame;

    /* Checks all contents */
    if (cm_start_atten_char_ind->APPLICATION_TYPE != 0x00) {
        return 1;
    }
    else if (cm_start_atten_char_ind->SECURITY_TYPE != 0x00) {
        return 2;
    }
    else if (cm_start_atten_char_ind->ACVarField.NUM_SOUNDS != NUM_RX_MNBC_SOUNDS_IND) {
        return 3;
    }
    else if (cm_start_atten_char_ind->ACVarField.TIME_OUT != 0x06) {
        return 4;
    }
    else if (cm_start_atten_char_ind->ACVarField.RESP_TYPE != 0x01) {
        return 5;
    }
    else if (memcmp(cm_start_atten_char_ind->ACVarField.FORWARDING_STA, charge_session->slac.EV_MAC_ADDR, sizeof(charge_session->slac.EV_MAC_ADDR)) != 0) {
        return 6;
    }
    else if (memcmp(cm_start_atten_char_ind->ACVarField.RunID, charge_session->slac.RunID, sizeof(charge_session->slac.RunID)) != 0) {
        return 6;
    }

    return 0;
}

uint8_t cm_mnbc_sound_ind(uint8_t *rx_frame, struct charge_session_t *charge_session) {
    struct cm_mnbc_sound_indicate_t* cm_mnbc_sound_ind = (struct cm_mnbc_sound_indicate_t*)rx_frame;
    uint8_t bufferSenderId [SLAC_UNIQUE_ID_LEN];

    memset(bufferSenderId, 0x00, sizeof(bufferSenderId));

    /* Checks all contents */
    if (cm_mnbc_sound_ind->APPLICATION_TYPE != 0x00) {
        return 1;
    }
    else if (cm_mnbc_sound_ind->SECURITY_TYPE != 0x00) {
        return 2;
    }
    else if (memcmp(cm_mnbc_sound_ind->MSVarField.SenderID, bufferSenderId, sizeof(bufferSenderId)) != 0) {
        return 3;
    }
    else if (memcmp(cm_mnbc_sound_ind->MSVarField.RunID, charge_session->slac.RunID, sizeof(charge_session->slac.RunID)) != 0) {
        return 4;
    }
    else if (cm_mnbc_sound_ind->MSVarField.RSVD != 0x00) {
        return 5;
    }

    return 0;
}

uint8_t cm_atten_profile_ind(uint8_t *rx_frame, struct charge_session_t *charge_session) {
    struct cm_atten_profile_indicate_t* cm_atten_profile_ind = (struct cm_atten_profile_indicate_t*)rx_frame;
    uint8_t i;

    /* Checks all contents */
    if (memcmp(cm_atten_profile_ind->PEV_MAC, charge_session->slac.EV_MAC_ADDR, sizeof(charge_session->slac.EV_MAC_ADDR)) != 0) {
        return 1;
    }
    if (cm_atten_profile_ind->NumGroups == 0) {
        return 2;
    }

    /* Store Attenuation data */
    /* Sum all attenuations for average calculation later on */
    charge_session->slac.numAttenGroups = cm_atten_profile_ind->NumGroups;
    for (i = 0; i < cm_atten_profile_ind->NumGroups; i++) {
        charge_session->slac.avgGroupAtten[i] = charge_session->slac.avgGroupAtten[i] + cm_atten_profile_ind->AAG[i];
    }
  
    return 0;
}

void cm_atten_char_ind(struct cm_atten_char_indicate_t *cm_atten_char_ind, struct charge_session_t *charge_session) {
    uint8_t i;

    /* Response */
    /* Fill in header */
    memcpy(cm_atten_char_ind->ethernet.ODA, charge_session->slac.EV_MAC_ADDR, sizeof(cm_atten_char_ind->ethernet.ODA));
    memcpy(cm_atten_char_ind->ethernet.OSA, charge_session->slac.EVSE_MAC_ADDR, sizeof(cm_atten_char_ind->ethernet.OSA));
    cm_atten_char_ind->ethernet.MTYPE = HPGP_TYPE_ID;

    cm_atten_char_ind->homeplug.MMV = HPGP_MMV_1;
    cm_atten_char_ind->homeplug.MMTYPE = CM_ATTEN_CHAR | MMTYPE_IND;

    /* Fill in data */
    cm_atten_char_ind->APPLICATION_TYPE = 0x00;
    cm_atten_char_ind->SECURITY_TYPE = 0x00;
    memcpy(cm_atten_char_ind->ACVarField.SOURCE_ADDRESS, charge_session->slac.EV_MAC_ADDR, sizeof(charge_session->slac.EV_MAC_ADDR));
    memcpy(cm_atten_char_ind->ACVarField.RunID, charge_session->slac.RunID, sizeof(cm_atten_char_ind->ACVarField.RunID));
    memset(cm_atten_char_ind->ACVarField.SOURCE_ID, 0x00, sizeof(cm_atten_char_ind->ACVarField.SOURCE_ID));
    memset(cm_atten_char_ind->ACVarField.RESP_ID, 0x00, sizeof(cm_atten_char_ind->ACVarField.RESP_ID));
    cm_atten_char_ind->ACVarField.NUM_SOUNDS = charge_session->slac.numSoundCnt;

    cm_atten_char_ind->ACVarField.ATTEN_PROFILE.NumGroups = charge_session->slac.numAttenGroups;
    for (i = 0; i < charge_session->slac.numAttenGroups; i++) {
        cm_atten_char_ind->ACVarField.ATTEN_PROFILE.AAG[i] = (uint8_t)(charge_session->slac.avgGroupAtten[i] / charge_session->slac.numAttenGroups);
    }

    return;
}

uint8_t cm_atten_char_rsp(uint8_t *rx_frame, struct charge_session_t *charge_session) {
    struct cm_atten_char_response_t* cm_atten_char_rsp = (struct cm_atten_char_response_t*)rx_frame;
    uint8_t bufferId [SLAC_UNIQUE_ID_LEN];

    memset(bufferId, 0x00, sizeof(bufferId));

    /* Checks all contents */
    if (cm_atten_char_rsp->APPLICATION_TYPE != 0x00) {
        return 1;
    }
    else if (cm_atten_char_rsp->SECURITY_TYPE != 0x00) {
        return 2;
    }
    else if (memcmp(cm_atten_char_rsp->ACVarField.SOURCE_ADDRESS, charge_session->slac.EV_MAC_ADDR, sizeof(charge_session->slac.EV_MAC_ADDR)) != 0) {
        return 3;
    }
    else if (memcmp(cm_atten_char_rsp->ACVarField.RunID, charge_session->slac.RunID, sizeof(charge_session->slac.RunID)) != 0) {
        return 4;
    }
    else if (memcmp(cm_atten_char_rsp->ACVarField.SOURCE_ID, bufferId, sizeof(bufferId)) != 0) {
        return 5;
    }
    else if (memcmp(cm_atten_char_rsp->ACVarField.RESP_ID, bufferId, sizeof(bufferId)) != 0) {
        return 6;
    }
    else if (cm_atten_char_rsp->ACVarField.Result != 0x00) {
        return 7;
    }
  
    return 0;
}

uint8_t cm_validate_req(uint8_t *rx_frame, struct charge_session_t *charge_session) {
    struct cm_validate_request_t* cm_validate_req = (struct cm_validate_request_t*)rx_frame;

    /* Checks all contents */
    switch (charge_session->slac.numValidateMsg) {
    case 0:
        /* The first message received */
        if (cm_validate_req->SignalType != 0x00) {
            return 1;
        }
        else if (cm_validate_req->VRVarField.Timer != 0x00) {
            return 2;
        }
        else if (cm_validate_req->VRVarField.Result != 0x01) {
            return 3;
        }

        break;

    case 1:
        /* The second message received */
        if (cm_validate_req->SignalType != 0x00) {
            return 1;
        }
        else if (cm_validate_req->VRVarField.Result != 0x01) {
            return 2;
        }

        /* Store BCB toggle timer */
        charge_session->slac.timeBCBToggle = (cm_validate_req->VRVarField.Timer + 1) * 100; // 0x00 = 100ms; 0x01 = 200ms

        break;
    }

    return 0;
}

void cm_validate_cnf(struct cm_validate_confirm_t *cm_validate_cnf, struct charge_session_t *charge_session, uint8_t toggleNum, uint8_t result) {

    /* Response */
    /* Fill in header */
    memcpy(cm_validate_cnf->ethernet.ODA, charge_session->slac.EV_MAC_ADDR, sizeof(cm_validate_cnf->ethernet.ODA));
    memcpy(cm_validate_cnf->ethernet.OSA, charge_session->slac.EVSE_MAC_ADDR, sizeof(cm_validate_cnf->ethernet.OSA));
    cm_validate_cnf->ethernet.MTYPE = HPGP_TYPE_ID;

    cm_validate_cnf->homeplug.MMV = HPGP_MMV_1;
    cm_validate_cnf->homeplug.MMTYPE = CM_VALIDATE | MMTYPE_CNF;

    /* Fill in data */
    cm_validate_cnf->SignalType = 0x00;
    cm_validate_cnf->VCVarField.ToggleNum = toggleNum;
    cm_validate_cnf->VCVarField.Result = result;

    return;
}

uint8_t cm_slac_match_req(uint8_t *rx_frame, struct cm_slac_match_confirm_t *cm_slac_match_cnf, struct charge_session_t *charge_session) {
    struct cm_slac_match_request_t* cm_slac_match_req = (struct cm_slac_match_request_t*)rx_frame;
    uint8_t bufferId [SLAC_UNIQUE_ID_LEN];

    memset(bufferId, 0x00, sizeof(bufferId));

    /* Checks all contents */
    if (cm_slac_match_req->APPLICATION_TYPE != 0x00) {
        return 1;
    }
    else if (cm_slac_match_req->SECURITY_TYPE != 0x00) {
        return 2;
    }
    else if (memcmp(cm_slac_match_req->MatchVarField.PEV_ID, bufferId, sizeof(bufferId)) != 0) {
        return 3;
    }
    else if (memcmp(cm_slac_match_req->MatchVarField.PEV_MAC, charge_session->slac.EV_MAC_ADDR, sizeof(charge_session->slac.EV_MAC_ADDR)) != 0) {
        return 4;
    }
    else if (memcmp(cm_slac_match_req->MatchVarField.EVSE_ID, bufferId, sizeof(bufferId)) != 0) {
        return 5;
    }
    else if (memcmp(cm_slac_match_req->MatchVarField.EVSE_MAC, charge_session->slac.EVSE_MAC_ADDR, sizeof(charge_session->slac.EVSE_MAC_ADDR)) != 0) {
        return 6;
    }
    else if (memcmp(cm_slac_match_req->MatchVarField.RunID, charge_session->slac.RunID, sizeof(charge_session->slac.RunID)) != 0) {
        return 7;
    }
    else if (cm_slac_match_req->MVFLength != 0x003E) {
        return 8;
    }

    /* Response */
    /* Fill in header */
    memcpy(cm_slac_match_cnf->ethernet.ODA, cm_slac_match_req->ethernet.OSA, sizeof(cm_slac_match_cnf->ethernet.ODA));
    memcpy(cm_slac_match_cnf->ethernet.OSA, charge_session->slac.EVSE_MAC_ADDR, sizeof(cm_slac_match_cnf->ethernet.OSA));
    cm_slac_match_cnf->ethernet.MTYPE = HPGP_TYPE_ID;

    cm_slac_match_cnf->homeplug.MMV = HPGP_MMV_1;
    cm_slac_match_cnf->homeplug.MMTYPE = CM_SLAC_MATCH | MMTYPE_CNF;

    /* Fill in body */
    cm_slac_match_cnf->APPLICATION_TYPE = 0x00;
    cm_slac_match_cnf->SECURITY_TYPE = 0x00;
    cm_slac_match_cnf->MVFLength = 0x0056;
    memset(cm_slac_match_cnf->MatchVarField.PEV_ID, 0x00, sizeof(cm_slac_match_cnf->MatchVarField.PEV_ID));
    memcpy(cm_slac_match_cnf->MatchVarField.PEV_MAC, cm_slac_match_req->ethernet.OSA, sizeof(cm_slac_match_cnf->MatchVarField.PEV_MAC));
    memset(cm_slac_match_cnf->MatchVarField.EVSE_ID, 0x00, sizeof(cm_slac_match_cnf->MatchVarField.EVSE_ID));
    memcpy(cm_slac_match_cnf->MatchVarField.EVSE_MAC, charge_session->slac.EVSE_MAC_ADDR, sizeof(cm_slac_match_cnf->MatchVarField.EVSE_MAC));
    memcpy(cm_slac_match_cnf->MatchVarField.RunID, charge_session->slac.RunID, sizeof(cm_slac_match_cnf->MatchVarField.RunID));

    memset(cm_slac_match_cnf->MatchVarField.NID, 0x00, sizeof(cm_slac_match_cnf->MatchVarField.NID));
    memset(cm_slac_match_cnf->MatchVarField.NMK, 0xFE, sizeof(cm_slac_match_cnf->MatchVarField.NMK));
    
    return 0;
}

void link_status_req(struct charge_session_t *charge_session, struct link_status_req_t *link_status_req) {

    /* Fill in header */
    memset(link_status_req->ethernet.ODA, QCA_MAC, sizeof(link_status_req->ethernet.ODA));
    memcpy(link_status_req->ethernet.OSA, charge_session->slac.EVSE_MAC_ADDR, sizeof(link_status_req->ethernet.OSA));
    link_status_req->ethernet.MTYPE = HPGP_TYPE_ID;

    link_status_req->qualcomm.MMV = HPGP_MMV_0;
    link_status_req->qualcomm.MMTYPE = VS_PL_LINK_STATUS | MMTYPE_REQ;
    memset(link_status_req->qualcomm.OUI, QCA_OUI, sizeof(link_status_req->qualcomm.OUI));

    return;
}

bool link_status_cnf(uint8_t *rx_frame) {
    struct link_status_cnf_t* link_status_cnf = (struct link_status_cnf_t*)rx_frame;

    /* Checks all contents */
    if (link_status_cnf->mmeStatus != 0x00) {
        return 1;
    }
    if (link_status_cnf->linkStatus != 0x01) {
        return 2;
    }

    return 0;
}

