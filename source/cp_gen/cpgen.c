/*
 * cpgen.c
 *
 *  Created on: 5 Apr 2019
 *      Author: Roque
 */

#include "cpgen.h"
#include <string.h>

/* Assigns a specific output to a new instance of a cp_gen, setups a specific timer */

/*!
 * @brief Calculates duty cycle for AC CCS according to IEC 61851-1/Table A.6
 */
double calcCCSAcDutyCycle(double maxAcCurr) {

    if (maxAcCurr >= 6 && maxAcCurr <= 51) {
        return maxAcCurr / 0.6;
    }
    else if (maxAcCurr > 51 && maxAcCurr < 80) {
        return (maxAcCurr / 2.5) + 64.0;
    }
    else return 0; // or return 100?
}

/*!
 * @brief Calculates cable maximum current based on the proximity resistance 
 * for AC CCS according to IEC 61851-1/Table B.3
 */
double calcCCSPPMaxCurr(double ppResistance, uint8_t nbPhases) {

    // Considering the tolerance in the standard
    if ((ppResistance >= 1500 - 1500*CCS_PP_RESISTANCE_TOLERANCE) && 
        (ppResistance <= 1500 + 1500*CCS_PP_RESISTANCE_TOLERANCE)) {
        return 13;
    }
    else if ((ppResistance >= 680 - 680*CCS_PP_RESISTANCE_TOLERANCE) && 
            (ppResistance <= 680 + 680*CCS_PP_RESISTANCE_TOLERANCE)) {
        return 20;
    }
    else if ((ppResistance >= 220 - 220*CCS_PP_RESISTANCE_TOLERANCE) && 
            (ppResistance <= 220 + 220*CCS_PP_RESISTANCE_TOLERANCE)) {
        return 32;
    }
    else if ((ppResistance >= 100 - 100*CCS_PP_RESISTANCE_TOLERANCE) && 
            (ppResistance <= 100 + 100*CCS_PP_RESISTANCE_TOLERANCE)) {
        if (nbPhases == 1) {
            return 70;
        }
        else if (nbPhases == 3) {
            return 63;
        }
        else return 0;
    }
    else return 0;
}

/*!
 * @brief CCS CP state according to IEWC 61851-1/Table A.3
 */
ccs_cp_state_t calcCCSCPState(double cpVoltage) {

    if ((cpVoltage >= CPSTATE_A_MIN_VOLTAGE) && (cpVoltage <= CPSTATE_A_MAX_VOLTAGE)) {
        return A;
    }
    else if ((cpVoltage >= CPSTATE_B_MIN_VOLTAGE) && (cpVoltage <= CPSTATE_B_MAX_VOLTAGE)) {
        return B;
    }
    else if ((cpVoltage >= CPSTATE_C1_MIN_VOLTAGE) && (cpVoltage <= CPSTATE_C1_MAX_VOLTAGE)) {
        return C1;
    }
    else if ((cpVoltage >= CPSTATE_C2_MIN_VOLTAGE) && (cpVoltage <= CPSTATE_C2_MAX_VOLTAGE)) {
        return C2;
    }
    else if ((cpVoltage >= CPSTATE_D_MIN_VOLTAGE) && (cpVoltage <= CPSTATE_D_MAX_VOLTAGE)) {
        return D;
    }
    else if ((cpVoltage >= CPSTATE_E_MIN_VOLTAGE) && (cpVoltage <= CPSTATE_E_MAX_VOLTAGE)) {
        return E;
    }
    else return UNKNOWN;
}

/*!
 * @brief Initializes a CP struct with the configuration
 */
struct cp_gen_t initCP(charge_mode_t mode, double freq, double dutyCycle, double taskIntFreq) {
    struct cp_gen_t cp;

    cp.mode = (uint8_t)mode;
    cp.freq = freq;
    cp.samplingFreq = taskIntFreq;

    switch (mode) {
    case UNDEFINED:
        memset(&cp, 0, sizeof(cp));
        break;
        
    case CCS_AC:
        cp.dutyCycle = dutyCycle;
        break;

    case CCS_DC:
        cp.dutyCycle = CCS_DC_DUTY_CYCLE;
        break;

    default:
    	cp.dutyCycle = 0;
    	break;
    }

    return cp;
}

/*!
 * @brief Setter function for CP frequency
 */
void setCPFreq(struct cp_gen_t *cp, double freq) {

    if (freq >= MIN_CP_FREQ && freq <= MAX_CP_FREQ) {
        cp->freq = freq;
    }
}

/*!
 * @brief Setter function for CP duty cycle
 */
void setCPDutyCycle(struct cp_gen_t *cp, double dutyCycle) {

    if (dutyCycle >= MIN_CP_DUTY_CYCLE && dutyCycle <= MAX_CP_DUTY_CYCLE) {
        cp->dutyCycle = dutyCycle;
    }
}


/*!
 * @brief Handles the CP generation based on the mode. Multiple instances
 * of this function (in threads) may be running. It is assumed that the 'tmr'
 * interruption calls this function, which will clear the flag 'tmr.tmrFlag'
 * in order to reset the timer count.
 */
void handleCPGen(struct cp_gen_t *cp, struct timer_t *tmr) {

    if (cp->enable) {

        switch (cp->mode) {
        case UNDEFINED:
            tmr->counter = 0;
            cp->output = 0;
            break;

        /* CCS AC and DC apply a simple PWM */
        case CCS_AC:
        case CCS_DC:
            tmr->counter++;
            
            /* Dutycycle pulse */
            if (tmr->counter <= (uint32_t)((cp->dutyCycle*cp->freq)/cp->samplingFreq)) { // + 1??
                cp->output = 1;
            }
            /* Remainder of the wave */
            else if (tmr->counter <= (uint32_t)(cp->freq/cp->samplingFreq)) { // + 1??
                cp->output = 0;
            }
            /* Full period: reset counter*/
            else {
            	tmr->counter = 0;
            }

            break;
        }

    }
    else {
        cp->output = 0;
        tmr->counter = 0;
    }

    return;
}
