/*
 * cpgen.c
 *
 *  Created on: 5 Apr 2019
 *      Author: Roque
 */

#include "cpgen.h"
#include <string.h>
#include "fsl_gpio.h"
#include "fsl_adc16.h"
#include "device/MK66F18.h"
#include "fsl_debug_console.h"
#include "lwip/sys.h"
#include "peripherals.h"

/*!
 * @brief CCS CP state according to IEWC 61851-1/Table A.3
 */
void calc_CP_state(struct cp_gen_t *cp, double cpVoltage) {

    if ((cpVoltage >= CPSTATE_A_MIN_VOLTAGE) && (cpVoltage <= CPSTATE_A_MAX_VOLTAGE)) {
        cp->cpState = A;
    }
    else if ((cpVoltage >= CPSTATE_B_MIN_VOLTAGE) && (cpVoltage <= CPSTATE_B_MAX_VOLTAGE)) {
        cp->cpState = B;
    }
    else if ((cpVoltage >= CPSTATE_C1_MIN_VOLTAGE) && (cpVoltage <= CPSTATE_C1_MAX_VOLTAGE)) {
        cp->cpState = C1;
    }
    else if ((cpVoltage >= CPSTATE_C2_MIN_VOLTAGE) && (cpVoltage <= CPSTATE_C2_MAX_VOLTAGE)) {
        cp->cpState = C2;
    }
    else if ((cpVoltage >= CPSTATE_D_MIN_VOLTAGE) && (cpVoltage <= CPSTATE_D_MAX_VOLTAGE)) {
        cp->cpState = D;
    }
    else if ((cpVoltage >= CPSTATE_E_MIN_VOLTAGE) && (cpVoltage <= CPSTATE_E_MAX_VOLTAGE)) {
        cp->cpState = E;
    }
    else {
        cp->cpState = UNKNOWN;
    }
}

/*!
 * @brief Initializes a CP struct with the configuration
 */
void CP_init(struct cp_gen_t *cp, charge_mode_t mode, uint32_t pinNumber,
            double freq) {

    cp->mode = (uint8_t)mode;
    cp->freq = freq;
    cp->gpio.pinDirection = kGPIO_DigitalOutput;
    cp->gpio.outputLogic = 0; 
    GPIO_PinInit(BOARD_SW3_GPIO, pinNumber, &cp->gpio);
}

/*!
 * @brief Enabler for Control Pilot, with custom duty cycle. 
 * This can also be used to simply update the duty cycle in AC mode
 */
void CP_enable(struct cp_gen_t *cp, double dutyCycle) {

    switch (cp->mode) {
    case UNDEFINED:
        memset(cp, 0, sizeof(struct cp_gen_t));
        break;
        
    case CCS_AC:
        if ((dutyCycle >= MIN_CP_DUTY_CYCLE) && (dutyCycle <= MAX_CP_DUTY_CYCLE)) {
            cp->dutyCycle = dutyCycle;
        }
        else {
            cp->dutyCycle = 0;
        }
        break;

    case CCS_DC:
        cp->dutyCycle = CCS_DC_DUTY_CYCLE;
        break;

    default:
        cp->dutyCycle = 0;
        break;
    }

    cp->enable = 1;
}

/*!
 * @brief Disabler for Control Pilot, stopping the PWM output. 
 */
void CP_disable(struct cp_gen_t *cp) {

    cp->enable = 0;
    cp->dutyCycle = 0;
}

void handle_CP(struct cp_gen_t *cp) {
    
    /* TESTING */
    static uint8_t dutyCycle = 0;
    if (dutyCycle >= 89) {
        dutyCycle = 0;
    }
    else {
        dutyCycle = dutyCycle + 10;
    }
    /* TESTING */

    FTM_DisableInterrupts(FTM0_PERIPHERAL, kFTM_TimeOverflowInterruptEnable);
    FTM_UpdateChnlEdgeLevelSelect(FTM0_PERIPHERAL, kFTM_Chnl_1, 0U);
    //FTM_UpdatePwmDutycycle(FTM0_PERIPHERAL, kFTM_Chnl_1, kFTM_EdgeAlignedPwm, cp->dutyCycle);
    FTM_UpdatePwmDutycycle(FTM0_PERIPHERAL, kFTM_Chnl_1, kFTM_EdgeAlignedPwm, dutyCycle);
    FTM_SetSoftwareTrigger(FTM0_PERIPHERAL, true);
    FTM_UpdateChnlEdgeLevelSelect(FTM0_PERIPHERAL, kFTM_Chnl_1, kFTM_HighTrue);
    FTM_EnableInterrupts(FTM0_PERIPHERAL, kFTM_TimeOverflowInterruptEnable);
}
