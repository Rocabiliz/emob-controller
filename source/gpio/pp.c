/*
 * cpgen.c
 *
 *  Created on: 5 Apr 2019
 *      Author: Roque
 */

#include "pp.h"
#include <string.h>
#include "fsl_gpio.h"
#include "fsl_adc16.h"
#include "device/MK66F18.h"
#include "fsl_debug_console.h"
#include "lwip/sys.h"
#include "peripherals.h"
#include "charger/charger.h"

const uint32_t g_Adc16_12bitFullRange = 4096U;

/*!
 * @brief Calculates duty cycle for AC CCS according to IEC 61851-1/Table A.6
 */
double calc_ccs_ac_dutycyle(double maxAcCurr) {

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
double calc_ccs_pp_max_curr(double ppResistance, uint8_t nbPhases) {

    double maxCurr = 0.0;
    // Considering the tolerance in the standard
    if ((ppResistance >= 1500 - 1500*CCS_PP_RESISTANCE_TOLERANCE) && 
        (ppResistance <= 1500 + 1500*CCS_PP_RESISTANCE_TOLERANCE)) {
        maxCurr = 13.0;
    }
    else if ((ppResistance >= 680 - 680*CCS_PP_RESISTANCE_TOLERANCE) && 
            (ppResistance <= 680 + 680*CCS_PP_RESISTANCE_TOLERANCE)) {
        maxCurr = 20.0;
    }
    else if ((ppResistance >= 220 - 220*CCS_PP_RESISTANCE_TOLERANCE) && 
            (ppResistance <= 220 + 220*CCS_PP_RESISTANCE_TOLERANCE)) {
        maxCurr = 32.0;
    }
    else if ((ppResistance >= 100 - 100*CCS_PP_RESISTANCE_TOLERANCE) && 
            (ppResistance <= 100 + 100*CCS_PP_RESISTANCE_TOLERANCE)) {
        if (nbPhases == 1) {
            maxCurr = 70.0;
        }
        else if (nbPhases == 3) {
            maxCurr = 63.0;
        }
        else {
            maxCurr = 0.0;
        }
    }

    return maxCurr;
}

void handle_PP(struct pp_t *pp) {

    ADC16_SetChannelConfig(DEMO_ADC16_BASE, DEMO_ADC16_CHANNEL_GROUP, &pp->ppAdc);
    while ((kADC16_ChannelConversionDoneFlag &
            ADC16_GetChannelStatusFlags(DEMO_ADC16_BASE, DEMO_ADC16_CHANNEL_GROUP)) == 0U) {
    }

    pp->ppVoltage = ((double)ADC16_GetChannelConversionValue(DEMO_ADC16_BASE, DEMO_ADC16_CHANNEL_GROUP)) * 3.3F / g_Adc16_12bitFullRange;
    
    PRINTF("PP VOLTAGE VALUE: %f\r\n", pp->ppVoltage);
    pp->maxCurr = calc_ccs_pp_max_curr(pp->ppVoltage * PP_VOLTAGE_DIVIDER_RATIO, charge_session.charger.ac_nb_phases);

    return;
}

void PP_init(struct pp_t *pp, uint32_t channelNb) {
    adc16_config_t adc16ConfigStruct;

    ADC16_GetDefaultConfig(&adc16ConfigStruct);
#ifdef BOARD_ADC_USE_ALT_VREF
    adc16ConfigStruct.referenceVoltageSource = kADC16_ReferenceVoltageSourceValt;
#endif
    ADC16_Init(DEMO_ADC16_BASE, &adc16ConfigStruct);
    ADC16_EnableHardwareTrigger(DEMO_ADC16_BASE, false); /* Make sure the software trigger is used. */
#if defined(FSL_FEATURE_ADC16_HAS_CALIBRATION) && FSL_FEATURE_ADC16_HAS_CALIBRATION
    if (kStatus_Success == ADC16_DoAutoCalibration(DEMO_ADC16_BASE)) {
        PRINTF("ADC16_DoAutoCalibration() Done.\r\n");
    }
    else {
        PRINTF("ADC16_DoAutoCalibration() Failed.\r\n");
    }
#endif /* FSL_FEATURE_ADC16_HAS_CALIBRATION */

    PRINTF("ADC Full Range: %d\r\n", g_Adc16_12bitFullRange);

    pp->ppAdc.channelNumber                        = channelNb;
    pp->ppAdc.enableInterruptOnConversionCompleted = false;
#if defined(FSL_FEATURE_ADC16_HAS_DIFF_MODE) && FSL_FEATURE_ADC16_HAS_DIFF_MODE
    pp->ppAdc.enableDifferentialConversion = false;
#endif /* FSL_FEATURE_ADC16_HAS_DIFF_MODE */

}

