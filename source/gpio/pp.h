/*
 * cpgen.h
 *
 *  Created on: 5 Apr 2019
 *      Author: Roque
 */

#ifndef PP_GPIO_H_
#define PP_GPIO_H_

#include "stdint.h"
#include "stdbool.h"
#include "board.h"
#include "fsl_adc16.h"

/* Pinout related */
#define PROXIMITY_PILOT_1_PIN 19U
#define PROXIMITY_PILOT_2_PIN 27U
#define DEMO_ADC16_BASE ADC0
#define DEMO_ADC16_CHANNEL_GROUP 0U

/* PP related defined */
#define PP_READ_VOLT_PERIOD 500UL // in ms
#define CCS_PP_RESISTANCE_TOLERANCE 0.03
#define PP_VOLTAGE_DIVIDER_RATIO 1100 // voltage divider ratio

/* Structs */
struct pp_t {
    double ppVoltage;
    double maxCurr;
    adc16_channel_config_t ppAdc;
};

/* Functions */
/* CCS related structures and functions */
double calc_ccs_ac_dutycyle(double maxAcCurr);
double calc_ccs_pp_max_curr(double PPresistance, uint8_t nbPhases);
void PP_init(struct pp_t *pp, uint32_t channelNb);
void handle_PP(struct pp_t *pp);

#endif /* PP_GPIO_H_ */
