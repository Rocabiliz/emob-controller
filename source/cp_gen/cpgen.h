/*
 * cpgen.h
 *
 *  Created on: 5 Apr 2019
 *      Author: Roque
 */

#ifndef CP_GEN_CPGEN_H_
#define CP_GEN_CPGEN_H_

#include "stdint.h"
#include "stdbool.h"
#include "board.h"
#include "fsl_gpio.h"

/* Pinout related */
#define CONTROL_PILOT_1_PIN 27U
#define CONTROL_PILOT_2_PIN 26U

/* CP related defines */
#define MIN_CP_FREQ 0
#define MAX_CP_FREQ 2000
#define MIN_CP_DUTY_CYCLE 0
#define MAX_CP_DUTY_CYCLE 100

/* CCS related */
#define CCS_CP_FREQ 1000
#define CCS_DC_DUTY_CYCLE 5
#define CCS_AC_MIN_DUTYCYCLE 10
#define CCS_AC_MAX_DUTYCYCLE 96
#define CCS_PP_RESISTANCE_TOLERANCE 0.03
#define CPSTATE_A_MIN_VOLTAGE 11
#define CPSTATE_A_MAX_VOLTAGE 13
#define CPSTATE_B_MIN_VOLTAGE 8
#define CPSTATE_B_MAX_VOLTAGE 10
#define CPSTATE_C1_MIN_VOLTAGE 5
#define CPSTATE_C1_MAX_VOLTAGE 7
#define CPSTATE_C2_MIN_VOLTAGE 2
#define CPSTATE_C2_MAX_VOLTAGE 4
#define CPSTATE_D_MIN_VOLTAGE -1
#define CPSTATE_D_MAX_VOLTAGE 1
#define CPSTATE_E_MIN_VOLTAGE -13
#define CPSTATE_E_MAX_VOLTAGE -11

/* Structs */
enum charge_mode {UNDEFINED,CCS_AC,CCS_DC,GBT,CHADEMO};
typedef enum charge_mode charge_mode_t;
enum ccs_cp_state {UNKNOWN,A,B,C1,C2,D,E,F};
typedef enum ccs_cp_state ccs_cp_state_t;

struct cp_gen_t {
    bool enable;
    uint8_t mode;
    uint8_t output;
    uint32_t freq;
    uint32_t samplingFreq;
    uint32_t dutyCycle; // in %
    uint32_t counter;
    gpio_pin_config_t gpio;
};


/* Functions */
/* CCS related structures and functions */
double calc_ccs_ac_dutycyle(double maxAcCurr);
double calc_ccs_pp_max_curr(double PPresistance, uint8_t nbPhases);
ccs_cp_state_t calc_CP_state(double cp_voltage);
void CP_init(struct cp_gen_t *cp, charge_mode_t mode, uint32_t pinNumber, double freq, double dutyCycle, double taskIntFreq);
void set_CP_freq(struct cp_gen_t *cp, double freq);
void set_CP_dutycycle(struct cp_gen_t *cp, double dutyCycle);
void handle_CP_gen(struct cp_gen_t *cp);

#endif /* CP_GEN_CPGEN_H_ */
