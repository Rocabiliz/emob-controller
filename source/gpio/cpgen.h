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
#define BOARD_SW_GPIO BOARD_SW3_GPIO
#define BOARD_SW_GPIO_PIN BOARD_SW3_GPIO_PIN
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
typedef enum charge_mode {UNDEFINED,CCS_AC,CCS_DC,GBT,CHADEMO} charge_mode_t;
typedef enum ccs_cp_state {UNKNOWN,A,B,C1,C2,D,E,F} ccs_cp_state_t;

struct cp_gen_t {
    bool enable;
    uint8_t mode;
    uint32_t freq;
    uint32_t dutyCycle;
    ccs_cp_state_t cpState; 
    gpio_pin_config_t gpio;
};

/* Functions */
/* CCS related structures and functions */
void calc_CP_state(struct cp_gen_t *cp, double cpVoltage);
void CP_init(struct cp_gen_t *cp, charge_mode_t mode, uint32_t pinNumber, double freq);
void CP_enable(struct cp_gen_t *cp, double dutyCycle);
void CP_disable(struct cp_gen_t *cp);
void handle_CP(struct cp_gen_t *cp);

#endif /* CP_GEN_CPGEN_H_ */
