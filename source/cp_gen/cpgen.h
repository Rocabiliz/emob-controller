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

typedef struct cp_gen_t {
    bool enable;
    uint8_t mode;
    uint8_t output;
    double freq;
    double samplingFreq;
    double dutyCycle;
} cp_gen_t;

typedef struct timer_t {
    uint32_t counter;
} timer_t;

/* Functions */
/* CCS related structures and functions */
double calcCCSAcDutyCycle(double maxAcCurr);
double calcCCSPPMaxCurr(double PPresistance, uint8_t nbPhases);
ccs_cp_state_t calcCCSCPState(double cp_voltage);
struct cp_gen_t initCP(charge_mode_t mode, double freq, double dutyCycle, double taskIntFreq);
void setCPFreq(struct cp_gen_t *cp, double freq);
void setCPDutyCycle(struct cp_gen_t *cp, double dutyCycle);
void handleCPGen(struct cp_gen_t *cp, struct timer_t *tmr);

#endif /* CP_GEN_CPGEN_H_ */
