/*
 * cpgen.c
 *
 *  Created on: 5 Apr 2019
 *      Author: Roque
 */

#include "cpgen.h"
#include "pp.h"
#include "gpio.h"
#include "fsl_gpio.h"
#include "fsl_adc16.h"
#include "device/MK66F18.h"
#include "fsl_debug_console.h"
#include "lwip/sys.h"
#include "peripherals.h"

/*!
 * @brief Function (thread) which handles all GPIO inputs
 * All ADCs are read in a sequential way
 */
static void handle_gpio_inputs(void *arg) {
    
    LWIP_UNUSED_ARG(arg);

    TickType_t xStart, xEnd, xDifference;
    PRINTF("## STARTING GPIO READING ##\r\n");

    /* Proximity Pilots Initilization */
    PP_init(&pp1, PROXIMITY_PILOT_1_PIN);
    PP_init(&pp2, PROXIMITY_PILOT_2_PIN);

	while (1) {
        vTaskDelay(pdMS_TO_TICKS(GPIO_READ_TASK_DELAY));
		xStart = xTaskGetTickCount();

        /************************************
         * INPUTS / ADC HANDLING
         * **********************************/
        handle_PP(&pp1);
        handle_PP(&pp2);

		xEnd = xTaskGetTickCount();
		xDifference = xEnd - xStart;
	}
    vTaskDelete(NULL);
}

/*!
 * @brief Function (thread) which handles all GPIO outputs
 * All outputs are set in a sequential way
 */
static void handle_gpio_outputs(void *arg) {
    
    LWIP_UNUSED_ARG(arg);

    TickType_t xStart, xEnd, xDifference;
    PRINTF("## STARTING GPIO WRITING ##\r\n");

    /* Control Pilots Initialization */
    CP_init(&cp1, CCS_DC, CONTROL_PILOT_1_PIN, CCS_CP_FREQ);
    cp1.enable = 1; // testing!

    CP_init(&cp2, CCS_AC, CONTROL_PILOT_2_PIN, CCS_CP_FREQ);
    cp2.enable = 1; // testing!

	while (1) {
		xStart = xTaskGetTickCount();
        
        vTaskDelay(pdMS_TO_TICKS(GPIO_READ_TASK_DELAY)); // TESTING
        /************************************
         * OUTPUTS HANDLING
         * **********************************/
        handle_CP(&cp1);
        handle_CP(&cp2);
        
		xEnd = xTaskGetTickCount();
		xDifference = xEnd - xStart;
	}
    vTaskDelete(NULL);
}

void gpio_init() {

    PRINTF("## GPIO INIT ##\r\n");
    
    if (sys_thread_new("gpio_inputs", handle_gpio_inputs, NULL, 200, 5) == NULL) {
		PRINTF("handle_gpio_inputs thread failed\r\n");
	}
    if (sys_thread_new("handle_gpio_outputs", handle_gpio_outputs, NULL, 200, 5) == NULL) {
		PRINTF("handle_gpio_outputs thread failed\r\n");
	}
    PRINTF("## GPIO OUT ##\r\n");

}

/*!
 * @brief Function for handling FTM0 timer interrupt
 * This particular timer will generate the Control Pilot PWM signals
 */
void FTM0_IRQHANDLER(void) {

    // Control Pilot 1
    //handle_CP_gen(&cp1);
    /*static uint8_t dutyCycle = 0;

    if (dutyCycle >= 49) {
        dutyCycle = 0;
    }
    else {
        dutyCycle++;
    }
    dutyCycle = 5;
    //GPIO_PinWrite(BOARD_SW3_GPIO, CONTROL_PILOT_1_PIN, cp1.output);
    FTM_DisableInterrupts(FTM0_PERIPHERAL, kFTM_Chnl1InterruptEnable);
    FTM_UpdatePwmDutycycle(FTM0_PERIPHERAL, kFTM_Chnl_1, kFTM_CenterAlignedPwm, dutyCycle);
    FTM_SetSoftwareTrigger(FTM0_PERIPHERAL, true);
    FTM_UpdateChnlEdgeLevelSelect(FTM0_PERIPHERAL, kFTM_Chnl_1, kFTM_HighTrue);
    FTM_EnableInterrupts(FTM0_PERIPHERAL, kFTM_Chnl1InterruptEnable);*/

    // Control Pilot 2
    //handle_CP_gen(&cp2);
    //GPIO_PinWrite(BOARD_SW3_GPIO, CONTROL_PILOT_2_PIN, cp2.output);

    /* Clear interrupt flag.*/
    FTM_ClearStatusFlags(FTM0, kFTM_TimeOverflowFlag);
}