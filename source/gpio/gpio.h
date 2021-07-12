/*
 * cpgen.h
 *
 *  Created on: 5 Apr 2019
 *      Author: Roque
 */

#ifndef GPIO_GPIO_H_
#define GPIO_GPIO_H_

#include "cpgen.h"
#include "pp.h"
#include "stdint.h"

/* PP related defined */
#define GPIO_READ_TASK_DELAY 50UL // in ms

// Variables
extern struct pp_t pp1, pp2;
extern struct cp_gen_t cp1, cp2;

// Functions
void gpio_init();

#endif /* GPIO_GPIO_H_ */
