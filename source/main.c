/*
 * Copyright (c) 2016, Freescale Semiconductor, Inc.
 * Copyright 2016-2019 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*******************************************************************************
 * Includes
 ******************************************************************************/
/* General */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>

/* FreeRTOS kernel includes. */
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "timers.h"
#include "portable.h"

/* Freescale includes. */
#include "fsl_device_registers.h"
#include "fsl_debug_console.h"
#include "board.h"
#include "pin_mux.h"
#include "clock_config.h"

/* Peripherals include */
#include "peripherals.h"
#include "fsl_ftm.h"
#include "fsl_gpio.h"

/* Software components includes */
#include "cp_gen/cpgen.h"
#include "slac/slac.h"
#include "v2g/v2g.h"
#include "charger/charger.h"
#include "webserver/webserver.h"

/* lwip include */
#include "lwip/opt.h"
#include "lwip/netif.h"
#include "lwip/sys.h"
#include "lwip/arch.h"
#include "lwip/api.h"
#include "lwip/tcpip.h"
#include "lwip/ip.h"
#include "lwip/netifapi.h"
#include "lwip/sockets.h"
#include "netif/etharp.h"
#include "enet_ethernetif.h"
#include "httpsrv.h"
#include "mdns.h"

/* mbed tls */
#include "ksdk_mbedtls.h"
#include "mbedtls/certs.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define BOARD_SW_GPIO BOARD_SW3_GPIO
#define BOARD_SW_GPIO_PIN BOARD_SW3_GPIO_PIN

/*******************************************************************************
 * Variables
 ******************************************************************************/
struct charge_session_t charge_session;
struct cp_gen_t cp1;

/* IP address configuration. */
#define configIP_ADDR0 192
#define configIP_ADDR1 168
#define configIP_ADDR2 1
#define configIP_ADDR3 144

/* Netmask configuration. */
#define configNET_MASK0 255
#define configNET_MASK1 255
#define configNET_MASK2 255
#define configNET_MASK3 0

/* Gateway address configuration. */
#define configGW_ADDR0 192
#define configGW_ADDR1 168
#define configGW_ADDR2 1
#define configGW_ADDR3 1

/* MAC address configuration. */
#define configMAC_ADDR                     \
    {                                      \
        0x02, 0x12, 0x13, 0x10, 0x15, 0x11 \
    }

/* Address of PHY interface. */
#define EXAMPLE_PHY_ADDRESS BOARD_ENET0_PHY_ADDRESS

/* System clock name. */
#define EXAMPLE_CLOCK_NAME kCLOCK_CoreSysClk

#if defined(FSL_FEATURE_SOC_LPC_ENET_COUNT) && (FSL_FEATURE_SOC_LPC_ENET_COUNT > 0)
static mem_range_t non_dma_memory[] = NON_DMA_MEMORY_ARRAY;
#endif /* FSL_FEATURE_SOC_LPC_ENET_COUNT */
/* FS data.*/

/*!
* @brief Function for handling FTM0 timer interrupt
* This particular timer will generate the Control Pilot PWM signals
 */
void FTM0_IRQHANDLER(void) {
    
    handle_CP_gen(&cp1);
    GPIO_PinWrite(BOARD_SW3_GPIO, CONTROL_PILOT_1_PIN, cp1.output);

    /* Clear interrupt flag.*/
    FTM_ClearStatusFlags(FTM0, kFTM_TimeOverflowFlag);
}

/*!
 * @brief Main function.
 */
int main(void) {
    PRINTF("Starting APP!\r\n");

    CRYPTO_InitHardware();

    SYSMPU_Type *base = SYSMPU;
    BOARD_InitPins();
    BOARD_BootClockRUN();
    BOARD_InitDebugConsole();
    BOARD_InitBootPeripherals();

    /* Control Pilots Initialization */
    CP_init(&cp1, CCS_DC, CCS_CP_FREQ, 50, 100000); // sampling is interrupt frequency (> signal frequency)
    GPIO_PinInit(BOARD_SW3_GPIO, 27U, &cp1.gpio);
    cp1.enable = 1; // testing!

    /* Disable SYSMPU. */
    base->CESR &= ~SYSMPU_CESR_VLD_MASK;
    /* Set RMII clock src. */
    SIM->SOPT2 |= SIM_SOPT2_RMIISRC_MASK;

    static struct netif netif;
	ip4_addr_t netif_ipaddr, netif_netmask, netif_gw;
	ethernetif_config_t enet_config = {
			.phyAddress = EXAMPLE_PHY_ADDRESS,
			.clockName  = EXAMPLE_CLOCK_NAME,
			.macAddress = configMAC_ADDR,
#if defined(FSL_FEATURE_SOC_LPC_ENET_COUNT) && (FSL_FEATURE_SOC_LPC_ENET_COUNT > 0)
            .non_dma_memory = non_dma_memory,
#endif /* FSL_FEATURE_SOC_LPC_ENET_COUNT */
	};

	tcpip_init(NULL, NULL);

	IP4_ADDR(&netif_ipaddr, configIP_ADDR0, configIP_ADDR1, configIP_ADDR2, configIP_ADDR3);
	IP4_ADDR(&netif_netmask, configNET_MASK0, configNET_MASK1, configNET_MASK2, configNET_MASK3);
	IP4_ADDR(&netif_gw, configGW_ADDR0, configGW_ADDR1, configGW_ADDR2, configGW_ADDR3);

	netifapi_netif_add(&netif, &netif_ipaddr, &netif_netmask, &netif_gw, &enet_config, ethernetif0_init, tcpip_input);
	netifapi_netif_set_default(&netif);
	netifapi_netif_set_up(&netif);
	netif_create_ip6_linklocal_address(&netif, 1);
    
    /*mdns_resp_init();
    mdns_resp_add_netif(&netif, MDNS_HOSTNAME, 60);
    mdns_resp_add_service(&netif, MDNS_HOSTNAME, "_http", DNSSD_PROTO_TCP, 80, 300, http_srv_txt, NULL);*/

    PRINTF("\r\n************************************************\r\n");
    PRINTF(" TCP Echo example\r\n");
    PRINTF("************************************************\r\n");
    PRINTF(" IPv4 Address     : %u.%u.%u.%u\r\n", ((u8_t *)&netif_ipaddr)[0], ((u8_t *)&netif_ipaddr)[1],
           ((u8_t *)&netif_ipaddr)[2], ((u8_t *)&netif_ipaddr)[3]);
    PRINTF(" IPv4 Subnet mask : %u.%u.%u.%u\r\n", ((u8_t *)&netif_netmask)[0], ((u8_t *)&netif_netmask)[1],
           ((u8_t *)&netif_netmask)[2], ((u8_t *)&netif_netmask)[3]);
    PRINTF(" IPv4 Gateway     : %u.%u.%u.%u\r\n", ((u8_t *)&netif_gw)[0], ((u8_t *)&netif_gw)[1],
           ((u8_t *)&netif_gw)[2], ((u8_t *)&netif_gw)[3]);
    PRINTF("************************************************\r\n");
  
    // Load EVSE Charger configuration
    load_charger_config(&netif.ip6_addr[0].u_addr.ip6.addr); // 20kb

    //webserver_init(); // will only work with 222E0 HEAP size (140KB)~
    v2g_init();

    /* run RTOS */
    vTaskStartScheduler();
    PRINTF("OOOPS\r\n");

    /* should not reach this statement */
    for (;;)
        ;
}

void vApplicationStackOverflowHook( TaskHandle_t *pxTask, signed char *pcTaskName ){
    PRINTF("[FREE-RTOS-DEBUG] Stack Overflow detection in Task %s", pcTaskName);
}
