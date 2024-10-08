/***********************************************************************************************************************
 * This file was generated by the MCUXpresso Config Tools. Any manual edits made to this file
 * will be overwritten if the respective MCUXpresso Config Tools is used to update this file.
 **********************************************************************************************************************/

/* clang-format off */
/*
 * TEXT BELOW IS USED AS SETTING FOR TOOLS *************************************
!!GlobalInfo
product: Pins v7.0
processor: MK66FN2M0xxx18
package_id: MK66FN2M0VMD18
mcu_data: ksdk2_0
processor_version: 7.0.1
board: FRDM-K66F
 * BE CAREFUL MODIFYING THIS COMMENT - IT IS YAML SETTINGS FOR TOOLS ***********
 */
/* clang-format on */

#include "fsl_common.h"
#include "fsl_port.h"
#include "pin_mux.h"

/* FUNCTION ************************************************************************************************************
 *
 * Function Name : BOARD_InitBootPins
 * Description   : Calls initialization functions.
 *
 * END ****************************************************************************************************************/
void BOARD_InitBootPins(void)
{
    BOARD_InitPins();
}

/* clang-format off */
/*
 * TEXT BELOW IS USED AS SETTING FOR TOOLS *************************************
BOARD_InitPins:
- options: {callFromInitBoot: 'true', coreID: core0, enableClock: 'true'}
- pin_list:
  - {pin_num: E10, peripheral: UART0, signal: RX, pin_signal: TSI0_CH9/PTB16/SPI1_SOUT/UART0_RX/FTM_CLKIN0/FB_AD17/SDRAM_D17/EWM_IN/TPM_CLKIN0}
  - {pin_num: E9, peripheral: UART0, signal: TX, pin_signal: TSI0_CH10/PTB17/SPI1_SIN/UART0_TX/FTM_CLKIN1/FB_AD16/SDRAM_D16/EWM_OUT_b/TPM_CLKIN1}
  - {pin_num: K9, peripheral: ENET, signal: MII_RXD1, pin_signal: CMP2_IN0/PTA12/CAN0_TX/FTM1_CH0/RMII0_RXD1/MII0_RXD1/I2C2_SCL/I2S0_TXD0/FTM1_QD_PHA/TPM1_CH0}
  - {pin_num: J9, peripheral: ENET, signal: MII_RXD0, pin_signal: CMP2_IN1/PTA13/LLWU_P4/CAN0_RX/FTM1_CH1/RMII0_RXD0/MII0_RXD0/I2C2_SDA/I2S0_TX_FS/FTM1_QD_PHB/TPM1_CH1}
  - {pin_num: L10, peripheral: ENET, signal: MII_RXDV, pin_signal: PTA14/SPI0_PCS0/UART0_TX/RMII0_CRS_DV/MII0_RXDV/I2C2_SCL/I2S0_RX_BCLK/I2S0_TXD1}
  - {pin_num: L11, peripheral: ENET, signal: MII_TXEN, pin_signal: CMP3_IN1/PTA15/SPI0_SCK/UART0_RX/RMII0_TXEN/MII0_TXEN/I2S0_RXD0}
  - {pin_num: K10, peripheral: ENET, signal: MII_TXD0, pin_signal: CMP3_IN2/PTA16/SPI0_SOUT/UART0_CTS_b/UART0_COL_b/RMII0_TXD0/MII0_TXD0/I2S0_RX_FS/I2S0_RXD1}
  - {pin_num: K11, peripheral: ENET, signal: MII_TXD1, pin_signal: ADC1_SE17/PTA17/SPI0_SIN/UART0_RTS_b/RMII0_TXD1/MII0_TXD1/I2S0_MCLK}
  - {pin_num: M8, peripheral: ENET, signal: MII_RXER, pin_signal: PTA5/USB0_CLKIN/FTM0_CH2/RMII0_RXER/MII0_RXER/CMP2_OUT/I2S0_TX_BCLK/JTAG_TRST_b}
  - {pin_num: H10, peripheral: ENET, signal: MII_MDIO, pin_signal: ADC0_SE8/ADC1_SE8/TSI0_CH0/PTB0/LLWU_P5/I2C0_SCL/FTM1_CH0/RMII0_MDIO/MII0_MDIO/SDRAM_CAS_b/FTM1_QD_PHA/TPM1_CH0,
    slew_rate: fast, open_drain: enable, drive_strength: low, pull_select: down, pull_enable: disable}
  - {pin_num: H9, peripheral: ENET, signal: MII_MDC, pin_signal: ADC0_SE9/ADC1_SE9/TSI0_CH6/PTB1/I2C0_SDA/FTM1_CH1/RMII0_MDC/MII0_MDC/SDRAM_RAS_b/FTM1_QD_PHB/TPM1_CH1}
  - {pin_num: K4, peripheral: ENET, signal: CLKIN_1588, pin_signal: PTE26/ENET_1588_CLKIN/UART4_CTS_b/RTC_CLKOUT/USB0_CLKIN}
  - {pin_num: L2, peripheral: ADC0, signal: 'DM, 0', pin_signal: ADC0_DM0/ADC1_DM3}
  - {pin_num: L7, peripheral: FTM0, signal: 'CH, 1', pin_signal: TSI0_CH5/PTA4/LLWU_P3/FTM0_CH1/NMI_b/EZP_CS_b}
 * BE CAREFUL MODIFYING THIS COMMENT - IT IS YAML SETTINGS FOR TOOLS ***********
 */
/* clang-format on */

/* FUNCTION ************************************************************************************************************
 *
 * Function Name : BOARD_InitPins
 * Description   : Configures pin routing and optionally pin electrical features.
 *
 * END ****************************************************************************************************************/
void BOARD_InitPins(void)
{
    /* Port A Clock Gate Control: Clock enabled */
    CLOCK_EnableClock(kCLOCK_PortA);
    /* Port B Clock Gate Control: Clock enabled */
    CLOCK_EnableClock(kCLOCK_PortB);
    /* Port E Clock Gate Control: Clock enabled */
    CLOCK_EnableClock(kCLOCK_PortE);

    /* PORTA12 (pin K9) is configured as MII0_RXD1 */
    PORT_SetPinMux(BOARD_INITPINS_RMII0_RXD1_PORT, BOARD_INITPINS_RMII0_RXD1_PIN, kPORT_MuxAlt4);

    /* PORTA13 (pin J9) is configured as MII0_RXD0 */
    PORT_SetPinMux(BOARD_INITPINS_RMII0_RXD0_PORT, BOARD_INITPINS_RMII0_RXD0_PIN, kPORT_MuxAlt4);

    /* PORTA14 (pin L10) is configured as MII0_RXDV */
    PORT_SetPinMux(BOARD_INITPINS_RMII0_CRS_DV_PORT, BOARD_INITPINS_RMII0_CRS_DV_PIN, kPORT_MuxAlt4);

    /* PORTA15 (pin L11) is configured as MII0_TXEN */
    PORT_SetPinMux(BOARD_INITPINS_RMII0_TXEN_PORT, BOARD_INITPINS_RMII0_TXEN_PIN, kPORT_MuxAlt4);

    /* PORTA16 (pin K10) is configured as MII0_TXD0 */
    PORT_SetPinMux(BOARD_INITPINS_RMII0_TXD_0_PORT, BOARD_INITPINS_RMII0_TXD_0_PIN, kPORT_MuxAlt4);

    /* PORTA17 (pin K11) is configured as MII0_TXD1 */
    PORT_SetPinMux(BOARD_INITPINS_RMII0_TXD_1_PORT, BOARD_INITPINS_RMII0_TXD_1_PIN, kPORT_MuxAlt4);

    /* PORTA4 (pin L7) is configured as FTM0_CH1 */
    PORT_SetPinMux(BOARD_INITPINS_NMI_PORT, BOARD_INITPINS_NMI_PIN, kPORT_MuxAlt3);

    /* PORTA5 (pin M8) is configured as MII0_RXER */
    PORT_SetPinMux(BOARD_INITPINS_RMII0_RXER_PORT, BOARD_INITPINS_RMII0_RXER_PIN, kPORT_MuxAlt4);

    const port_pin_config_t RMII0_MDIO = {/* Internal pull-up/down resistor is disabled */
                                          kPORT_PullDisable,
                                          /* Fast slew rate is configured */
                                          kPORT_FastSlewRate,
                                          /* Passive filter is disabled */
                                          kPORT_PassiveFilterDisable,
                                          /* Open drain is enabled */
                                          kPORT_OpenDrainEnable,
                                          /* Low drive strength is configured */
                                          kPORT_LowDriveStrength,
                                          /* Pin is configured as MII0_MDIO */
                                          kPORT_MuxAlt4,
                                          /* Pin Control Register fields [15:0] are not locked */
                                          kPORT_UnlockRegister};
    /* PORTB0 (pin H10) is configured as MII0_MDIO */
    PORT_SetPinConfig(BOARD_INITPINS_RMII0_MDIO_PORT, BOARD_INITPINS_RMII0_MDIO_PIN, &RMII0_MDIO);

    /* PORTB1 (pin H9) is configured as MII0_MDC */
    PORT_SetPinMux(BOARD_INITPINS_RMII0_MDC_PORT, BOARD_INITPINS_RMII0_MDC_PIN, kPORT_MuxAlt4);

    /* PORTB16 (pin E10) is configured as UART0_RX */
    PORT_SetPinMux(BOARD_INITPINS_DEBUG_UART_RX_PORT, BOARD_INITPINS_DEBUG_UART_RX_PIN, kPORT_MuxAlt3);

    /* PORTB17 (pin E9) is configured as UART0_TX */
    PORT_SetPinMux(BOARD_INITPINS_DEBUG_UART_TX_PORT, BOARD_INITPINS_DEBUG_UART_TX_PIN, kPORT_MuxAlt3);

    /* PORTE26 (pin K4) is configured as ENET_1588_CLKIN */
    PORT_SetPinMux(PORTE, 26U, kPORT_MuxAlt2);

    SIM->SOPT5 = ((SIM->SOPT5 &
                   /* Mask bits to zero which are setting */
                   (~(SIM_SOPT5_UART0TXSRC_MASK)))

                  /* UART 0 transmit data source select: UART0_TX pin. */
                  | SIM_SOPT5_UART0TXSRC(SOPT5_UART0TXSRC_UART_TX));
}
/***********************************************************************************************************************
 * EOF
 **********************************************************************************************************************/
