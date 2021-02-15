################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../drivers/fsl_clock.c \
../drivers/fsl_common.c \
../drivers/fsl_enet.c \
../drivers/fsl_ftfx_cache.c \
../drivers/fsl_ftfx_controller.c \
../drivers/fsl_ftfx_flash.c \
../drivers/fsl_ftfx_flexnvm.c \
../drivers/fsl_ftm.c \
../drivers/fsl_gpio.c \
../drivers/fsl_lpuart.c \
../drivers/fsl_rnga.c \
../drivers/fsl_sim.c \
../drivers/fsl_smc.c \
../drivers/fsl_uart.c 

OBJS += \
./drivers/fsl_clock.o \
./drivers/fsl_common.o \
./drivers/fsl_enet.o \
./drivers/fsl_ftfx_cache.o \
./drivers/fsl_ftfx_controller.o \
./drivers/fsl_ftfx_flash.o \
./drivers/fsl_ftfx_flexnvm.o \
./drivers/fsl_ftm.o \
./drivers/fsl_gpio.o \
./drivers/fsl_lpuart.o \
./drivers/fsl_rnga.o \
./drivers/fsl_sim.o \
./drivers/fsl_smc.o \
./drivers/fsl_uart.o 

C_DEPS += \
./drivers/fsl_clock.d \
./drivers/fsl_common.d \
./drivers/fsl_enet.d \
./drivers/fsl_ftfx_cache.d \
./drivers/fsl_ftfx_controller.d \
./drivers/fsl_ftfx_flash.d \
./drivers/fsl_ftfx_flexnvm.d \
./drivers/fsl_ftm.d \
./drivers/fsl_gpio.d \
./drivers/fsl_lpuart.d \
./drivers/fsl_rnga.d \
./drivers/fsl_sim.d \
./drivers/fsl_smc.d \
./drivers/fsl_uart.d 


# Each subdirectory must supply rules for building sources it contributes
drivers/%.o: ../drivers/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: MCU C Compiler'
	arm-none-eabi-gcc -std=gnu99 -D__REDLIB__ -DCPU_MK66FN2M0VMD18 -DCPU_MK66FN2M0VMD18_cm4 -D_POSIX_SOURCE -DUSE_RTOS=1 -DPRINTF_ADVANCED_ENABLE=1 -DHTTPSRV_CFG_WEBSOCKET_ENABLED=0 -DFRDM_K66F -DFREEDOM -DSERIAL_PORT_TYPE_UART=1 -DFSL_RTOS_FREE_RTOS -DSDK_DEBUGCONSOLE=0 -DPRINTF_FLOAT_ENABLE=1 -D__MCUXPRESSO -D__USE_CMSIS -DDEBUG -DSDK_OS_FREE_RTOS -DMBEDTLS_DEBUG_C=1 -DMBEDTLS_CONFIG_FILE='"ksdk_mbedtls_config.h"' -I"C:\projects\Emob-Controller\board" -I"C:\projects\Emob-Controller\OpenV2G\appHandshake" -I"C:\projects\Emob-Controller\OpenV2G\codec" -I"C:\projects\Emob-Controller\OpenV2G\din" -I"C:\projects\Emob-Controller\OpenV2G\transport" -I"C:\projects\Emob-Controller\OpenV2G\xmldsig" -I"C:\projects\Emob-Controller\amazon-freertos\freertos_kernel\include" -I"C:\projects\Emob-Controller\component\lists" -I"C:\projects\Emob-Controller\drivers" -I"C:\projects\Emob-Controller\utilities" -I"C:\projects\Emob-Controller\CMSIS" -I"C:\projects\Emob-Controller\lwip\port" -I"C:\projects\Emob-Controller\source" -I"C:\projects\Emob-Controller\lwip\src\include\lwip\apps" -I"C:\projects\Emob-Controller\component\serial_manager" -I"C:\projects\Emob-Controller\device" -I"C:\projects\Emob-Controller\component\uart" -I"C:\projects\Emob-Controller\lwip\src\apps\httpsrv" -I"C:\projects\Emob-Controller\amazon-freertos\freertos_kernel\portable\GCC\ARM_CM4F" -I"C:\projects\Emob-Controller\lwip\port\arch" -I"C:\projects\Emob-Controller\lwip\src\include\compat\posix\arpa" -I"C:\projects\Emob-Controller\lwip\src\include\compat\posix\net" -I"C:\projects\Emob-Controller\lwip\src\include\compat\posix" -I"C:\projects\Emob-Controller\lwip\src\include\compat\posix\sys" -I"C:\projects\Emob-Controller\lwip\src\include\compat\stdc" -I"C:\projects\Emob-Controller\lwip\src\include\lwip" -I"C:\projects\Emob-Controller\lwip\src\include\lwip\priv" -I"C:\projects\Emob-Controller\lwip\src\include\lwip\prot" -I"C:\projects\Emob-Controller\lwip\src\include\netif" -I"C:\projects\Emob-Controller\lwip\src\include\netif\ppp" -I"C:\projects\Emob-Controller\lwip\src\include\netif\ppp\polarssl" -I"C:\projects\Emob-Controller\lwip\src" -I"C:\projects\Emob-Controller\lwip\src\include" -I"C:\projects\Emob-Controller" -I"C:\projects\Emob-Controller\mmcau\mmcau_include" -I"C:\projects\Emob-Controller\mbedtls\include" -I"C:\projects\Emob-Controller\mbedtls\port\ksdk" -O3 -fno-common -g3 -Wall -c  -ffunction-sections  -fdata-sections  -ffreestanding  -fno-builtin -fmacro-prefix-map="../$(@D)/"=. -mcpu=cortex-m4 -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb -D__REDLIB__ -fstack-usage -specs=redlib.specs -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.o)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


