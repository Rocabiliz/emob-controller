################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../lwip/src/netif/bridgeif.c \
../lwip/src/netif/bridgeif_fdb.c \
../lwip/src/netif/ethernet.c \
../lwip/src/netif/lowpan6.c \
../lwip/src/netif/lowpan6_ble.c \
../lwip/src/netif/lowpan6_common.c \
../lwip/src/netif/slipif.c \
../lwip/src/netif/zepif.c 

OBJS += \
./lwip/src/netif/bridgeif.o \
./lwip/src/netif/bridgeif_fdb.o \
./lwip/src/netif/ethernet.o \
./lwip/src/netif/lowpan6.o \
./lwip/src/netif/lowpan6_ble.o \
./lwip/src/netif/lowpan6_common.o \
./lwip/src/netif/slipif.o \
./lwip/src/netif/zepif.o 

C_DEPS += \
./lwip/src/netif/bridgeif.d \
./lwip/src/netif/bridgeif_fdb.d \
./lwip/src/netif/ethernet.d \
./lwip/src/netif/lowpan6.d \
./lwip/src/netif/lowpan6_ble.d \
./lwip/src/netif/lowpan6_common.d \
./lwip/src/netif/slipif.d \
./lwip/src/netif/zepif.d 


# Each subdirectory must supply rules for building sources it contributes
lwip/src/netif/%.o: ../lwip/src/netif/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: MCU C Compiler'
	arm-none-eabi-gcc -std=gnu99 -D__REDLIB__ -DCPU_MK66FN2M0VMD18 -DCPU_MK66FN2M0VMD18_cm4 -D_POSIX_SOURCE -DUSE_RTOS=1 -DPRINTF_ADVANCED_ENABLE=1 -DHTTPSRV_CFG_WEBSOCKET_ENABLED=0 -DFRDM_K66F -DFREEDOM -DSERIAL_PORT_TYPE_UART=1 -DFSL_RTOS_FREE_RTOS -DSDK_DEBUGCONSOLE=0 -DPRINTF_FLOAT_ENABLE=1 -D__MCUXPRESSO -D__USE_CMSIS -DDEBUG -DSDK_OS_FREE_RTOS -DMBEDTLS_DEBUG_C=1 -DMBEDTLS_CONFIG_FILE='"ksdk_mbedtls_config.h"' -I"C:\projects\Emob-Controller\board" -I"C:\projects\Emob-Controller\OpenV2G\appHandshake" -I"C:\projects\Emob-Controller\OpenV2G\codec" -I"C:\projects\Emob-Controller\OpenV2G\din" -I"C:\projects\Emob-Controller\OpenV2G\transport" -I"C:\projects\Emob-Controller\OpenV2G\xmldsig" -I"C:\projects\Emob-Controller\amazon-freertos\freertos_kernel\include" -I"C:\projects\Emob-Controller\component\lists" -I"C:\projects\Emob-Controller\drivers" -I"C:\projects\Emob-Controller\utilities" -I"C:\projects\Emob-Controller\CMSIS" -I"C:\projects\Emob-Controller\lwip\port" -I"C:\projects\Emob-Controller\source" -I"C:\projects\Emob-Controller\lwip\src\include\lwip\apps" -I"C:\projects\Emob-Controller\component\serial_manager" -I"C:\projects\Emob-Controller\device" -I"C:\projects\Emob-Controller\component\uart" -I"C:\projects\Emob-Controller\lwip\src\apps\httpsrv" -I"C:\projects\Emob-Controller\amazon-freertos\freertos_kernel\portable\GCC\ARM_CM4F" -I"C:\projects\Emob-Controller\lwip\port\arch" -I"C:\projects\Emob-Controller\lwip\src\include\compat\posix\arpa" -I"C:\projects\Emob-Controller\lwip\src\include\compat\posix\net" -I"C:\projects\Emob-Controller\lwip\src\include\compat\posix" -I"C:\projects\Emob-Controller\lwip\src\include\compat\posix\sys" -I"C:\projects\Emob-Controller\lwip\src\include\compat\stdc" -I"C:\projects\Emob-Controller\lwip\src\include\lwip" -I"C:\projects\Emob-Controller\lwip\src\include\lwip\priv" -I"C:\projects\Emob-Controller\lwip\src\include\lwip\prot" -I"C:\projects\Emob-Controller\lwip\src\include\netif" -I"C:\projects\Emob-Controller\lwip\src\include\netif\ppp" -I"C:\projects\Emob-Controller\lwip\src\include\netif\ppp\polarssl" -I"C:\projects\Emob-Controller\lwip\src" -I"C:\projects\Emob-Controller\lwip\src\include" -I"C:\projects\Emob-Controller" -I"C:\projects\Emob-Controller\mmcau\mmcau_include" -I"C:\projects\Emob-Controller\mbedtls\include" -I"C:\projects\Emob-Controller\mbedtls\port\ksdk" -O3 -fno-common -g3 -Wall -c  -ffunction-sections  -fdata-sections  -ffreestanding  -fno-builtin -fmacro-prefix-map="../$(@D)/"=. -mcpu=cortex-m4 -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb -D__REDLIB__ -fstack-usage -specs=redlib.specs -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.o)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


