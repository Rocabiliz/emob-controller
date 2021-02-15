################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../lwip/src/netif/ppp/auth.c \
../lwip/src/netif/ppp/ccp.c \
../lwip/src/netif/ppp/chap-md5.c \
../lwip/src/netif/ppp/chap-new.c \
../lwip/src/netif/ppp/chap_ms.c \
../lwip/src/netif/ppp/demand.c \
../lwip/src/netif/ppp/eap.c \
../lwip/src/netif/ppp/eui64.c \
../lwip/src/netif/ppp/fsm.c \
../lwip/src/netif/ppp/ipcp.c \
../lwip/src/netif/ppp/ipv6cp.c \
../lwip/src/netif/ppp/lcp.c \
../lwip/src/netif/ppp/lwip_ecp.c \
../lwip/src/netif/ppp/magic.c \
../lwip/src/netif/ppp/mppe.c \
../lwip/src/netif/ppp/multilink.c \
../lwip/src/netif/ppp/ppp.c \
../lwip/src/netif/ppp/pppapi.c \
../lwip/src/netif/ppp/pppcrypt.c \
../lwip/src/netif/ppp/pppoe.c \
../lwip/src/netif/ppp/pppol2tp.c \
../lwip/src/netif/ppp/pppos.c \
../lwip/src/netif/ppp/upap.c \
../lwip/src/netif/ppp/utils.c \
../lwip/src/netif/ppp/vj.c 

OBJS += \
./lwip/src/netif/ppp/auth.o \
./lwip/src/netif/ppp/ccp.o \
./lwip/src/netif/ppp/chap-md5.o \
./lwip/src/netif/ppp/chap-new.o \
./lwip/src/netif/ppp/chap_ms.o \
./lwip/src/netif/ppp/demand.o \
./lwip/src/netif/ppp/eap.o \
./lwip/src/netif/ppp/eui64.o \
./lwip/src/netif/ppp/fsm.o \
./lwip/src/netif/ppp/ipcp.o \
./lwip/src/netif/ppp/ipv6cp.o \
./lwip/src/netif/ppp/lcp.o \
./lwip/src/netif/ppp/lwip_ecp.o \
./lwip/src/netif/ppp/magic.o \
./lwip/src/netif/ppp/mppe.o \
./lwip/src/netif/ppp/multilink.o \
./lwip/src/netif/ppp/ppp.o \
./lwip/src/netif/ppp/pppapi.o \
./lwip/src/netif/ppp/pppcrypt.o \
./lwip/src/netif/ppp/pppoe.o \
./lwip/src/netif/ppp/pppol2tp.o \
./lwip/src/netif/ppp/pppos.o \
./lwip/src/netif/ppp/upap.o \
./lwip/src/netif/ppp/utils.o \
./lwip/src/netif/ppp/vj.o 

C_DEPS += \
./lwip/src/netif/ppp/auth.d \
./lwip/src/netif/ppp/ccp.d \
./lwip/src/netif/ppp/chap-md5.d \
./lwip/src/netif/ppp/chap-new.d \
./lwip/src/netif/ppp/chap_ms.d \
./lwip/src/netif/ppp/demand.d \
./lwip/src/netif/ppp/eap.d \
./lwip/src/netif/ppp/eui64.d \
./lwip/src/netif/ppp/fsm.d \
./lwip/src/netif/ppp/ipcp.d \
./lwip/src/netif/ppp/ipv6cp.d \
./lwip/src/netif/ppp/lcp.d \
./lwip/src/netif/ppp/lwip_ecp.d \
./lwip/src/netif/ppp/magic.d \
./lwip/src/netif/ppp/mppe.d \
./lwip/src/netif/ppp/multilink.d \
./lwip/src/netif/ppp/ppp.d \
./lwip/src/netif/ppp/pppapi.d \
./lwip/src/netif/ppp/pppcrypt.d \
./lwip/src/netif/ppp/pppoe.d \
./lwip/src/netif/ppp/pppol2tp.d \
./lwip/src/netif/ppp/pppos.d \
./lwip/src/netif/ppp/upap.d \
./lwip/src/netif/ppp/utils.d \
./lwip/src/netif/ppp/vj.d 


# Each subdirectory must supply rules for building sources it contributes
lwip/src/netif/ppp/%.o: ../lwip/src/netif/ppp/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: MCU C Compiler'
	arm-none-eabi-gcc -std=gnu99 -D__REDLIB__ -DCPU_MK66FN2M0VMD18 -DCPU_MK66FN2M0VMD18_cm4 -D_POSIX_SOURCE -DUSE_RTOS=1 -DPRINTF_ADVANCED_ENABLE=1 -DHTTPSRV_CFG_WEBSOCKET_ENABLED=0 -DFRDM_K66F -DFREEDOM -DSERIAL_PORT_TYPE_UART=1 -DFSL_RTOS_FREE_RTOS -DSDK_DEBUGCONSOLE=0 -DPRINTF_FLOAT_ENABLE=1 -D__MCUXPRESSO -D__USE_CMSIS -DDEBUG -DSDK_OS_FREE_RTOS -DMBEDTLS_DEBUG_C=1 -DMBEDTLS_CONFIG_FILE='"ksdk_mbedtls_config.h"' -I"C:\projects\Emob-Controller\board" -I"C:\projects\Emob-Controller\OpenV2G\appHandshake" -I"C:\projects\Emob-Controller\OpenV2G\codec" -I"C:\projects\Emob-Controller\OpenV2G\din" -I"C:\projects\Emob-Controller\OpenV2G\transport" -I"C:\projects\Emob-Controller\OpenV2G\xmldsig" -I"C:\projects\Emob-Controller\amazon-freertos\freertos_kernel\include" -I"C:\projects\Emob-Controller\component\lists" -I"C:\projects\Emob-Controller\drivers" -I"C:\projects\Emob-Controller\utilities" -I"C:\projects\Emob-Controller\CMSIS" -I"C:\projects\Emob-Controller\lwip\port" -I"C:\projects\Emob-Controller\source" -I"C:\projects\Emob-Controller\lwip\src\include\lwip\apps" -I"C:\projects\Emob-Controller\component\serial_manager" -I"C:\projects\Emob-Controller\device" -I"C:\projects\Emob-Controller\component\uart" -I"C:\projects\Emob-Controller\lwip\src\apps\httpsrv" -I"C:\projects\Emob-Controller\amazon-freertos\freertos_kernel\portable\GCC\ARM_CM4F" -I"C:\projects\Emob-Controller\lwip\port\arch" -I"C:\projects\Emob-Controller\lwip\src\include\compat\posix\arpa" -I"C:\projects\Emob-Controller\lwip\src\include\compat\posix\net" -I"C:\projects\Emob-Controller\lwip\src\include\compat\posix" -I"C:\projects\Emob-Controller\lwip\src\include\compat\posix\sys" -I"C:\projects\Emob-Controller\lwip\src\include\compat\stdc" -I"C:\projects\Emob-Controller\lwip\src\include\lwip" -I"C:\projects\Emob-Controller\lwip\src\include\lwip\priv" -I"C:\projects\Emob-Controller\lwip\src\include\lwip\prot" -I"C:\projects\Emob-Controller\lwip\src\include\netif" -I"C:\projects\Emob-Controller\lwip\src\include\netif\ppp" -I"C:\projects\Emob-Controller\lwip\src\include\netif\ppp\polarssl" -I"C:\projects\Emob-Controller\lwip\src" -I"C:\projects\Emob-Controller\lwip\src\include" -I"C:\projects\Emob-Controller" -I"C:\projects\Emob-Controller\mmcau\mmcau_include" -I"C:\projects\Emob-Controller\mbedtls\include" -I"C:\projects\Emob-Controller\mbedtls\port\ksdk" -O3 -fno-common -g3 -Wall -c  -ffunction-sections  -fdata-sections  -ffreestanding  -fno-builtin -fmacro-prefix-map="../$(@D)/"=. -mcpu=cortex-m4 -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb -D__REDLIB__ -fstack-usage -specs=redlib.specs -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.o)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


