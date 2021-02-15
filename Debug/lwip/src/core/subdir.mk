################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../lwip/src/core/altcp.c \
../lwip/src/core/altcp_alloc.c \
../lwip/src/core/altcp_tcp.c \
../lwip/src/core/def.c \
../lwip/src/core/dns.c \
../lwip/src/core/inet_chksum.c \
../lwip/src/core/init.c \
../lwip/src/core/ip.c \
../lwip/src/core/mem.c \
../lwip/src/core/memp.c \
../lwip/src/core/netif.c \
../lwip/src/core/pbuf.c \
../lwip/src/core/raw.c \
../lwip/src/core/stats.c \
../lwip/src/core/sys.c \
../lwip/src/core/tcp.c \
../lwip/src/core/tcp_in.c \
../lwip/src/core/tcp_out.c \
../lwip/src/core/timeouts.c \
../lwip/src/core/udp.c 

OBJS += \
./lwip/src/core/altcp.o \
./lwip/src/core/altcp_alloc.o \
./lwip/src/core/altcp_tcp.o \
./lwip/src/core/def.o \
./lwip/src/core/dns.o \
./lwip/src/core/inet_chksum.o \
./lwip/src/core/init.o \
./lwip/src/core/ip.o \
./lwip/src/core/mem.o \
./lwip/src/core/memp.o \
./lwip/src/core/netif.o \
./lwip/src/core/pbuf.o \
./lwip/src/core/raw.o \
./lwip/src/core/stats.o \
./lwip/src/core/sys.o \
./lwip/src/core/tcp.o \
./lwip/src/core/tcp_in.o \
./lwip/src/core/tcp_out.o \
./lwip/src/core/timeouts.o \
./lwip/src/core/udp.o 

C_DEPS += \
./lwip/src/core/altcp.d \
./lwip/src/core/altcp_alloc.d \
./lwip/src/core/altcp_tcp.d \
./lwip/src/core/def.d \
./lwip/src/core/dns.d \
./lwip/src/core/inet_chksum.d \
./lwip/src/core/init.d \
./lwip/src/core/ip.d \
./lwip/src/core/mem.d \
./lwip/src/core/memp.d \
./lwip/src/core/netif.d \
./lwip/src/core/pbuf.d \
./lwip/src/core/raw.d \
./lwip/src/core/stats.d \
./lwip/src/core/sys.d \
./lwip/src/core/tcp.d \
./lwip/src/core/tcp_in.d \
./lwip/src/core/tcp_out.d \
./lwip/src/core/timeouts.d \
./lwip/src/core/udp.d 


# Each subdirectory must supply rules for building sources it contributes
lwip/src/core/%.o: ../lwip/src/core/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: MCU C Compiler'
	arm-none-eabi-gcc -std=gnu99 -D__REDLIB__ -DCPU_MK66FN2M0VMD18 -DCPU_MK66FN2M0VMD18_cm4 -D_POSIX_SOURCE -DUSE_RTOS=1 -DPRINTF_ADVANCED_ENABLE=1 -DHTTPSRV_CFG_WEBSOCKET_ENABLED=0 -DFRDM_K66F -DFREEDOM -DSERIAL_PORT_TYPE_UART=1 -DFSL_RTOS_FREE_RTOS -DSDK_DEBUGCONSOLE=0 -DPRINTF_FLOAT_ENABLE=1 -D__MCUXPRESSO -D__USE_CMSIS -DDEBUG -DSDK_OS_FREE_RTOS -DMBEDTLS_DEBUG_C=1 -DMBEDTLS_CONFIG_FILE='"ksdk_mbedtls_config.h"' -I"C:\projects\Emob-Controller\board" -I"C:\projects\Emob-Controller\OpenV2G\appHandshake" -I"C:\projects\Emob-Controller\OpenV2G\codec" -I"C:\projects\Emob-Controller\OpenV2G\din" -I"C:\projects\Emob-Controller\OpenV2G\transport" -I"C:\projects\Emob-Controller\OpenV2G\xmldsig" -I"C:\projects\Emob-Controller\amazon-freertos\freertos_kernel\include" -I"C:\projects\Emob-Controller\component\lists" -I"C:\projects\Emob-Controller\drivers" -I"C:\projects\Emob-Controller\utilities" -I"C:\projects\Emob-Controller\CMSIS" -I"C:\projects\Emob-Controller\lwip\port" -I"C:\projects\Emob-Controller\source" -I"C:\projects\Emob-Controller\lwip\src\include\lwip\apps" -I"C:\projects\Emob-Controller\component\serial_manager" -I"C:\projects\Emob-Controller\device" -I"C:\projects\Emob-Controller\component\uart" -I"C:\projects\Emob-Controller\lwip\src\apps\httpsrv" -I"C:\projects\Emob-Controller\amazon-freertos\freertos_kernel\portable\GCC\ARM_CM4F" -I"C:\projects\Emob-Controller\lwip\port\arch" -I"C:\projects\Emob-Controller\lwip\src\include\compat\posix\arpa" -I"C:\projects\Emob-Controller\lwip\src\include\compat\posix\net" -I"C:\projects\Emob-Controller\lwip\src\include\compat\posix" -I"C:\projects\Emob-Controller\lwip\src\include\compat\posix\sys" -I"C:\projects\Emob-Controller\lwip\src\include\compat\stdc" -I"C:\projects\Emob-Controller\lwip\src\include\lwip" -I"C:\projects\Emob-Controller\lwip\src\include\lwip\priv" -I"C:\projects\Emob-Controller\lwip\src\include\lwip\prot" -I"C:\projects\Emob-Controller\lwip\src\include\netif" -I"C:\projects\Emob-Controller\lwip\src\include\netif\ppp" -I"C:\projects\Emob-Controller\lwip\src\include\netif\ppp\polarssl" -I"C:\projects\Emob-Controller\lwip\src" -I"C:\projects\Emob-Controller\lwip\src\include" -I"C:\projects\Emob-Controller" -I"C:\projects\Emob-Controller\mmcau\mmcau_include" -I"C:\projects\Emob-Controller\mbedtls\include" -I"C:\projects\Emob-Controller\mbedtls\port\ksdk" -O3 -fno-common -g3 -Wall -c  -ffunction-sections  -fdata-sections  -ffreestanding  -fno-builtin -fmacro-prefix-map="../$(@D)/"=. -mcpu=cortex-m4 -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb -D__REDLIB__ -fstack-usage -specs=redlib.specs -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.o)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


