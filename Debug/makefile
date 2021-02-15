################################################################################
# Automatically-generated file. Do not edit!
################################################################################

-include ../makefile.init

RM := rm -rf

# All of the sources participating in the build are defined here
-include sources.mk
-include utilities/subdir.mk
-include startup/subdir.mk
-include source/webserver/subdir.mk
-include source/v2g/subdir.mk
-include source/slac/subdir.mk
-include source/master_if/subdir.mk
-include source/cp_gen/subdir.mk
-include source/charger/subdir.mk
-include source/subdir.mk
-include mmcau/mmcau_source/subdir.mk
-include mbedtls/port/ksdk/subdir.mk
-include mbedtls/library/subdir.mk
-include lwip/src/netif/ppp/subdir.mk
-include lwip/src/netif/subdir.mk
-include lwip/src/core/ipv6/subdir.mk
-include lwip/src/core/ipv4/subdir.mk
-include lwip/src/core/subdir.mk
-include lwip/src/apps/mdns/subdir.mk
-include lwip/src/apps/httpsrv/subdir.mk
-include lwip/src/api/subdir.mk
-include lwip/port/subdir.mk
-include drivers/subdir.mk
-include device/subdir.mk
-include component/uart/subdir.mk
-include component/serial_manager/subdir.mk
-include component/lists/subdir.mk
-include board/subdir.mk
-include amazon-freertos/freertos_kernel/portable/MemMang/subdir.mk
-include amazon-freertos/freertos_kernel/portable/GCC/ARM_CM4F/subdir.mk
-include amazon-freertos/freertos_kernel/subdir.mk
-include OpenV2G/xmldsig/subdir.mk
-include OpenV2G/transport/subdir.mk
-include OpenV2G/din/subdir.mk
-include OpenV2G/codec/subdir.mk
-include OpenV2G/appHandshake/subdir.mk
-include subdir.mk
-include objects.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
endif

-include ../makefile.defs

# Add inputs and outputs from these tool invocations to the build variables 

# All Target
all: frdmk66f_lwip_httpsrv_freertos__testing_V3.axf

# Tool invocations
frdmk66f_lwip_httpsrv_freertos__testing_V3.axf: $(OBJS) $(USER_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: MCU Linker'
	arm-none-eabi-gcc -nostdlib -L"C:\projects\Emob-Controller\libs" -Xlinker -Map="frdmk66f_lwip_httpsrv_freertos__testing_V3.map" -Xlinker --gc-sections -Xlinker -print-memory-usage -Xlinker --sort-section=alignment -Xlinker --cref -mcpu=cortex-m4 -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb -T frdmk66f_lwip_httpsrv_freertos_testing_V3_Debug.ld -o "frdmk66f_lwip_httpsrv_freertos__testing_V3.axf" $(OBJS) $(USER_OBJS) $(LIBS)
	@echo 'Finished building target: $@'
	@echo ' '
	$(MAKE) --no-print-directory post-build

# Other Targets
clean:
	-$(RM) $(EXECUTABLES)$(OBJS)$(C_DEPS) frdmk66f_lwip_httpsrv_freertos__testing_V3.axf
	-@echo ' '

post-build:
	-@echo 'Performing post-build steps'
	-arm-none-eabi-size "frdmk66f_lwip_httpsrv_freertos__testing_V3.axf"; # arm-none-eabi-objcopy -v -O binary "frdmk66f_lwip_httpsrv_freertos__testing_V3.axf" "frdmk66f_lwip_httpsrv_freertos__testing_V3.bin" ; # checksum -p MK66FN2M0xxx18 -d "frdmk66f_lwip_httpsrv_freertos__testing_V3.bin";
	-@echo ' '

.PHONY: all clean dependents post-build

-include ../makefile.targets
