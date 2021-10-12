#include <string.h>
#include "fsl_flash.h"
#if defined(FSL_FEATURE_HAS_L1CACHE) && FSL_FEATURE_HAS_L1CACHE
#include "fsl_cache.h"
#endif /* FSL_FEATURE_HAS_L1CACHE */
#include <stdint.h>
#include "fsl_device_registers.h"
#include "fsl_debug_console.h"
#include "nvm.h"

/* In case of the protected sectors at the end of the pFlash just select
the block from the end of pFlash to be used for operations
SECTOR_INDEX_FROM_END = 1 means the last sector,
SECTOR_INDEX_FROM_END = 2 means (the last sector - 1) ...
in case of FSL_FEATURE_FLASH_HAS_PFLASH_BLOCK_SWAP it is
SECTOR_INDEX_FROM_END = 1 means the last 2 sectors with width of 2 sectors,
SECTOR_INDEX_FROM_END = 2 means the last 4 sectors back
with width of 2 sectors ...
*/
#ifndef SECTOR_INDEX_FROM_END
#define SECTOR_INDEX_FROM_END 1U
#endif

/*! @brief Flash driver Structure */
static flash_config_t s_flashDriver;
/*! @brief Flash cache driver Structure */
static ftfx_cache_config_t s_cacheDriver;
/*! @brief Buffer for program */
static uint32_t s_buffer[2546];
/*! @brief Buffer for readback */
static uint32_t s_buffer_rbc[4];

static uint32_t pflashBlockBase  = 0;
static uint32_t pflashTotalSize  = 0;
static uint32_t pflashSectorSize = 0;
static uint32_t destAdrss;

void error_trap(void)
{
    PRINTF("\r\n\r\n\r\n\t---- HALTED DUE TO FLASH ERROR! ----");
    while (1)
    {
    }
}

/*!
 * @brief Initializes structures to handle the Flash memory (NVM) 
 */
void NVM_init() {
    ftfx_security_state_t securityStatus = kFTFx_SecurityStateNotSecure; /* Return protection status */
    status_t result;
    uint32_t i, failAddr, failDat;

    /* Clean up Flash, Cache driver Structure*/
    memset(&s_flashDriver, 0, sizeof(flash_config_t));
    memset(&s_cacheDriver, 0, sizeof(ftfx_cache_config_t));

    /* Setup flash driver structure for device and initialize variables. */
    result = FLASH_Init(&s_flashDriver);
    if (kStatus_FTFx_Success != result) {
        error_trap();
    }
    /* Setup flash cache driver structure for device and initialize variables. */
    result = FTFx_CACHE_Init(&s_cacheDriver);
    if (kStatus_FTFx_Success != result) {
        error_trap();
    }
    
    /* Get flash properties*/
    FLASH_GetProperty(&s_flashDriver, kFLASH_PropertyPflash0BlockBaseAddr, &pflashBlockBase);
    FLASH_GetProperty(&s_flashDriver, kFLASH_PropertyPflash0TotalSize, &pflashTotalSize);
    FLASH_GetProperty(&s_flashDriver, kFLASH_PropertyPflash0SectorSize, &pflashSectorSize);

    /* Check security status. */
    result = FLASH_GetSecurityState(&s_flashDriver, &securityStatus);
    if (kStatus_FTFx_Success != result) {
        error_trap();
    }
    /* Print security status. */
    switch (securityStatus) {
        case kFTFx_SecurityStateNotSecure:
            PRINTF("\r\n Flash is UNSECURE!");
            break;
        case kFTFx_SecurityStateBackdoorEnabled:
            PRINTF("\r\n Flash is SECURE, BACKDOOR is ENABLED!");
            break;
        case kFTFx_SecurityStateBackdoorDisabled:
            PRINTF("\r\n Flash is SECURE, BACKDOOR is DISABLED!");
            break;
        default:
            break;
    }
    PRINTF("\r\n");

    if (kFTFx_SecurityStateNotSecure == securityStatus) {
#if defined(FSL_FEATURE_FLASH_HAS_PFLASH_BLOCK_SWAP) && FSL_FEATURE_FLASH_HAS_PFLASH_BLOCK_SWAP
        /* Note: we should make sure that the sector shouldn't be swap indicator sector*/
        destAdrss = pflashBlockBase + (pflashTotalSize - (SECTOR_INDEX_FROM_END * pflashSectorSize * 2));
#else
        destAdrss = pflashBlockBase + (pflashTotalSize - (SECTOR_INDEX_FROM_END * pflashSectorSize));
#endif
    }
    else {
        destAdrss = NULL;
    }

}

/*!
 * @brief Reads a uint8 buffer from Flash memory. 
 */
void NVM_read(uint8_t *buffer, size_t len) {

    PRINTF("READING NVM DATA...\r\n");
    /* Copy Flash data to buffer */
    for (uint8_t i = 0; i < len; i++) {
        buffer[i] = *(volatile uint8_t *)(destAdrss + i);
    }
    PRINTF("READ DONE!\r\n");

}

void NVM_write(uint8_t *buffer, size_t len) {
    uint32_t failAddr, failDat;
    status_t result;

    PRINTF("WRITING NVM DATA 1...\r\n");

    /* Pre-preparation work about flash Cache/Prefetch/Speculation. */
    FTFx_CACHE_ClearCachePrefetchSpeculation(&s_cacheDriver, true);

    /* Debug message for user. */
    /* Erase several sectors on upper pflash block where there is no code */
    PRINTF("\r\n Erase a sector of flash");

    result = FLASH_Erase(&s_flashDriver, destAdrss, pflashSectorSize, kFTFx_ApiEraseKey);
    if (kStatus_FTFx_Success != result) {
        error_trap();
    }

    /* Verify sector if it's been erased. */
    result = FLASH_VerifyErase(&s_flashDriver, destAdrss, pflashSectorSize, kFTFx_MarginValueUser);
    if (kStatus_FTFx_Success != result) {
        error_trap();
    }

    /* Print message for user. */
    PRINTF("\r\n Successfully Erased Sector 0x%x -> 0x%x\r\n", destAdrss, (destAdrss + pflashSectorSize));

    /* Program user buffer into flash*/
    result = FLASH_Program(&s_flashDriver, destAdrss, buffer, len * 8);
    if (kStatus_FTFx_Success != result) {
        PRINTF("ERROR: %d\r\n", result);
        error_trap();
    }

    /* Verify programming by Program Check command with user margin levels */
    PRINTF("WRITE 1\r\n");
    result = FLASH_VerifyProgram(&s_flashDriver, destAdrss, len * 8, (const uint8_t *)buffer,
                                    kFTFx_MarginValueUser, &failAddr, &failDat);
    if (kStatus_FTFx_Success != result) {
        error_trap();
    }
    PRINTF("WRITE 2\r\n");

    /* Post-preparation work about flash Cache/Prefetch/Speculation. */
    FTFx_CACHE_ClearCachePrefetchSpeculation(&s_cacheDriver, false);
    PRINTF("WRITE 3\r\n");

#if defined(FSL_FEATURE_HAS_L1CACHE) && FSL_FEATURE_HAS_L1CACHE
        L1CACHE_InvalidateCodeCache();
#endif /* FSL_FEATURE_HAS_L1CACHE */
    PRINTF("WRITE 4\r\n");

#if defined(__DCACHE_PRESENT) && __DCACHE_PRESENT
        /* Clean the D-Cache before reading the flash data*/
        SCB_CleanInvalidateDCache();
#endif
    
    PRINTF("WRITE DONE!\r\n");

}