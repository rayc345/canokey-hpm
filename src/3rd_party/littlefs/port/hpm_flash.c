/*
 * Copyright (c) 2023 HPMicro
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "hpm_flash.h"
#include "hpm_l1c_drv.h"
#include "board.h"

void e2p_enter_critical(void)
{
    disable_global_irq(CSR_MSTATUS_MIE_MASK);
}

void e2p_exit_critical(void)
{
    enable_global_irq(CSR_MSTATUS_MIE_MASK);
}

E2P_ATTR
hpm_stat_t nor_flash_init(nor_flash_config_t *cfg)
{
    xpi_nor_config_option_t option;

    option.header.U = cfg->opt_header;
    option.option0.U = cfg->opt0;
    option.option1.U = cfg->opt1;
    hpm_stat_t status = rom_xpi_nor_auto_config(cfg->xpi_base, &cfg->nor_config, &option);
    if (status != status_success)
    {
        return status;
    }

    rom_xpi_nor_get_property(cfg->xpi_base, &cfg->nor_config, xpi_nor_property_sector_size, &cfg->sector_size);
    rom_xpi_nor_get_property(cfg->xpi_base, &cfg->nor_config, xpi_nor_property_total_size, &cfg->flash_size);
    rom_xpi_nor_get_property(cfg->xpi_base, &cfg->nor_config, xpi_nor_property_page_size, &cfg->page_size);
    __asm volatile("fence.i");
    return status_success;
}

E2P_ATTR
hpm_stat_t nor_flash_read(nor_flash_config_t *cfg, uint8_t *buf, uint32_t addr, uint32_t size)
{
    uint32_t aligned_start = HPM_L1C_CACHELINE_ALIGN_DOWN(addr);
    uint32_t aligned_end = HPM_L1C_CACHELINE_ALIGN_UP(addr + size);
    uint32_t aligned_size = aligned_end - aligned_start;
    e2p_enter_critical();
    (void)cfg;
    addr >= cfg->base_addr ? (addr -= cfg->base_addr) : addr;
    l1c_dc_invalidate(aligned_start, aligned_size);
    hpm_stat_t status = rom_xpi_nor_read(cfg->xpi_base, xpi_xfer_channel_auto,
                                         &cfg->nor_config, (uint32_t *)buf, addr, size);
    e2p_exit_critical();
    return status;
}

E2P_ATTR
hpm_stat_t nor_flash_write(nor_flash_config_t *cfg, const uint8_t *buf, uint32_t addr, uint32_t size)
{
    e2p_enter_critical();
    addr >= cfg->base_addr ? (addr -= cfg->base_addr) : addr;
    hpm_stat_t status = rom_xpi_nor_program(cfg->xpi_base, xpi_xfer_channel_auto,
                                            &cfg->nor_config, (const uint32_t *)buf, addr, size);
    e2p_exit_critical();
    return status;
}

E2P_ATTR
hpm_stat_t nor_flash_erase_sector(nor_flash_config_t *cfg, uint32_t start_addr)
{
    e2p_enter_critical();
    start_addr >= cfg->base_addr ? (start_addr -= cfg->base_addr) : start_addr;
    hpm_stat_t status = rom_xpi_nor_erase_sector(cfg->xpi_base, xpi_xfer_channel_auto, &cfg->nor_config, start_addr);
    e2p_exit_critical();
    return status;
}

E2P_ATTR
void nor_flash_erase(nor_flash_config_t *cfg, uint32_t start_addr, uint32_t size)
{
    uint32_t sector_size = cfg->sector_size;
    for (uint32_t i = 0; i < size / sector_size; i++)
    {
        nor_flash_erase_sector(cfg, start_addr + i * sector_size);
    }
}
