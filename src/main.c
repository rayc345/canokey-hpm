/*
 * Copyright (c) 2021-2025 HPMicro
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdio.h>
#include "board.h"
#include "hpm_rng_drv.h"
#include "hpm_gptmr_drv.h"
#include "usb_config.h"
#include "lfs_port.h"
#include <apdu.h>
#include <applets.h>
#include <device.h>
#include "usbd.h"
#include <rand.h>
#include "crypto-util.h"

extern void device_periodic_task(void);
uint32_t random32(void)
{
    uint32_t rand;
    hpm_stat_t stat;
    stat = rng_rand_wait(HPM_RNG, &rand, sizeof(rand));
    if (stat)
    {
        printf("failed to rng_rand_wait: 0x%x\n", stat);
        return 1;
    }
    return rand;
}

uint32_t device_get_tick2(void)
{
  uint64_t expected_ticks = hpm_csr_get_core_cycle() / (uint64_t)clock_get_core_clock_ticks_per_ms();
  return (uint32_t)expected_ticks;
}

uint32_t ticks;
SDK_DECLARE_EXT_ISR_M(IRQn_GPTMR2, tick_ms_isr)
void tick_ms_isr(void)
{
    if (gptmr_check_status(HPM_GPTMR2, GPTMR_CH_RLD_STAT_MASK(1))) {
        gptmr_clear_status(HPM_GPTMR2, GPTMR_CH_RLD_STAT_MASK(1));
        board_led_toggle();
        ticks++;
    }
}


int main(void)
{
    board_init();
    board_init_led_pins();
    clock_add_to_group(clock_rng, 0);
    hpm_stat_t stat;
    stat = rng_init(HPM_RNG);
    if (stat)
    {
        printf("failed to rng_init: 0x%x\n", stat);
        return 1;
    }
    printf("rng get rand wait\n");
    board_init_usb((USB_Type *)CONFIG_HPM_USBD_BASE);
    intc_set_irq_priority(CONFIG_HPM_USBD_IRQn, 2);
    printf("cherry usb hid_custom in/out device sample.\n");

    uint32_t gptmr_freq;
    gptmr_channel_config_t config;

    gptmr_freq = board_init_gptmr_clock(HPM_GPTMR2);
    gptmr_channel_get_default_config(HPM_GPTMR2, &config);

    config.reload = gptmr_freq / 1000 * 1;
    gptmr_channel_config(HPM_GPTMR2, 1, &config, false);
    gptmr_start_counter(HPM_GPTMR2, 1);
    gptmr_enable_irq(HPM_GPTMR2, GPTMR_CH_RLD_IRQ_MASK(1));
    intc_m_enable_irq_with_priority(IRQn_GPTMR2, 1);


    littlefs_init();
    crypto_rng_init();
    applets_install();
    init_apdu_buffer();
    canokey_init(0, CONFIG_HPM_USBD_BASE);

    board_timer_create(10, device_periodic_task);

    while (1)
    {
        device_loop();
    }

    return 0;

    return 0;
}
