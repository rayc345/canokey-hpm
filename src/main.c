/*
 * Copyright (c) 2021-2025 HPMicro
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdio.h>
#include "board.h"
// #include "hpm_rng_drv.h"
#include "usb_config.h"
#include "lfs_port.h"
#include <apdu.h>
#include <applets.h>
#include <device.h>
#include "usbd.h"
#include <rand.h>

extern void device_periodic_task(void);
extern void fido_usb_device_init(uint8_t busid, uint32_t reg_base);

// uint32_t random32(void)
//{
//     uint32_t rand;
//     hpm_stat_t stat;
//     stat = rng_rand_wait(HPM_RNG, &rand, sizeof(rand));
//     if (stat)
//     {
//         printf("failed to rng_rand_wait: 0x%x\n", stat);
//         return 1;
//     }
//     return rand;
// }

int main(void)
{
    board_init();
    board_init_led_pins();
    // clock_add_to_group(clock_rng, 0);
    // hpm_stat_t stat;
    // stat = rng_init(HPM_RNG);
    // if (stat)
    //{
    //     printf("failed to rng_init: 0x%x\n", stat);
    //     return 1;
    // }
    // printf("rng get rand wait\n");
    board_init_usb((USB_Type *)CONFIG_HPM_USBD_BASE);
    intc_set_irq_priority(CONFIG_HPM_USBD_IRQn, 2);
    printf("cherry usb hid_custom in/out device sample.\n");

    littlefs_init();
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
