/*
 * Copyright (c) 2021-2025 HPMicro
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdio.h>
#include <stdatomic.h>
#include "board.h"
// #include "hpm_rng_drv.h"
#include "lfs_port.h"
#include <apdu.h>
#include <applets.h>
#include <device.h>
#include <tusb.h>
#include "usb_device.h"


extern void device_periodic_task(void);

// uint8_t *global_buffer;
// uint8_t buffer[1500];

//uint32_t random32(void)
//{
//    uint32_t rand;
//    hpm_stat_t stat;
//    stat = rng_rand_wait(HPM_RNG, &rand, sizeof(rand));
//    if (stat)
//    {
//        printf("failed to rng_rand_wait: 0x%x\n", stat);
//        return 1;
//    }
//    return rand;
//}

int main(void)
{
    board_init();
    board_init_led_pins();
    // global_buffer = buffer;
    //clock_add_to_group(clock_rng, 0);
    //hpm_stat_t stat;
    //stat = rng_init(HPM_RNG);
    //if (stat)
    //{
    //    printf("failed to rng_init: 0x%x\n", stat);
    //    return 1;
    //}
    //printf("rng get rand wait\n");
    board_init_usb(HPM_USB0);
    printf("cherry usb hid_custom in/out device sample.\n");

    littlefs_init();
    applets_install();
    // init_apdu_buffer();
    // tusb_init();
    canokey_usb_device_init();

    board_timer_create(10, device_periodic_task);

    while (1)
    {
        device_loop(1);
    }

    return 0;

    return 0;
}
