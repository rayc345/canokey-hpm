/*
 * Copyright (c) 2023 HPMicro
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
.type device_atomic_compare_and_swap, function
.global device_atomic_compare_and_swap
device_atomic_compare_and_swap:
    lr.w t0, (a0)       #加载以前的值
    bne t0, a1, fail    #不相等则跳转到fail
    sc.w a0, a2, (a0)   #尝试更新
    ret                 #返回
fail:
    li a0, 1            #a0 = 1
    ret