// SPDX-License-Identifier: Apache-2.0
// #include "device-config.h"
#include "board.h"
#include <device.h>
#include "hpm_gpio_drv.h"

/* This file overrides functions defined in canokey-core/src/device.c */

const uint32_t UNTOUCHED_MAX_VAL = 40; /* Suitable for 56K pull-down resistor */
const uint32_t CALI_TIMES = 4;
const uint32_t TOUCH_GAP_TIME = TOUCH_EXPIRE_TIME; /* Gap period (in ms) between two consecutive touch events */
const uint32_t MIN_LONG_TOUCH_TIME = 500;
const uint32_t MIN_TOUCH_TIME = 20;

// extern TIM_HandleTypeDef htim6;
// extern SPI_HandleTypeDef FM_SPI;
// extern UART_HandleTypeDef DBG_UART;

static volatile uint32_t blinking_until;

uint32_t device_get_tick(void)
{
  // return HAL_GetTick();
  uint64_t expected_ticks = hpm_csr_get_core_cycle() / (uint64_t)clock_get_core_clock_ticks_per_ms();
  return (uint32_t)expected_ticks;
}

static bool GPIO_Touched(void)
{
  if (gpio_read_pin(BOARD_APP_GPIO_CTRL, BOARD_APP_GPIO_INDEX, BOARD_APP_GPIO_PIN) == BOARD_BUTTON_PRESSED_VALUE)
  {
    return true;
  }
  else
  {
    return false;
  }
}

void led_on(void)
{
  gpio_write_pin(BOARD_LED_GPIO_CTRL, BOARD_LED_GPIO_INDEX,
                 BOARD_LED_GPIO_PIN, BOARD_LED_ON_LEVEL);
}

void led_off(void)
{
  gpio_write_pin(BOARD_LED_GPIO_CTRL, BOARD_LED_GPIO_INDEX,
                 BOARD_LED_GPIO_PIN, BOARD_LED_OFF_LEVEL);
}

void device_periodic_task(void)
{
  enum
  {
    TOUCH_STATE_IDLE,
    TOUCH_STATE_DOWN,
    TOUCH_STATE_ASSERT,
    TOUCH_STATE_DEASSERT,
  };
  static uint32_t event_tick, fsm = TOUCH_STATE_IDLE;
  uint32_t tick = HAL_GetTick();
  switch (fsm)
  {
  case TOUCH_STATE_IDLE:
    if (GPIO_Touched())
    {
      fsm = TOUCH_STATE_DOWN;
      event_tick = tick;
    }
    break;
  case TOUCH_STATE_DOWN:
    if (!GPIO_Touched() || tick - event_tick > MIN_LONG_TOUCH_TIME)
    {
      if (tick - event_tick > MIN_TOUCH_TIME)
      {
        set_touch_result(tick - event_tick > MIN_LONG_TOUCH_TIME ? TOUCH_LONG : TOUCH_SHORT);
        fsm = TOUCH_STATE_ASSERT;
        event_tick = tick;
      }
      else
        fsm = TOUCH_STATE_IDLE;
    }
    break;
  case TOUCH_STATE_ASSERT:
    if (tick - event_tick >= TOUCH_GAP_TIME)
    {
      set_touch_result(TOUCH_NO);
      fsm = TOUCH_STATE_DEASSERT;
    }
    break;
  case TOUCH_STATE_DEASSERT:
    if (!GPIO_Touched())
    {
      fsm = TOUCH_STATE_IDLE;
    }
    break;
  default:
    break;
  }
  device_update_led();
}

int device_atomic_compare_and_swap(volatile uint32_t *var, uint32_t expect, uint32_t update)
{
  // int status = 0;
  // do
  //{
  //   if (__LDREXW(var) != expect)
  //     return -1;
  //   status = __STREXW(update, var); // Try to set
  // } while (status != 0); // retry until updated
  //__DMB(); // Do not start any other memory access
  return 0;
}

// ARM Cortex-M Programming Guide to Memory Barrier Instructions,	Application Note 321

int device_spinlock_lock(volatile uint32_t *lock, uint32_t blocking)
{
  //// Note: __LDREXW and __STREXW are CMSIS functions
  // int status = 0;
  // do
  //{
  //   while (__LDREXW(lock) != 0)
  //     if (!blocking)
  //       return -1;
  //     else
  //     {
  //     } // Wait until
  //   // lock is free
  //   status = __STREXW(1, lock); // Try to set
  //   // lock
  // } while (status != 0); // retry until lock successfully
  //__DMB(); // Do not start any other memory access
  //// until memory barrier is completed
  return 0;
}

void device_spinlock_unlock(volatile uint32_t *lock)
{
  //// Note: __LDREXW and __STREXW are CMSIS functions
  //__DMB(); // Ensure memory operations completed before
  //// releasing lock
  *lock = 0;
}
