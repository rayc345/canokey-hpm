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

void device_delay(int ms)
{
  board_delay_ms(ms);
}

void device_set_timeout(void (*callback)(void), uint16_t timeout)
{
  board_timer_create(timeout, callback);
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
  uint32_t tick = device_get_tick();
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

int device_spinlock_lock(volatile uint32_t *lock, uint32_t blocking)
{
  // Not really working, for test only
  while (*lock)
  {
    if (!blocking)
    {
      return -1;
    }
  }
  *lock = 1;
  return 0;
}

void device_spinlock_unlock(volatile uint32_t *lock)
{
  *lock = 0;
}

int device_atomic_compare_and_swap(volatile uint32_t *var, uint32_t expect, uint32_t update)
{
  if (*var == expect)
  {
    *var = update;
    return 0;
  }
  else
  {
    return -1;
  }

  // register unsigned int ret;
  // register unsigned int __rc;
  // __asm__ __volatile__(
  //     "0: lr.w %0, %2\n"
  //     "   bne  %0, %z3, 1f\n"
  //     "   sc.w.rl %1, %z4, %2\n"
  //     "   bnez %1, 0b\n"
  //     "   fence rw, rw\n"
  //     "1:\n"
  //     : "=&r"(ret), "=&r"(__rc), "+A"(*var)
  //     : "rJ"((long)expect), "rJ"(update)
  //     : "memory");
  // return ret;
}