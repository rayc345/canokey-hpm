// SPDX-License-Identifier: Apache-2.0
// #include "device-config.h"
#include <stdio.h>
#include <stdatomic.h>
#include "board.h"
#include <device.h>
#include "hpm_gpio_drv.h"
#include "hpm_gptmr_drv.h"

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

// static board_timer_cb timer_cb_pt;
// SDK_DECLARE_EXT_ISR_M(IRQn_GPTMR2, board_tp_timer_isr)
// void board_tp_timer_isr(void)
// {
//   if (gptmr_check_status(HPM_GPTMR2, GPTMR_CH_RLD_STAT_MASK(1)))
//   {
//     gptmr_clear_status(HPM_GPTMR2, GPTMR_CH_RLD_STAT_MASK(1));
//     timer_cb_pt();
//   }
// }

static board_timer_cb timer_cb2;
SDK_DECLARE_EXT_ISR_M(IRQn_GPTMR0, board_timer_isr2)
void board_timer_isr2(void)
{
  if (gptmr_check_status(HPM_GPTMR0, GPTMR_CH_RLD_STAT_MASK(1)))
  {
    gptmr_clear_status(HPM_GPTMR0, GPTMR_CH_RLD_STAT_MASK(1));
    if (timer_cb2)
      timer_cb2();
    gptmr_stop_counter(HPM_GPTMR0, 1);
  }
}

void board_timer_create2(uint32_t ms, board_timer_cb cb)
{
  uint32_t gptmr_freq;
  gptmr_channel_config_t config;

  timer_cb2 = cb;
  gptmr_channel_get_default_config(HPM_GPTMR0, &config);

  clock_add_to_group(clock_gptmr0, 0);
  gptmr_freq = clock_get_frequency(clock_gptmr0);

  config.reload = gptmr_freq / 1000 * ms;
  gptmr_channel_config(HPM_GPTMR0, 1, &config, false);
  gptmr_enable_irq(HPM_GPTMR0, GPTMR_CH_RLD_IRQ_MASK(1));
  intc_m_enable_irq_with_priority(IRQn_GPTMR0, 1);

  gptmr_start_counter(HPM_GPTMR0, 1);
}

void device_set_timeout(void (*callback)(void), uint16_t timeout)
{
  board_timer_create2(timeout, callback);
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

int device_atomic_compare_and_swap(volatile uint32_t *var, uint32_t expect, uint32_t update)
{
  return atomic_compare_exchange_strong(var, &expect, update) == true;
}

int device_spinlock_lock(volatile uint32_t *lock, uint32_t blocking)
{
  int status;
  do
  {
    status = device_atomic_compare_and_swap(lock, 0, 1);
  } while (blocking && status != 0);
  if (status == 0)
  {
    return 0; // 加锁成功
  }
  return -1; // 加锁失败
}

void device_spinlock_unlock(volatile uint32_t *lock)
{
  device_atomic_compare_and_swap(lock, 1, 0);
  // *lock = 0;
  // int status;
  // status = device_atomic_compare_and_swap(lock, 1, 0);
  // if (status == 0)
  // {
  //   return 1; // 解锁成功
  // }
  // return 0; // 解锁失败
}