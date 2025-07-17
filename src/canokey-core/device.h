/* SPDX-License-Identifier: Apache-2.0 */
#ifndef _DEVICE_H_
#define _DEVICE_H_

#include "common.h"

#define TOUCH_NO 0
#define TOUCH_SHORT 1
#define TOUCH_LONG 2

#define USER_PRESENCE_OK 0
#define USER_PRESENCE_CANCEL 1
#define USER_PRESENCE_TIMEOUT 2

#define WAIT_ENTRY_CCID 0
#define WAIT_ENTRY_CTAPHID 1

typedef enum {
  FM_STATUS_OK = 0,
  FM_STATUS_NACK = 1,
} fm_status_t;

// functions should be implemented by device
/**
 * Delay processing for specific milliseconds
 *
 * @param ms Time to delay
 */
void device_delay(int ms);
uint32_t device_get_tick(void);

void led_on(void);
void led_off(void);
void device_set_timeout(void (*callback)(void), uint16_t timeout);

// -----------------------------------------------------------------------------------

// platform independent functions
uint8_t wait_for_user_presence(uint8_t entry);
int strong_user_presence_test(void);
int send_keepalive_during_processing(uint8_t entry);
void device_loop(void);
uint8_t is_nfc(void);
void set_nfc_state(uint8_t state);
uint8_t get_touch_result(void);
void set_touch_result(uint8_t result);
void device_update_led(void);
/**
 * Blink for several time
 * @param sec duration, 0 for infinite
 * @param interval controls blinking frequency
 */
void start_blinking_interval(uint8_t sec, uint32_t interval);
static inline void start_blinking(uint8_t sec) {
  if (!is_nfc()) start_blinking_interval(sec, 200);
}
static inline void start_quick_blinking(uint8_t sec) {
  if (!is_nfc()) start_blinking_interval(sec, 25);
}
void device_init(void);
void stop_blinking(void);
uint8_t device_is_blinking(void);
bool device_allow_kbd_touch(void);


#endif // _DEVICE_H_
