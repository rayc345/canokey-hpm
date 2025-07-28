/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __USBDD__H__
#define __USBDD__H__

#define CTAPHID_IDLE 0
#define CTAPHID_BUSY 1

#define KBDHID_IDLE 0
#define KBDHID_BUSY 1

// CCID Bulk State
#define CCID_STATE_IDLE 0
#define CCID_STATE_RECEIVE_DATA 1
#define CCID_STATE_DATA_IN 2
#define CCID_STATE_DATA_IN_WITH_ZLP 3
#define CCID_STATE_PROCESS_DATA 4
#define CCID_STATE_DISCARD_DATA 5
#define CCID_STATE_DATA_IN_TIME_EXTENSION 6

typedef struct {
  uint8_t id;
  uint8_t modifier;
  uint8_t reserved;
  uint8_t keycode[5];
} keyboard_report_t;

uint8_t USBD_CTAPHID_SendReport(uint8_t busid, uint8_t *report, uint16_t len);
uint8_t CCID_Response_SendData(uint8_t busid, const uint8_t *buf, uint16_t len, uint8_t is_time_extension_request);
uint8_t USBD_KBDHID_SendReport(uint8_t busid, uint8_t *report, uint16_t len);
uint8_t USBD_KBDHID_IsIdle(void);

void canokey_init(uint8_t busid, uintptr_t reg_base);

#endif /* __USBDD__H__ */
