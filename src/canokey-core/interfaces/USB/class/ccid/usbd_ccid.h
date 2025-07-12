/* SPDX-License-Identifier: Apache-2.0 */
#ifndef _USBD_CCID_H_
#define _USBD_CCID_H_

#include <ccid.h>
#include <usbd_ioreq.h>

// CCID Bulk State machine
#define CCID_STATE_IDLE 0
#define CCID_STATE_RECEIVE_DATA 1
#define CCID_STATE_DATA_IN 2
#define CCID_STATE_DATA_IN_WITH_ZLP 3
#define CCID_STATE_PROCESS_DATA 4
#define CCID_STATE_DISCARD_DATA 5
#define CCID_STATE_DATA_IN_TIME_EXTENSION 6

uint8_t USBD_CCID_Init(uint8_t busid);
uint8_t USBD_CCID_DataIn(uint8_t busid);
uint8_t USBD_CCID_DataOut(uint8_t busid);
uint8_t CCID_Response_SendData(uint8_t busid, const uint8_t *buf, uint16_t len,
                               uint8_t is_time_extension_request);

#endif // _USBD_CCID_H_
