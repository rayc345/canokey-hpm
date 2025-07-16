/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __USBDD__H__
#define __USBDD__H__

#define CTAPHID_IDLE 0
#define CTAPHID_BUSY 1

uint8_t USBD_CTAPHID_SendReport(uint8_t busid, uint8_t *report, uint16_t len);

void canokey_init(uint8_t busid, uintptr_t reg_base);

#endif /* __USBDD__H__ */
