/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __USB_CTAPHID_H
#define __USB_CTAPHID_H

#define CTAPHID_DESCRIPTOR_TYPE 0x21
#define CTAPHID_REPORT_DESC 0x22
#define CTAPHID_REQ_SET_IDLE 0x0A
#define USBD_CTAPHID_REPORT_BUF_SIZE 64
#define CTAPHID_REPORT_DESC_SIZE 34

typedef enum { CTAPHID_IDLE = 0, CTAPHID_BUSY } CTAPHID_StateTypeDef;

typedef struct {
  uint8_t report_buf[USBD_CTAPHID_REPORT_BUF_SIZE];
  CTAPHID_StateTypeDef state;
} USBD_CTAPHID_HandleTypeDef;

void USBD_CTAPHID_DataIn(uint8_t busid, uint8_t ep, uint32_t nbytes);
void USBD_CTAPHID_DataOut(uint8_t busid, uint8_t ep, uint32_t nbytes);
uint8_t USBD_CTAPHID_Init(uint8_t busid);
uint8_t USBD_CTAPHID_SendReport(uint8_t busid, uint8_t *report, uint16_t len);

#endif /* __USB_CTAPHID_H */
