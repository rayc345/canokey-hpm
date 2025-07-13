/* SPDX-License-Identifier: Apache-2.0 */
#ifndef _WEBUSB_H_
#define _WEBUSB_H_

#define WEBUSB_EP0_SENDER 0x01

#define WEBUSB_REQ_CMD 0x00
#define WEBUSB_REQ_RESP 0x01
#define WEBUSB_REQ_STAT 0x02

uint8_t USBD_WEBUSB_Init(uint8_t busid);
uint8_t USBD_WEBUSB_TxSent(uint8_t busid);
uint8_t USBD_WEBUSB_RxReady(uint8_t busid);
void WebUSB_Loop(void);

#endif // _WEBUSB_H_
