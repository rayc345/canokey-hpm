/* SPDX-License-Identifier: Apache-2.0 */
#ifndef _WEBUSB_H_
#define _WEBUSB_H_

// #include "usbd_core.h"

#define WEBUSB_EP0_SENDER 0x01

#define WEBUSB_REQ_CMD 0x00
#define WEBUSB_REQ_RESP 0x01
#define WEBUSB_REQ_STAT 0x02

uint8_t USBD_WEBUSB_Init(void);
// int USBD_WEBUSB_Setup(uint8_t busid, struct usb_setup_packet *setup, uint8_t **data, uint32_t *len);
void USBD_WEBUSB_TxSent(uint8_t busid);
void USBD_WEBUSB_RxReady(uint8_t busid);
void WebUSB_Loop(void);

#endif // _WEBUSB_H_
