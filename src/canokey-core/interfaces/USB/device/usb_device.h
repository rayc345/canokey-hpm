/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __USB_DEVICE__H__
#define __USB_DEVICE__H__

#include <stdint.h>

void canokey_usb_device_init(void);
void canokey_usb_device_deinit(void);
void usb_resources_alloc(void);

#endif /* __USB_DEVICE__H__ */
