/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __USB_DEVICE__H__
#define __USB_DEVICE__H__

#include <stdint.h>

// 0xFF indicates corresponding interface disabled
typedef struct {
  uint8_t ctap_hid;
  // uint8_t webusb;
  uint8_t ccid;
  uint8_t kbd_hid;
} IFACE_TABLE_t;

// 0xFF indicates corresponding interface disabled
typedef struct {
  uint8_t ccid;
  uint8_t ctap_hid;
  uint8_t kbd_hid;
} EP_TABLE_t;

#define EP_OUT(x) (EP_TABLE.x)
#define EP_IN(x) (0x80 | EP_TABLE.x)
#define IS_ENABLED_IFACE(i) (i != 0xFF)

/** USB interface number allocation table. */
extern IFACE_TABLE_t IFACE_TABLE;
/** USB endpoint number allocation table. */
extern EP_TABLE_t EP_TABLE;

void canokey_usb_device_init(void);
void canokey_usb_device_deinit(void);
void usb_resources_alloc(void);

#endif /* __USB_DEVICE__H__ */
