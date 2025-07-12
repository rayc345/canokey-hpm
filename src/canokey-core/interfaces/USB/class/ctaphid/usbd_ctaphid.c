// SPDX-License-Identifier: Apache-2.0
#include <ctaphid.h>
#include <device.h>
#include "usbd.h"
// #include <usb_device.h>
#include <usbd_ctaphid.h>
// #include <usbd_ctlreq.h>

static USBD_CTAPHID_HandleTypeDef hid_handle;
USB_NOCACHE_RAM_SECTION USB_MEM_ALIGNX uint8_t ctaphid_buffer[HID_REPORT_CNT];

void USBD_CTAPHID_DataIn(uint8_t busid, uint8_t ep, uint32_t nbytes)
{
  (void)busid;
  (void)ep;
  (void)nbytes;
  hid_handle.state = CTAPHID_IDLE;
}

void USBD_CTAPHID_DataOut(uint8_t busid, uint8_t ep, uint32_t nbytes)
{
  (void)nbytes;
  // printf("RX:");
  // PRINT_HEX(read_buffer, nbytes);
  CTAPHID_OutEvent(hid_handle.report_buf);
  usbd_ep_start_read(busid, ep, ctaphid_buffer, HID_REPORT_CNT);
}

/*!< custom hid report descriptor */
static const uint8_t hid_custom_report_desc[HID_CUSTOM_REPORT_DESC_SIZE] = {
    0x06, 0xD0, 0xF1, // USAGE_PAGE (CTAP Usage Page)
    0x09, 0x01,       // USAGE (CTAP HID)
    0xA1, 0x01,       // COLLECTION (Application)
    0x09, 0x20,       //   USAGE (Usage Data In)
    0x15, 0x00,       //   LOGICAL_MINIMUM (0)
    0x26, 0xFF, 0x00, //   LOGICAL_MAXIMUM (255)
    0x75, 0x08,       //   REPORT_SIZE (8)
    0x95, 0x40,       //   REPORT_COUNT (64)
    0x81, 0x02,       //   INPUT (Data,Var,Abs)
    0x09, 0x21,       //   USAGE (Usage Data Out)
    0x15, 0x00,       //   LOGICAL_MINIMUM (0)
    0x26, 0xFF, 0x00, //   LOGICAL_MAXIMUM (255)
    0x75, 0x08,       //   REPORT_SIZE (8)
    0x95, 0x40,       //   REPORT_COUNT (64)
    0x91, 0x02,       //   OUTPUT (Data,Var,Abs)
    0xC0              // END_COLLECTION
};

static struct usbd_endpoint ctaphid_in_ep = {
    .ep_cb = USBD_CTAPHID_DataIn,
    .ep_addr = HIDRAW_IN_EP};

static struct usbd_endpoint ctaphid_out_ep = {
    .ep_cb = USBD_CTAPHID_DataOut,
    .ep_addr = HIDRAW_OUT_EP};
struct usbd_interface intf0;

uint8_t USBD_CTAPHID_Init(uint8_t busid)
{
  hid_handle.state = CTAPHID_IDLE;
  usbd_add_interface(busid, usbd_hid_init_intf(busid, &intf0, hid_custom_report_desc, HID_CUSTOM_REPORT_DESC_SIZE));
  usbd_add_endpoint(busid, &ctaphid_in_ep);
  usbd_add_endpoint(busid, &ctaphid_out_ep);

  CTAPHID_Init(USBD_CTAPHID_SendReport);
  usbd_ep_start_read(busid, HIDRAW_OUT_EP, ctaphid_buffer, HID_REPORT_CNT);
  return 0;
}

uint8_t USBD_CTAPHID_SendReport(uint8_t busid, uint8_t *report, uint16_t len)
{
  volatile CTAPHID_StateTypeDef *state = &hid_handle.state;
  int retry = 0;
  while (*state != CTAPHID_IDLE)
  {
    // if reports are not being processed on host, we may get stuck here
    if (++retry > 50)
      return 1;
    device_delay(1);
  }
  hid_handle.state = CTAPHID_BUSY;
  // USBD_LL_Transmit(pdev, EP_IN(ctap_hid), report, len);
  if (len != sizeof(ctaphid_buffer))
  {
    printf("Wrong Len\n");
    return 0;
  }
  memcpy(ctaphid_buffer, report, len);
  usbd_ep_start_write(busid, HIDRAW_IN_EP, ctaphid_buffer, len);
  return 0;
}