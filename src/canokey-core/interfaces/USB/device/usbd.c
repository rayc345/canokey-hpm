/*
 * Copyright (c) 2025 HPMicro
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "board.h"
#include "usbd.h"
#include "usbd_core.h"
#include "usbd_hid.h"
#include "usb_hid.h"
#include "ctaphid.h"
#include "device.h"

enum
{
    ITF_NUM_CTAPHID = 0,
    ITF_NUM_TOTAL
};

// CTAP_HID
#define CTAPHID_IN_EP 0x81
#define CTAPHID_OUT_EP 0x01

#define CTAPHID_EP_MPS_HS 512
#define CTAPHID_EP_MPS_FS 64
#define CTAPHID_EP_INTERVAL 10

#define CTAPHID_REPORT_CNT 64
#define HID_CTAPHID_REPORT_DESC_SIZE 34

#define USB_CONFIG_SIZE (9 + HID_CUSTOM_INOUT_DESCRIPTOR_LEN)

static const uint8_t device_descriptor[] = {
    USB_DEVICE_DESCRIPTOR_INIT(USB_2_0, 0x00, 0x00, 0x00, USBD_VID, USBD_PID, 0x0002, 0x01)};

static const uint8_t config_descriptor_hs[] = {
    USB_CONFIG_DESCRIPTOR_INIT(USB_CONFIG_SIZE, ITF_NUM_TOTAL, 0x01, USB_CONFIG_BUS_POWERED, USBD_MAX_POWER),
    /************** Descriptor of CTAPHID interface ****************/
    HID_CUSTOM_INOUT_DESCRIPTOR_INIT(ITF_NUM_CTAPHID, 0x00, HID_CTAPHID_REPORT_DESC_SIZE, CTAPHID_IN_EP, CTAPHID_OUT_EP, CTAPHID_EP_MPS_HS, CTAPHID_EP_INTERVAL),
    // clang-format on
};

static const uint8_t config_descriptor_fs[] = {
    USB_CONFIG_DESCRIPTOR_INIT(USB_CONFIG_SIZE, ITF_NUM_TOTAL, 0x01, USB_CONFIG_BUS_POWERED, USBD_MAX_POWER),
    /************** Descriptor of CTAPHID interface ****************/
    HID_CUSTOM_INOUT_DESCRIPTOR_INIT(ITF_NUM_CTAPHID, 0x00, HID_CTAPHID_REPORT_DESC_SIZE, CTAPHID_IN_EP, CTAPHID_OUT_EP, CTAPHID_EP_MPS_FS, CTAPHID_EP_INTERVAL),
    // clang-format on
};

static const uint8_t device_quality_descriptor[] = {
    USB_DEVICE_QUALIFIER_DESCRIPTOR_INIT(USB_2_0, 0x00, 0x00, 0x00, 0x01),
};

static const uint8_t other_speed_config_descriptor_hs[] = {
    USB_OTHER_SPEED_CONFIG_DESCRIPTOR_INIT(USB_CONFIG_SIZE, ITF_NUM_TOTAL, 0x01, USB_CONFIG_BUS_POWERED, USBD_MAX_POWER),
    /************** Descriptor of CTAPHID interface ****************/
    HID_CUSTOM_INOUT_DESCRIPTOR_INIT(ITF_NUM_CTAPHID, 0x00, HID_CTAPHID_REPORT_DESC_SIZE, CTAPHID_IN_EP, CTAPHID_OUT_EP, CTAPHID_EP_MPS_HS, CTAPHID_EP_INTERVAL),
    // clang-format on
};

static const uint8_t other_speed_config_descriptor_fs[] = {
    USB_OTHER_SPEED_CONFIG_DESCRIPTOR_INIT(USB_CONFIG_SIZE, ITF_NUM_TOTAL, 0x01, USB_CONFIG_BUS_POWERED, USBD_MAX_POWER),
    /************** Descriptor of CTAPHID interface ****************/
    HID_CUSTOM_INOUT_DESCRIPTOR_INIT(ITF_NUM_CTAPHID, 0x00, HID_CTAPHID_REPORT_DESC_SIZE, CTAPHID_IN_EP, CTAPHID_OUT_EP, CTAPHID_EP_MPS_FS, CTAPHID_EP_INTERVAL),
    // clang-format on
};

static const char *const string_descriptors[] = {
    (const char[]){0x09, 0x04}, /* Langid */
    "canokeys.org",             /* Manufacturer */
    "CanoKey",                  /* Product */
    "10101010",                 /* Serial Number */
};

static const uint8_t *device_descriptor_callback(uint8_t speed)
{
    (void)speed;
    return device_descriptor;
}

static const uint8_t *config_descriptor_callback(uint8_t speed)
{
    if (speed == USB_SPEED_HIGH)
    {
        return config_descriptor_hs;
    }
    else if (speed == USB_SPEED_FULL)
    {
        return config_descriptor_fs;
    }
    else
    {
        return NULL;
    }
}

static const uint8_t *device_quality_descriptor_callback(uint8_t speed)
{
    (void)speed;
    return device_quality_descriptor;
}

static const uint8_t *other_speed_config_descriptor_callback(uint8_t speed)
{
    if (speed == USB_SPEED_HIGH)
    {
        return other_speed_config_descriptor_hs;
    }
    else if (speed == USB_SPEED_FULL)
    {
        return other_speed_config_descriptor_fs;
    }
    else
    {
        return NULL;
    }
}

static const char *string_descriptor_callback(uint8_t speed, uint8_t index)
{
    (void)speed;
    if (index >= (sizeof(string_descriptors) / sizeof(char *)))
    {
        return NULL;
    }
    return string_descriptors[index];
}

const struct usb_descriptor canokey_descriptor = {
    .device_descriptor_callback = device_descriptor_callback,
    .config_descriptor_callback = config_descriptor_callback,
    .device_quality_descriptor_callback = device_quality_descriptor_callback,
    .other_speed_descriptor_callback = other_speed_config_descriptor_callback,
    .string_descriptor_callback = string_descriptor_callback,
};

/*!< ctap hid report descriptor */
static const uint8_t hid_ctaphid_report_desc[HID_CTAPHID_REPORT_DESC_SIZE] = {
    0x06, 0xD0, 0xF1,         // USAGE_PAGE (CTAP Usage Page)
    0x09, 0x01,               // USAGE (CTAP HID)
    0xA1, 0x01,               // COLLECTION (Application)
    0x09, 0x20,               //   USAGE (Usage Data In)
    0x15, 0x00,               //   LOGICAL_MINIMUM (0)
    0x26, 0xFF, 0x00,         //   LOGICAL_MAXIMUM (255)
    0x75, 0x08,               //   REPORT_SIZE (8)
    0x95, CTAPHID_REPORT_CNT, //   REPORT_COUNT (64)
    0x81, 0x02,               //   INPUT (Data,Var,Abs)
    0x09, 0x21,               //   USAGE (Usage Data Out)
    0x15, 0x00,               //   LOGICAL_MINIMUM (0)
    0x26, 0xFF, 0x00,         //   LOGICAL_MAXIMUM (255)
    0x75, 0x08,               //   REPORT_SIZE (8)
    0x95, CTAPHID_REPORT_CNT, //   REPORT_COUNT (64)
    0x91, 0x02,               //   OUTPUT (Data,Var,Abs)
    0xC0                      // END_COLLECTION
};

static USB_NOCACHE_RAM_SECTION USB_MEM_ALIGNX uint8_t ctaphid_buffer[CTAPHID_REPORT_CNT + 1];

static volatile uint8_t ctaphid_state;

static void usbd_event_handler(uint8_t busid, uint8_t event)
{
    switch (event)
    {
    case USBD_EVENT_RESET:
        break;
    case USBD_EVENT_CONNECTED:
        break;
    case USBD_EVENT_DISCONNECTED:
        break;
    case USBD_EVENT_RESUME:
        break;
    case USBD_EVENT_SUSPEND:
        break;
    case USBD_EVENT_CONFIGURED:
        ctaphid_state = CTAPHID_IDLE;
        /* setup first out ep read transfer */
        usbd_ep_start_read(busid, CTAPHID_OUT_EP, ctaphid_buffer, CTAPHID_REPORT_CNT);
        CTAPHID_Init();
        break;
    case USBD_EVENT_SET_REMOTE_WAKEUP:
        break;
    case USBD_EVENT_CLR_REMOTE_WAKEUP:
        break;

    default:
        break;
    }
}

static void usbd_hid_ctaphid_in_callback(uint8_t busid, uint8_t ep, uint32_t nbytes)
{
    (void)busid;
    (void)ep;
    ctaphid_state = CTAPHID_IDLE;
}

static void usbd_hid_ctaphid_out_callback(uint8_t busid, uint8_t ep, uint32_t nbytes)
{
    CTAPHID_OutEvent(ctaphid_buffer);
    usbd_ep_start_read(busid, ep, ctaphid_buffer, CTAPHID_REPORT_CNT);
}

uint8_t USBD_CTAPHID_SendReport(uint8_t busid, uint8_t *report, uint16_t len)
{
    int retry = 0;
    while (ctaphid_state != CTAPHID_IDLE)
    {
        // if reports are not being processed on host, we may get stuck here
        if (++retry > 50)
            return 1;
        device_delay(1);
    }
    ctaphid_state = CTAPHID_BUSY;
    memcpy(ctaphid_buffer, report, len);
    return usbd_ep_start_write(busid, CTAPHID_IN_EP, ctaphid_buffer, len);
}

static struct usbd_endpoint ctaphid_in_ep = {
    .ep_cb = usbd_hid_ctaphid_in_callback,
    .ep_addr = CTAPHID_IN_EP};

static struct usbd_endpoint ctaphid_out_ep = {
    .ep_cb = usbd_hid_ctaphid_out_callback,
    .ep_addr = CTAPHID_OUT_EP};

struct usbd_interface ctaphidintf;

void canokey_init(uint8_t busid, uintptr_t reg_base)
{
    usbd_desc_register(busid, &canokey_descriptor);

    usbd_add_interface(busid, usbd_hid_init_intf(busid, &ctaphidintf, hid_ctaphid_report_desc, HID_CTAPHID_REPORT_DESC_SIZE));
    usbd_add_endpoint(busid, &ctaphid_in_ep);
    usbd_add_endpoint(busid, &ctaphid_out_ep);

    usbd_initialize(busid, reg_base, usbd_event_handler);
}
