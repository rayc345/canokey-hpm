/*
 * Copyright (c) 2025 HPMicro
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "board.h"
#include "usb_device.h"
#include "usbd_core.h"
#include "usbd_hid.h"
#include "usb_hid.h"
#include "ctaphid.h"
#include "kbdhid.h"
#include "ccid.h"
#include "webusb.h"
#include "device.h"

enum
{
    ITF_NUM_CTAPHID = 0,
    ITF_NUM_WEBUSB,
    ITF_NUM_CCID,
    ITF_NUM_KBDHID,
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

// WEBUSB
// #define WEBUSB_IN_EP (0x82)
// #define WEBUSB_OUT_EP (0x02)

// #define WEBUSB_EP_MPS_HS 512
// #define WEBUSB_EP_MPS_FS 64

#define USBD_WEBUSB_VENDOR_CODE (0x08)
#define USBD_WINUSB_VENDOR_CODE (0x09)
#define USBD_WINUSB_DESC_SET_LEN (0xB2)

#define WEBUSB_URL_STRINGS 'c', 'o', 'n', 's', 'o', 'l', 'e', '.', 'c', 'a', 'n', 'o', 'k', 'e', 'y', 's', '.', 'o', 'r', 'g'
#define URL_DESCRIPTOR_LENGTH (3 + 20)

// CCID
#define CCID_IN_EP 0x83
#define CCID_OUT_EP 0x03

#define CCID_EP_MPS_HS 512
#define CCID_EP_MPS_FS 64

// KBD_HID
#define KBDHID_INT_EP 0x84
#define KBDHID_INT_EP_SIZE 8
#define KBDHID_INT_EP_INTERVAL 10

#define HID_KBDHID_REPORT_DESC_SIZE 87

const uint8_t USBD_WinUSBDescriptorSetDescriptor[USBD_WINUSB_DESC_SET_LEN] = {
    /*
     * WCID20 descriptor set descriptor
     */
    0x0A, 0x00,                     /* Descriptor size (10 bytes) */
    0x00, 0x00,                     /* MS OS 2.0 descriptor set header */
    0x00, 0x00, 0x03, 0x06,         /* Windows version (8.1) (0x06030000) */
    USBD_WINUSB_DESC_SET_LEN, 0x00, /* Size, MS OS 2.0 descriptor set */

    /*
     * WCID20 configuration subset descriptor
     */
    0x08, 0x00, /* wLength */
    0x01, 0x00, /* wDescriptorType */
    0x00,       /* configuration No.0 */
    0x00,       /* bReserved */
    0XA8, 0X00, /* Size, MS OS 2.0 configuration subset */

    /*
     * WCID20 function subset descriptor
     */
    0x08, 0x00,     /* Descriptor size (8 bytes) */
    0x02, 0x00,     /* MS OS 2.0 function subset header  */
    ITF_NUM_WEBUSB, /* bFirstInterface */
    0x00,           /* bReserved */
    0xA0, 0x00,     /* wSubsetLength */

    /*
     * WCID20 compatible ID descriptor
     */
    0x14, 0x00,                                     /* wLength  20 */
    0x03, 0x00,                                     /* MS_OS_20_FEATURE_COMPATIBLE_ID */
    'W', 'I', 'N', 'U', 'S', 'B', 0x00, 0x00,       /* cCID_8 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* cSubCID_8 */

    /*
     * WCID20 registry property descriptor
     */
    0x84, 0x00, /* wLength: 132 */
    0x04, 0x00, /*  wDescriptorType: MS_OS_20_FEATURE_REG_PROPERTY: 0x04 (Table 9) */
    0x07, 0x00, /* wPropertyDataType: REG_MULTI_SZ (Table 15) */
    0x2a, 0x00, /* wPropertyNameLength: */
    /* bPropertyName: “DeviceInterfaceGUID”  */
    'D', 0x00, 'e', 0x00, 'v', 0x00, 'i', 0x00, 'c', 0x00, 'e', 0x00, 'I', 0x00, 'n', 0x00, 't', 0x00, 'e', 0x00,
    'r', 0x00, 'f', 0x00, 'a', 0x00, 'c', 0x00, 'e', 0x00, 'G', 0x00, 'U', 0x00, 'I', 0x00, 'D', 0x00, 's', 0x00,
    0x00, 0x00,
    0x50, 0x00, /* wPropertyDataLength  */
    /* bPropertyData: “{312bb799-598d-4469-9ca3-535c1efcbb9c}” */
    '{', 0x00, '3', 0x00, '1', 0x00, '2', 0x00, 'b', 0x00, 'b', 0x00, '7', 0x00, '9', 0x00, '9', 0x00, '-', 0x00,
    '5', 0x00, '9', 0x00, '8', 0x00, 'd', 0x00, '-', 0x00, '4', 0x00, '4', 0x00, '6', 0x00, '9', 0x00, '-', 0x00,
    '9', 0x00, 'c', 0x00, 'a', 0x00, '3', 0x00, '-', 0x00, '5', 0x00, '3', 0x00, '5', 0x00, 'c', 0x00, '1', 0x00,
    'e', 0x00, 'f', 0x00, 'c', 0x00, 'b', 0x00, 'b', 0x00, '9', 0x00, 'c', 0x00, '}', 0x00, 0x00, 0x00, 0x00, 0x00
    // clang-format on
};

const uint8_t USBD_WebUSBURLDescriptor[URL_DESCRIPTOR_LENGTH] = {
    URL_DESCRIPTOR_LENGTH,
    WEBUSB_URL_TYPE,
    WEBUSB_URL_SCHEME_HTTPS,
    WEBUSB_URL_STRINGS};

#define USBD_BOS_WTOTALLENGTH 0x39

#define LANDING_PAGE 0x01
uint8_t USBD_BinaryObjectStoreDescriptor[USBD_BOS_WTOTALLENGTH] = {
    /*
     * WCID20 BOS descriptor
     */
    0x05,                        /* bLength */
    0x0F,                        /* bDescriptorType */
    USBD_BOS_WTOTALLENGTH, 0x00, /* wTotalLength */
    0x02,                        /* bNumDeviceCaps */

    /*
     * WCID20 WebUSB Platform capability descriptor
     */
    0x18, /* Descriptor size (24 bytes) */
    0x10, /* Descriptor type (Device Capability) */
    0x05, /* Capability type (Platform) */
    0x00, /* Reserved */

    /* WebUSB Platform Capability ID (3408b638-09a9-47a0-8bfd-a0768815b665) */
    0x38, 0xB6, 0x08, 0x34,
    0xA9, 0x09, 0xA0, 0x47,
    0x8B, 0xFD, 0xA0, 0x76,
    0x88, 0x15, 0xB6, 0x65,
    0x00, 0x01,              /* WebUSB version 1.0 */
    USBD_WEBUSB_VENDOR_CODE, /* Vendor-assigned WebUSB request code */
    LANDING_PAGE,            /* Landing page */

    /*
     *WCID20 device capability descriptor
     */
    0x1C, /* Descriptor size (28 bytes) */
    0x10, /* Descriptor type (Device Capability) */
    0x05, /* Capability type (Platform) */
    0x00, /* Reserved */

    0xDF, 0x60, 0xDD, 0xD8, /* PlatformCapabilityUUID */
    0x89, 0x45, 0xC7, 0x4C,
    0x9C, 0xD2, 0x65, 0x9D,
    0x9E, 0x64, 0x8A, 0x9F,
    0x00, 0x00, 0x03, 0x06,         /* >= Win 8.1 * dwWindowsVersion */
    USBD_WINUSB_DESC_SET_LEN, 0X00, /* wDescriptorSetTotalLength */
    USBD_WINUSB_VENDOR_CODE,        /* bVendorCode */
    0X00                            /* bAltEnumCode */
                                    // clang-format on
};

struct usb_webusb_descriptor webusb_url_desc = {
    .vendor_code = USBD_WEBUSB_VENDOR_CODE,
    .string = USBD_WebUSBURLDescriptor,
    .string_len = USBD_WINUSB_DESC_SET_LEN};

struct usb_msosv2_descriptor msosv2_desc = {
    .vendor_code = USBD_WINUSB_VENDOR_CODE,
    .compat_id = USBD_WinUSBDescriptorSetDescriptor,
    .compat_id_len = USBD_WINUSB_DESC_SET_LEN,
};

struct usb_bos_descriptor bos_desc = {
    .string = USBD_BinaryObjectStoreDescriptor,
    .string_len = USBD_BOS_WTOTALLENGTH};

#define USB_CONFIG_SIZE (9 + HID_CUSTOM_INOUT_DESCRIPTOR_LEN + HID_KEYBOARD_DESCRIPTOR_LEN + 77 + 9)

static const uint8_t device_descriptor[] = {
    USB_DEVICE_DESCRIPTOR_INIT(USB_2_1, 0x00, 0x00, 0x00, USBD_VID, USBD_PID, 0x0002, 0x01)};

static const uint8_t config_descriptor_hs[] = {
    USB_CONFIG_DESCRIPTOR_INIT(USB_CONFIG_SIZE, ITF_NUM_TOTAL, 0x01, USB_CONFIG_BUS_POWERED, USBD_MAX_POWER),
    /************** Descriptor of CTAPHID interface ****************/
    HID_CUSTOM_INOUT_DESCRIPTOR_INIT(ITF_NUM_CTAPHID, 0x00, HID_CTAPHID_REPORT_DESC_SIZE, CTAPHID_IN_EP, CTAPHID_OUT_EP, CTAPHID_EP_MPS_HS, CTAPHID_EP_INTERVAL),
    /************** Descriptor of WEBUSB interface ****************/
    USB_INTERFACE_DESCRIPTOR_INIT(ITF_NUM_WEBUSB, 0x00, 0x00, USB_DEVICE_CLASS_VEND_SPECIFIC, 0xFF, 0xFF, 5),
    /************** Descriptor of CCID interface ****************/
    USB_INTERFACE_DESCRIPTOR_INIT(ITF_NUM_CCID, 0x00, 0x02, USB_DEVICE_CLASS_SMART_CARD, 0x00, 0x00, 4),
    /******************** Descriptor of CCID *************************/
    0x36,                                        /* bLength: CCID Descriptor size */
    0x21,                                        /* bDescriptorType: Functional Descriptor type. */
    0x10,                                        /* bcdCCID(LSB): CCID Class Spec release number (1.10) */
    0x01,                                        /* bcdCCID(MSB) */
    CCID_NUMBER_OF_SLOTS - 1,                    /* bMaxSlotIndex: highest available slot on this device */
    0x07,                                        /* bVoltageSupport: 5.0V/3.3V/1.8V*/
    0x02, 0x00, 0x00, 0x00,                      /* dwProtocols: Protocol T=1 */
    0xA0, 0x0F, 0x00, 0x00,                      /* dwDefaultClock: 4MHz */
    0xA0, 0x0F, 0x00, 0x00,                      /* dwMaximumClock: 4MHz */
    0x00,                                        /* bNumClockSupported : no setting from PC */
    0x00, 0xB0, 0x04, 0x00,                      /* dwDataRate: Default ICC I/O data rate */
    0x00, 0xB0, 0x04, 0x00,                      /* dwMaxDataRate: Maximum supported ICC I/O data */
    0x00,                                        /* bNumDataRatesSupported : no setting from PC */
    WBVAL(ABDATA_SIZE),                          /* dwMaxIFSD, B3-B2 */
    0x00, 0x00,                                  /* dwMaxIFSD, B1B0 */
    0x00, 0x00, 0x00, 0x00,                      /* dwSynchProtocols  */
    0x00, 0x00, 0x00, 0x00,                      /* dwMechanical: no special characteristics */
    0xFE, 0x00, 0x04, 0x00,                      /* dwFeatures */
    WBVAL((ABDATA_SIZE + CCID_CMD_HEADER_SIZE)), /* dwMaxCCIDMessageLength, B3-B2 */
    0x00, 0x00,                                  /* dwMaxCCIDMessageLength, B1B0 */
    0xFF,                                        /* bClassGetResponse*/
    0xFF,                                        /* bClassEnvelope */
    0x00, 0x00,                                  /* wLcdLayout: 0000h no LCD */
    0x00,                                        /* bPINSupport: no PIN */
    CCID_NUMBER_OF_SLOTS,                        /* bMaxCCIDBusySlots*/
    USB_ENDPOINT_DESCRIPTOR_INIT(CCID_IN_EP, USB_ENDPOINT_TYPE_BULK, CCID_EP_MPS_HS, 0x00),
    USB_ENDPOINT_DESCRIPTOR_INIT(CCID_OUT_EP, USB_ENDPOINT_TYPE_BULK, CCID_EP_MPS_HS, 0x00),
    /************** Descriptor of KBDHID interface ****************/
    HID_KEYBOARD_DESCRIPTOR_INIT(ITF_NUM_KBDHID, 0x00, HID_KBDHID_REPORT_DESC_SIZE, KBDHID_INT_EP, KBDHID_INT_EP_SIZE, KBDHID_INT_EP_INTERVAL),
    // clang-format on
};

static const uint8_t config_descriptor_fs[] = {
    USB_CONFIG_DESCRIPTOR_INIT(USB_CONFIG_SIZE, ITF_NUM_TOTAL, 0x01, USB_CONFIG_BUS_POWERED, USBD_MAX_POWER),
    /************** Descriptor of CTAPHID interface ****************/
    HID_CUSTOM_INOUT_DESCRIPTOR_INIT(ITF_NUM_CTAPHID, 0x00, HID_CTAPHID_REPORT_DESC_SIZE, CTAPHID_IN_EP, CTAPHID_OUT_EP, CTAPHID_EP_MPS_FS, CTAPHID_EP_INTERVAL),
    /************** Descriptor of WEBUSB interface ****************/
    USB_INTERFACE_DESCRIPTOR_INIT(ITF_NUM_WEBUSB, 0x00, 0x00, USB_DEVICE_CLASS_VEND_SPECIFIC, 0xFF, 0xFF, 5),
    /************** Descriptor of CCID interface ****************/
    USB_INTERFACE_DESCRIPTOR_INIT(ITF_NUM_CCID, 0x00, 0x02, USB_DEVICE_CLASS_SMART_CARD, 0x00, 0x00, 4),
    /******************** Descriptor of CCID *************************/
    0x36,                                        /* bLength: CCID Descriptor size */
    0x21,                                        /* bDescriptorType: Functional Descriptor type. */
    0x10,                                        /* bcdCCID(LSB): CCID Class Spec release number (1.10) */
    0x01,                                        /* bcdCCID(MSB) */
    CCID_NUMBER_OF_SLOTS - 1,                    /* bMaxSlotIndex: highest available slot on this device */
    0x07,                                        /* bVoltageSupport: 5.0V/3.3V/1.8V*/
    0x02, 0x00, 0x00, 0x00,                      /* dwProtocols: Protocol T=1 */
    0xA0, 0x0F, 0x00, 0x00,                      /* dwDefaultClock: 4MHz */
    0xA0, 0x0F, 0x00, 0x00,                      /* dwMaximumClock: 4MHz */
    0x00,                                        /* bNumClockSupported : no setting from PC */
    0x00, 0xB0, 0x04, 0x00,                      /* dwDataRate: Default ICC I/O data rate */
    0x00, 0xB0, 0x04, 0x00,                      /* dwMaxDataRate: Maximum supported ICC I/O data */
    0x00,                                        /* bNumDataRatesSupported : no setting from PC */
    WBVAL(ABDATA_SIZE),                          /* dwMaxIFSD, B3-B2 */
    0x00, 0x00,                                  /* dwMaxIFSD, B1B0 */
    0x00, 0x00, 0x00, 0x00,                      /* dwSynchProtocols  */
    0x00, 0x00, 0x00, 0x00,                      /* dwMechanical: no special characteristics */
    0xFE, 0x00, 0x04, 0x00,                      /* dwFeatures */
    WBVAL((ABDATA_SIZE + CCID_CMD_HEADER_SIZE)), /* dwMaxCCIDMessageLength, B3-B2 */
    0x00, 0x00,                                  /* dwMaxCCIDMessageLength, B1B0 */
    0xFF,                                        /* bClassGetResponse*/
    0xFF,                                        /* bClassEnvelope */
    0x00, 0x00,                                  /* wLcdLayout: 0000h no LCD */
    0x00,                                        /* bPINSupport: no PIN */
    CCID_NUMBER_OF_SLOTS,                        /* bMaxCCIDBusySlots*/
    USB_ENDPOINT_DESCRIPTOR_INIT(CCID_IN_EP, USB_ENDPOINT_TYPE_BULK, CCID_EP_MPS_FS, 0x00),
    USB_ENDPOINT_DESCRIPTOR_INIT(CCID_OUT_EP, USB_ENDPOINT_TYPE_BULK, CCID_EP_MPS_FS, 0x00),
    /************** Descriptor of KBDHID interface ****************/
    HID_KEYBOARD_DESCRIPTOR_INIT(ITF_NUM_KBDHID, 0x00, HID_KBDHID_REPORT_DESC_SIZE, KBDHID_INT_EP, KBDHID_INT_EP_SIZE, KBDHID_INT_EP_INTERVAL),
    // clang-format on
};

static const uint8_t device_quality_descriptor[] = {
    USB_DEVICE_QUALIFIER_DESCRIPTOR_INIT(USB_2_0, 0x00, 0x00, 0x00, 0x01),
};

static const uint8_t other_speed_config_descriptor_hs[] = {
    USB_OTHER_SPEED_CONFIG_DESCRIPTOR_INIT(USB_CONFIG_SIZE, ITF_NUM_TOTAL, 0x01, USB_CONFIG_BUS_POWERED, USBD_MAX_POWER),
    /************** Descriptor of CTAPHID interface ****************/
    HID_CUSTOM_INOUT_DESCRIPTOR_INIT(ITF_NUM_CTAPHID, 0x00, HID_CTAPHID_REPORT_DESC_SIZE, CTAPHID_IN_EP, CTAPHID_OUT_EP, CTAPHID_EP_MPS_HS, CTAPHID_EP_INTERVAL),
    /************** Descriptor of WEBUSB interface ****************/
    USB_INTERFACE_DESCRIPTOR_INIT(ITF_NUM_WEBUSB, 0x00, 0x00, USB_DEVICE_CLASS_VEND_SPECIFIC, 0xFF, 0xFF, 5),
    /************** Descriptor of CCID interface ****************/
    USB_INTERFACE_DESCRIPTOR_INIT(ITF_NUM_CCID, 0x00, 0x02, USB_DEVICE_CLASS_SMART_CARD, 0x00, 0x00, 4),
    /******************** Descriptor of CCID *************************/
    0x36,                                        /* bLength: CCID Descriptor size */
    0x21,                                        /* bDescriptorType: Functional Descriptor type. */
    0x10,                                        /* bcdCCID(LSB): CCID Class Spec release number (1.10) */
    0x01,                                        /* bcdCCID(MSB) */
    CCID_NUMBER_OF_SLOTS - 1,                    /* bMaxSlotIndex: highest available slot on this device */
    0x07,                                        /* bVoltageSupport: 5.0V/3.3V/1.8V*/
    0x02, 0x00, 0x00, 0x00,                      /* dwProtocols: Protocol T=1 */
    0xA0, 0x0F, 0x00, 0x00,                      /* dwDefaultClock: 4MHz */
    0xA0, 0x0F, 0x00, 0x00,                      /* dwMaximumClock: 4MHz */
    0x00,                                        /* bNumClockSupported : no setting from PC */
    0x00, 0xB0, 0x04, 0x00,                      /* dwDataRate: Default ICC I/O data rate */
    0x00, 0xB0, 0x04, 0x00,                      /* dwMaxDataRate: Maximum supported ICC I/O data */
    0x00,                                        /* bNumDataRatesSupported : no setting from PC */
    WBVAL(ABDATA_SIZE),                          /* dwMaxIFSD, B3-B2 */
    0x00, 0x00,                                  /* dwMaxIFSD, B1B0 */
    0x00, 0x00, 0x00, 0x00,                      /* dwSynchProtocols  */
    0x00, 0x00, 0x00, 0x00,                      /* dwMechanical: no special characteristics */
    0xFE, 0x00, 0x04, 0x00,                      /* dwFeatures */
    WBVAL((ABDATA_SIZE + CCID_CMD_HEADER_SIZE)), /* dwMaxCCIDMessageLength, B3-B2 */
    0x00, 0x00,                                  /* dwMaxCCIDMessageLength, B1B0 */
    0xFF,                                        /* bClassGetResponse*/
    0xFF,                                        /* bClassEnvelope */
    0x00, 0x00,                                  /* wLcdLayout: 0000h no LCD */
    0x00,                                        /* bPINSupport: no PIN */
    CCID_NUMBER_OF_SLOTS,                        /* bMaxCCIDBusySlots*/
    USB_ENDPOINT_DESCRIPTOR_INIT(CCID_IN_EP, USB_ENDPOINT_TYPE_BULK, CCID_EP_MPS_HS, 0x00),
    USB_ENDPOINT_DESCRIPTOR_INIT(CCID_OUT_EP, USB_ENDPOINT_TYPE_BULK, CCID_EP_MPS_HS, 0x00),
    /************** Descriptor of KBDHID interface ****************/
    HID_KEYBOARD_DESCRIPTOR_INIT(ITF_NUM_KBDHID, 0x00, HID_KBDHID_REPORT_DESC_SIZE, KBDHID_INT_EP, KBDHID_INT_EP_SIZE, KBDHID_INT_EP_INTERVAL),
    // clang-format on
};

static const uint8_t other_speed_config_descriptor_fs[] = {
    USB_OTHER_SPEED_CONFIG_DESCRIPTOR_INIT(USB_CONFIG_SIZE, ITF_NUM_TOTAL, 0x01, USB_CONFIG_BUS_POWERED, USBD_MAX_POWER),
    /************** Descriptor of CTAPHID interface ****************/
    HID_CUSTOM_INOUT_DESCRIPTOR_INIT(ITF_NUM_CTAPHID, 0x00, HID_CTAPHID_REPORT_DESC_SIZE, CTAPHID_IN_EP, CTAPHID_OUT_EP, CTAPHID_EP_MPS_FS, CTAPHID_EP_INTERVAL),
    /************** Descriptor of WEBUSB interface ****************/
    USB_INTERFACE_DESCRIPTOR_INIT(ITF_NUM_WEBUSB, 0x00, 0x00, USB_DEVICE_CLASS_VEND_SPECIFIC, 0xFF, 0xFF, 5),
    /************** Descriptor of CCID interface ****************/
    USB_INTERFACE_DESCRIPTOR_INIT(ITF_NUM_CCID, 0x00, 0x02, USB_DEVICE_CLASS_SMART_CARD, 0x00, 0x00, 4),
    /******************** Descriptor of CCID *************************/
    0x36,                                        /* bLength: CCID Descriptor size */
    0x21,                                        /* bDescriptorType: Functional Descriptor type. */
    0x10,                                        /* bcdCCID(LSB): CCID Class Spec release number (1.10) */
    0x01,                                        /* bcdCCID(MSB) */
    CCID_NUMBER_OF_SLOTS - 1,                    /* bMaxSlotIndex: highest available slot on this device */
    0x07,                                        /* bVoltageSupport: 5.0V/3.3V/1.8V*/
    0x02, 0x00, 0x00, 0x00,                      /* dwProtocols: Protocol T=1 */
    0xA0, 0x0F, 0x00, 0x00,                      /* dwDefaultClock: 4MHz */
    0xA0, 0x0F, 0x00, 0x00,                      /* dwMaximumClock: 4MHz */
    0x00,                                        /* bNumClockSupported : no setting from PC */
    0x00, 0xB0, 0x04, 0x00,                      /* dwDataRate: Default ICC I/O data rate */
    0x00, 0xB0, 0x04, 0x00,                      /* dwMaxDataRate: Maximum supported ICC I/O data */
    0x00,                                        /* bNumDataRatesSupported : no setting from PC */
    WBVAL(ABDATA_SIZE),                          /* dwMaxIFSD, B3-B2 */
    0x00, 0x00,                                  /* dwMaxIFSD, B1B0 */
    0x00, 0x00, 0x00, 0x00,                      /* dwSynchProtocols  */
    0x00, 0x00, 0x00, 0x00,                      /* dwMechanical: no special characteristics */
    0xFE, 0x00, 0x04, 0x00,                      /* dwFeatures */
    WBVAL((ABDATA_SIZE + CCID_CMD_HEADER_SIZE)), /* dwMaxCCIDMessageLength, B3-B2 */
    0x00, 0x00,                                  /* dwMaxCCIDMessageLength, B1B0 */
    0xFF,                                        /* bClassGetResponse*/
    0xFF,                                        /* bClassEnvelope */
    0x00, 0x00,                                  /* wLcdLayout: 0000h no LCD */
    0x00,                                        /* bPINSupport: no PIN */
    CCID_NUMBER_OF_SLOTS,                        /* bMaxCCIDBusySlots*/
    USB_ENDPOINT_DESCRIPTOR_INIT(CCID_IN_EP, USB_ENDPOINT_TYPE_BULK, CCID_EP_MPS_FS, 0x00),
    USB_ENDPOINT_DESCRIPTOR_INIT(CCID_OUT_EP, USB_ENDPOINT_TYPE_BULK, CCID_EP_MPS_FS, 0x00),
    /************** Descriptor of KBDHID interface ****************/
    HID_KEYBOARD_DESCRIPTOR_INIT(ITF_NUM_KBDHID, 0x00, HID_KBDHID_REPORT_DESC_SIZE, KBDHID_INT_EP, KBDHID_INT_EP_SIZE, KBDHID_INT_EP_INTERVAL),
    // clang-format on
};

static const char *const string_descriptors[] = {
    (const char[]){0x09, 0x04}, /* Langid */
    "canokeys.org",             /* Manufacturer */
    "CanoKey",                  /* Product */
    "10101010",                 /* Serial Number */
    "OpenPGP PIV OATH",
    // "FIDO2/U2F",
    // "Keyboard",
    "WebUSB"};

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
    .msosv2_descriptor = &msosv2_desc,
    .webusb_url_descriptor = &webusb_url_desc,
    .bos_descriptor = &bos_desc,
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

/*!< keyboard hid report descriptor */
static const uint8_t hid_keyboardhid_report_desc[HID_KBDHID_REPORT_DESC_SIZE] = {
    0x05, 0x01,       // Usage Page (Generic Desktop Ctrls)
    0x09, 0x06,       // Usage (Keyboard)
    0xA1, 0x01,       // Collection (Application)
    0x85, 0x01,       //   Report ID (1)
    0x05, 0x07,       //   Usage Page (Kbrd/Keypad)
    0x19, 0xE0,       //   Usage Minimum (0xE0)
    0x29, 0xE7,       //   Usage Maximum (0xE7)
    0x15, 0x00,       //   Logical Minimum (0)
    0x25, 0x01,       //   Logical Maximum (1)
    0x75, 0x01,       //   Report Size (1)
    0x95, 0x08,       //   Report Count (8)
    0x81, 0x02,       //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x95, 0x01,       //   Report Count (1)
    0x75, 0x08,       //   Report Size (8)
    0x81, 0x03,       //   Input (Const,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x95, 0x05,       //   Report Count (5)
    0x75, 0x01,       //   Report Size (1)
    0x05, 0x08,       //   Usage Page (LEDs)
    0x19, 0x01,       //   Usage Minimum (Num Lock)
    0x29, 0x05,       //   Usage Maximum (Kana)
    0x91, 0x02,       //   Output (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile)
    0x95, 0x01,       //   Report Count (1)
    0x75, 0x03,       //   Report Size (3)
    0x91, 0x03,       //   Output (Const,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile)
    0x95, 0x05,       //   Report Count (5)
    0x75, 0x08,       //   Report Size (8)
    0x15, 0x00,       //   Logical Minimum (0)
    0x25, 0x65,       //   Logical Maximum (101)
    0x05, 0x07,       //   Usage Page (Kbrd/Keypad)
    0x19, 0x00,       //   Usage Minimum (0x00)
    0x29, 0x65,       //   Usage Maximum (0x65)
    0x81, 0x00,       //   Input (Data,Array,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0xC0,             // End Collection
    0x05, 0x0C,       // Usage Page (Consumer)
    0x09, 0x01,       // Usage (Consumer Control)
    0xA1, 0x01,       // Collection (Application)
    0x85, 0x02,       //   Report ID (2)
    0x15, 0x00,       //   Logical Minimum (0)
    0x25, 0x01,       //   Logical Maximum (1)
    0x75, 0x08,       //   Report Size (1)
    0x95, 0x01,       //   Report Count (1)
    0x0A, 0xAE, 0x01, //   Usage (AL Keyboard Layout)
    0x81, 0x06,       //   Input (Data,Var,Rel,No Wrap,Linear,Preferred State,No Null Position)
    0xC0,             // End Collection
};

static USB_NOCACHE_RAM_SECTION USB_MEM_ALIGNX uint8_t ctaphid_buffer[CTAPHID_REPORT_CNT + 1];
// static USB_NOCACHE_RAM_SECTION USB_MEM_ALIGNX uint8_t webusb_buffer[WEBUSB_EP_MPS_HS + 1];
static USB_NOCACHE_RAM_SECTION USB_MEM_ALIGNX uint8_t ccid_buffer[CCID_EP_MPS_HS + 1];
static USB_NOCACHE_RAM_SECTION USB_MEM_ALIGNX uint8_t kbdhid_buffer[KBDHID_INT_EP_SIZE + 1];

static volatile uint8_t ctaphid_state;
static volatile uint8_t ccid_state;
static volatile uint8_t kbdhid_state;

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
        ccid_state = CCID_STATE_IDLE;
        kbdhid_state = KBDHID_IDLE;
        /* setup first out ep read transfer */
        usbd_ep_start_read(busid, CTAPHID_OUT_EP, ctaphid_buffer, CTAPHID_REPORT_CNT);
        // usbd_ep_start_read(busid, WEBUSB_OUT_EP, webusb_buffer, usbd_get_ep_mps(busid, WEBUSB_OUT_EP));
        usbd_ep_start_read(busid, CCID_OUT_EP, ccid_buffer, usbd_get_ep_mps(busid, CCID_OUT_EP));
        CTAPHID_Init();
        USBD_WEBUSB_Init();
        CCID_Init();
        KBDHID_Init();
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

// // WebUSB
// void usbd_webusb_out(uint8_t busid, uint8_t ep, uint32_t nbytes)
// {
//     usbd_ep_start_write(busid, WEBUSB_IN_EP, webusb_buffer, nbytes); /* echo back */
//     /* setup next out ep read transfer */
//     usbd_ep_start_read(busid, ep, webusb_buffer, usbd_get_ep_mps(busid, ep));
// }

// void usbd_webusb_in(uint8_t busid, uint8_t ep, uint32_t nbytes)
// {
//     if ((nbytes % usbd_get_ep_mps(busid, ep)) == 0 && nbytes)
//     {
//         /* send zlp */
//         usbd_ep_start_write(busid, ep, NULL, 0);
//     }
// }

// struct usbd_endpoint webusb_out_ep = {
//     .ep_addr = WEBUSB_OUT_EP,
//     .ep_cb = usbd_webusb_out};

// struct usbd_endpoint webusb_in_ep = {
//     .ep_addr = WEBUSB_IN_EP,
//     .ep_cb = usbd_webusb_in};

struct usbd_interface webusbintf;

// CCID
void usbd_ccid_out(uint8_t busid, uint8_t ep, uint32_t nbytes)
{
    CCID_OutEvent(ccid_buffer, nbytes);
    /* setup next out ep read transfer */
    usbd_ep_start_read(busid, ep, ccid_buffer, usbd_get_ep_mps(busid, CCID_OUT_EP));
    // USB_LOG_RAW("actual out len:%d\r\n", nbytes);
}

void usbd_ccid_in(uint8_t busid, uint8_t ep, uint32_t nbytes)
{
    if (ccid_state == CCID_STATE_DATA_IN_WITH_ZLP)
    {
        ccid_state = CCID_STATE_DATA_IN;
        /* send zlp */
        usbd_ep_start_write(busid, ep, NULL, 0);
    }
    else
    {
        CCID_InFinished(ccid_state == CCID_STATE_DATA_IN_TIME_EXTENSION);
        ccid_state = CCID_STATE_IDLE;
    }
    // USB_LOG_RAW("actual in len:%d\r\n", nbytes);
}

uint8_t CCID_Response_SendData(uint8_t busid, const uint8_t *buf, uint16_t len, uint8_t is_time_extension_request)
{
    uint8_t ret = 0;

    int retry = 0;
    while (ccid_state != CCID_STATE_IDLE)
    {
        if (is_time_extension_request)
            return ret;
        else if (++retry > 50)
            return 1;
        else
            device_delay(1);
    }
    uint16_t ep_size = usbd_get_ep_mps(busid, CCID_IN_EP);
    if (is_time_extension_request)
        ccid_state = CCID_STATE_DATA_IN_TIME_EXTENSION;
    else
        ccid_state = len % ep_size == 0 ? CCID_STATE_DATA_IN_WITH_ZLP : CCID_STATE_DATA_IN;
    memcpy(ccid_buffer, buf, len);
    ret = usbd_ep_start_write(busid, CCID_IN_EP, ccid_buffer, len);

    return ret;
}

struct usbd_endpoint ccid_out_ep = {
    .ep_addr = CCID_OUT_EP,
    .ep_cb = usbd_ccid_out};

struct usbd_endpoint ccid_in_ep = {
    .ep_addr = CCID_IN_EP,
    .ep_cb = usbd_ccid_in};

struct usbd_interface ccid_intf;

void usbd_kbdhid_int_callback(uint8_t busid, uint8_t ep, uint32_t nbytes)
{
    (void)busid;
    (void)ep;
    (void)nbytes;
    kbdhid_state = KBDHID_IDLE;
}

uint8_t USBD_KBDHID_SendReport(uint8_t busid, uint8_t *report, uint16_t len)
{
    int retry = 0;
    while (kbdhid_state != KBDHID_IDLE)
    {
        // if reports are not being processed on host, we may get stuck here
        if (++retry > 50)
            return 1;
        device_delay(1);
    }
    kbdhid_state = KBDHID_BUSY;
    memcpy(kbdhid_buffer, report, len);
    return usbd_ep_start_write(busid, KBDHID_INT_EP, kbdhid_buffer, len);
}

uint8_t USBD_KBDHID_IsIdle(void)
{
    return kbdhid_state == KBDHID_IDLE;
}

static struct usbd_endpoint kbdhid_in_ep = {
    .ep_cb = usbd_kbdhid_int_callback,
    .ep_addr = KBDHID_INT_EP};

struct usbd_interface kbdintf;

int USBD_WEBUSB_Setup(uint8_t busid, struct usb_setup_packet *setup, uint8_t **data, uint32_t *len);

void canokey_init(uint8_t busid, uintptr_t reg_base)
{
    usbd_desc_register(busid, &canokey_descriptor);

    usbd_add_interface(busid, usbd_hid_init_intf(busid, &ctaphidintf, hid_ctaphid_report_desc, HID_CTAPHID_REPORT_DESC_SIZE));
    usbd_add_endpoint(busid, &ctaphid_in_ep);
    usbd_add_endpoint(busid, &ctaphid_out_ep);

    webusbintf.vendor_handler = USBD_WEBUSB_Setup;
    usbd_add_interface(busid, &webusbintf);
    // usbd_add_endpoint(busid, &webusb_out_ep);
    // usbd_add_endpoint(busid, &webusb_in_ep);

    usbd_add_interface(busid, &ccid_intf);
    usbd_add_endpoint(busid, &ccid_out_ep);
    usbd_add_endpoint(busid, &ccid_in_ep);

    usbd_add_interface(busid, usbd_hid_init_intf(busid, &kbdintf, hid_keyboardhid_report_desc, HID_KBDHID_REPORT_DESC_SIZE));
    usbd_add_endpoint(busid, &kbdhid_in_ep);
    usbd_initialize(busid, reg_base, usbd_event_handler);
}
