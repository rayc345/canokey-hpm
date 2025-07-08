/*
 * Copyright (c) 2022 HPMicro
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "usbd_core.h"
#include "usbd_hid.h"
#include "ctaphid_device.h"
#include "apdu.h"
#include "ctap.h"
#include "rand.h"

/*!< hidraw in endpoint */
#define HIDRAW_IN_EP 0x81
#define HIDRAW_IN_EP_MPS_HS 1024
#define HIDRAW_IN_EP_MPS_FS 64
#define HIDRAW_IN_INTERVAL 10

/*!< hidraw out endpoint */
#define HIDRAW_OUT_EP 0x02
#define HIDRAW_OUT_EP_MPS_HS 1024
#define HIDRAW_OUT_EP_MPS_FS 64
#define HIDRAW_OUT_EP_INTERVAL 10

/*!< hid report counter */
#define HID_REPORT_CNT 64

/*!< config descriptor size */
#define USB_HID_CONFIG_DESC_SIZ (9 + 9 + 9 + 7 + 7)

/*!< custom hid report descriptor size */
#define HID_CUSTOM_REPORT_DESC_SIZE 34

static const uint8_t device_descriptor[] = {
    USB_DEVICE_DESCRIPTOR_INIT(USB_2_0, 0x00, 0x00, 0x00, USBD_VID, USBD_PID, 0x0002, 0x01)};

static const uint8_t config_descriptor_hs[] = {
    USB_CONFIG_DESCRIPTOR_INIT(USB_HID_CONFIG_DESC_SIZ, 0x01, 0x01, USB_CONFIG_BUS_POWERED, USBD_MAX_POWER),
    /************** Descriptor of Custom interface *****************/
    0x09,                          /* bLength: Interface Descriptor size */
    USB_DESCRIPTOR_TYPE_INTERFACE, /* bDescriptorType: Interface descriptor type */
    0x00,                          /* bInterfaceNumber: Number of Interface */
    0x00,                          /* bAlternateSetting: Alternate setting */
    0x02,                          /* bNumEndpoints */
    0x03,                          /* bInterfaceClass: HID */
    0x00,                          /* bInterfaceSubClass : 1=BOOT, 0=no boot */
    0x00,                          /* nInterfaceProtocol : 0=none, 1=keyboard, 2=mouse */
    0,                             /* iInterface: Index of string descriptor */
    /******************** Descriptor of Custom HID ********************/
    0x09,                    /* bLength: HID Descriptor size */
    HID_DESCRIPTOR_TYPE_HID, /* bDescriptorType: HID */
    0x11,                    /* bcdHID: HID Class Spec release number */
    0x01,
    0x00,                        /* bCountryCode: Hardware target country */
    0x01,                        /* bNumDescriptors: Number of HID class descriptors to follow */
    0x22,                        /* bDescriptorType */
    HID_CUSTOM_REPORT_DESC_SIZE, /* wItemLength: Total length of Report descriptor */
    0x00,
    /******************** Descriptor of Custom in endpoint ********************/
    0x07,                         /* bLength: Endpoint Descriptor size */
    USB_DESCRIPTOR_TYPE_ENDPOINT, /* bDescriptorType: */
    HIDRAW_IN_EP,                 /* bEndpointAddress: Endpoint Address (IN) */
    0x03,                         /* bmAttributes: Interrupt endpoint */
    WBVAL(HIDRAW_IN_EP_MPS_HS),   /* wMaxPacketSize */
    HIDRAW_IN_INTERVAL,           /* bInterval: Polling Interval */
    /******************** Descriptor of Custom out endpoint ********************/
    0x07,                         /* bLength: Endpoint Descriptor size */
    USB_DESCRIPTOR_TYPE_ENDPOINT, /* bDescriptorType: */
    HIDRAW_OUT_EP,                /* bEndpointAddress: Endpoint Address (IN) */
    0x03,                         /* bmAttributes: Interrupt endpoint */
    WBVAL(HIDRAW_OUT_EP_MPS_HS),  /* wMaxPacketSize */
    HIDRAW_OUT_EP_INTERVAL,       /* bInterval: Polling Interval */
};

static const uint8_t config_descriptor_fs[] = {
    USB_CONFIG_DESCRIPTOR_INIT(USB_HID_CONFIG_DESC_SIZ, 0x01, 0x01, USB_CONFIG_BUS_POWERED, USBD_MAX_POWER),
    /************** Descriptor of Custom interface *****************/
    0x09,                          /* bLength: Interface Descriptor size */
    USB_DESCRIPTOR_TYPE_INTERFACE, /* bDescriptorType: Interface descriptor type */
    0x00,                          /* bInterfaceNumber: Number of Interface */
    0x00,                          /* bAlternateSetting: Alternate setting */
    0x02,                          /* bNumEndpoints */
    0x03,                          /* bInterfaceClass: HID */
    0x00,                          /* bInterfaceSubClass : 1=BOOT, 0=no boot */
    0x00,                          /* nInterfaceProtocol : 0=none, 1=keyboard, 2=mouse */
    0,                             /* iInterface: Index of string descriptor */
    /******************** Descriptor of Custom HID ********************/
    0x09,                    /* bLength: HID Descriptor size */
    HID_DESCRIPTOR_TYPE_HID, /* bDescriptorType: HID */
    0x11,                    /* bcdHID: HID Class Spec release number */
    0x01,
    0x00,                        /* bCountryCode: Hardware target country */
    0x01,                        /* bNumDescriptors: Number of HID class descriptors to follow */
    0x22,                        /* bDescriptorType */
    HID_CUSTOM_REPORT_DESC_SIZE, /* wItemLength: Total length of Report descriptor */
    0x00,
    /******************** Descriptor of Custom in endpoint ********************/
    0x07,                         /* bLength: Endpoint Descriptor size */
    USB_DESCRIPTOR_TYPE_ENDPOINT, /* bDescriptorType: */
    HIDRAW_IN_EP,                 /* bEndpointAddress: Endpoint Address (IN) */
    0x03,                         /* bmAttributes: Interrupt endpoint */
    WBVAL(HIDRAW_IN_EP_MPS_FS),   /* wMaxPacketSize */
    HIDRAW_IN_INTERVAL,           /* bInterval: Polling Interval */
    /******************** Descriptor of Custom out endpoint ********************/
    0x07,                         /* bLength: Endpoint Descriptor size */
    USB_DESCRIPTOR_TYPE_ENDPOINT, /* bDescriptorType: */
    HIDRAW_OUT_EP,                /* bEndpointAddress: Endpoint Address (IN) */
    0x03,                         /* bmAttributes: Interrupt endpoint */
    WBVAL(HIDRAW_OUT_EP_MPS_FS),  /* wMaxPacketSize */
    HIDRAW_OUT_EP_INTERVAL,       /* bInterval: Polling Interval */
};

static const uint8_t device_quality_descriptor[] = {
    USB_DEVICE_QUALIFIER_DESCRIPTOR_INIT(USB_2_0, 0x00, 0x00, 0x00, 0x01),
};

static const uint8_t other_speed_config_descriptor_hs[] = {
    USB_OTHER_SPEED_CONFIG_DESCRIPTOR_INIT(USB_HID_CONFIG_DESC_SIZ, 0x01, 0x01, USB_CONFIG_BUS_POWERED, USBD_MAX_POWER),
    /************** Descriptor of Custom interface *****************/
    0x09,                          /* bLength: Interface Descriptor size */
    USB_DESCRIPTOR_TYPE_INTERFACE, /* bDescriptorType: Interface descriptor type */
    0x00,                          /* bInterfaceNumber: Number of Interface */
    0x00,                          /* bAlternateSetting: Alternate setting */
    0x02,                          /* bNumEndpoints */
    0x03,                          /* bInterfaceClass: HID */
    0x00,                          /* bInterfaceSubClass : 1=BOOT, 0=no boot */
    0x00,                          /* nInterfaceProtocol : 0=none, 1=keyboard, 2=mouse */
    0,                             /* iInterface: Index of string descriptor */
    /******************** Descriptor of Custom HID ********************/
    0x09,                    /* bLength: HID Descriptor size */
    HID_DESCRIPTOR_TYPE_HID, /* bDescriptorType: HID */
    0x11,                    /* bcdHID: HID Class Spec release number */
    0x01,
    0x00,                        /* bCountryCode: Hardware target country */
    0x01,                        /* bNumDescriptors: Number of HID class descriptors to follow */
    0x22,                        /* bDescriptorType */
    HID_CUSTOM_REPORT_DESC_SIZE, /* wItemLength: Total length of Report descriptor */
    0x00,
    /******************** Descriptor of Custom in endpoint ********************/
    0x07,                         /* bLength: Endpoint Descriptor size */
    USB_DESCRIPTOR_TYPE_ENDPOINT, /* bDescriptorType: */
    HIDRAW_IN_EP,                 /* bEndpointAddress: Endpoint Address (IN) */
    0x03,                         /* bmAttributes: Interrupt endpoint */
    WBVAL(HIDRAW_IN_EP_MPS_FS),   /* wMaxPacketSize */
    HIDRAW_IN_INTERVAL,           /* bInterval: Polling Interval */
    /******************** Descriptor of Custom out endpoint ********************/
    0x07,                         /* bLength: Endpoint Descriptor size */
    USB_DESCRIPTOR_TYPE_ENDPOINT, /* bDescriptorType: */
    HIDRAW_OUT_EP,                /* bEndpointAddress: Endpoint Address (IN) */
    0x03,                         /* bmAttributes: Interrupt endpoint */
    WBVAL(HIDRAW_OUT_EP_MPS_FS),  /* wMaxPacketSize */
    HIDRAW_OUT_EP_INTERVAL,       /* bInterval: Polling Interval */
};

static const uint8_t other_speed_config_descriptor_fs[] = {
    USB_OTHER_SPEED_CONFIG_DESCRIPTOR_INIT(USB_HID_CONFIG_DESC_SIZ, 0x01, 0x01, USB_CONFIG_BUS_POWERED, USBD_MAX_POWER),
    /************** Descriptor of Custom interface *****************/
    0x09,                          /* bLength: Interface Descriptor size */
    USB_DESCRIPTOR_TYPE_INTERFACE, /* bDescriptorType: Interface descriptor type */
    0x00,                          /* bInterfaceNumber: Number of Interface */
    0x00,                          /* bAlternateSetting: Alternate setting */
    0x02,                          /* bNumEndpoints */
    0x03,                          /* bInterfaceClass: HID */
    0x00,                          /* bInterfaceSubClass : 1=BOOT, 0=no boot */
    0x00,                          /* nInterfaceProtocol : 0=none, 1=keyboard, 2=mouse */
    0,                             /* iInterface: Index of string descriptor */
    /******************** Descriptor of Custom HID ********************/
    0x09,                    /* bLength: HID Descriptor size */
    HID_DESCRIPTOR_TYPE_HID, /* bDescriptorType: HID */
    0x11,                    /* bcdHID: HID Class Spec release number */
    0x01,
    0x00,                        /* bCountryCode: Hardware target country */
    0x01,                        /* bNumDescriptors: Number of HID class descriptors to follow */
    0x22,                        /* bDescriptorType */
    HID_CUSTOM_REPORT_DESC_SIZE, /* wItemLength: Total length of Report descriptor */
    0x00,
    /******************** Descriptor of Custom in endpoint ********************/
    0x07,                         /* bLength: Endpoint Descriptor size */
    USB_DESCRIPTOR_TYPE_ENDPOINT, /* bDescriptorType: */
    HIDRAW_IN_EP,                 /* bEndpointAddress: Endpoint Address (IN) */
    0x03,                         /* bmAttributes: Interrupt endpoint */
    WBVAL(HIDRAW_IN_EP_MPS_HS),   /* wMaxPacketSize */
    HIDRAW_IN_INTERVAL,           /* bInterval: Polling Interval */
    /******************** Descriptor of Custom out endpoint ********************/
    0x07,                         /* bLength: Endpoint Descriptor size */
    USB_DESCRIPTOR_TYPE_ENDPOINT, /* bDescriptorType: */
    HIDRAW_OUT_EP,                /* bEndpointAddress: Endpoint Address (IN) */
    0x03,                         /* bmAttributes: Interrupt endpoint */
    WBVAL(HIDRAW_OUT_EP_MPS_HS),  /* wMaxPacketSize */
    HIDRAW_OUT_EP_INTERVAL,       /* bInterval: Polling Interval */
};

static const char *string_descriptors[] = {
    (const char[]){0x09, 0x04}, /* Langid */
    "HPMicro",                  /* Manufacturer */
    "HPMicro HID CTAP",         /* Product */
    "2025071701",               /* Serial Number */
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

const struct usb_descriptor hid_descriptor = {
    .device_descriptor_callback = device_descriptor_callback,
    .config_descriptor_callback = config_descriptor_callback,
    .device_quality_descriptor_callback = device_quality_descriptor_callback,
    .other_speed_descriptor_callback = other_speed_config_descriptor_callback,
    .string_descriptor_callback = string_descriptor_callback,
};

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
    // /* USER CODE BEGIN 0 */
    // 0x06, 0x00, 0xff, /* USAGE_PAGE (Vendor Defined Page 1) */
    // 0x09, 0x01,       /* USAGE (Vendor Usage 1) */
    // 0xa1, 0x01,       /* COLLECTION (Application) */
    // 0x85, 0x02,       /*   REPORT ID (0x02) */
    // 0x09, 0x01,       /*   USAGE (Vendor Usage 1) */
    // 0x15, 0x00,       /*   LOGICAL_MINIMUM (0) */
    // 0x26, 0xff, 0x00, /*   LOGICAL_MAXIMUM (255) */
    // 0x95, HID_REPORT_CNT - 1,   /*   REPORT_COUNT (63) */
    // 0x75, 0x08,       /*   REPORT_SIZE (8) */
    // 0x81, 0x02,       /*   INPUT (Data,Var,Abs) */
    // /* <___________________________________________________> */
    // 0x85, 0x01,       /*   REPORT ID (0x01) */
    // 0x09, 0x01,       /*   USAGE (Vendor Usage 1) */
    // 0x15, 0x00,       /*   LOGICAL_MINIMUM (0) */
    // 0x26, 0xff, 0x00, /*   LOGICAL_MAXIMUM (255) */
    // 0x95, HID_REPORT_CNT - 1,   /*   REPORT_COUNT (63) */
    // 0x75, 0x08,       /*   REPORT_SIZE (8) */
    // 0x91, 0x02,       /*   OUTPUT (Data,Var,Abs) */
    // /* USER CODE END 0 */
    // 0xC0 /*     END_COLLECTION	             */
};

USB_NOCACHE_RAM_SECTION USB_MEM_ALIGNX uint8_t read_buffer[HID_REPORT_CNT];
USB_NOCACHE_RAM_SECTION USB_MEM_ALIGNX uint8_t send_buffer[HID_REPORT_CNT];

#define HID_STATE_IDLE 0
#define HID_STATE_BUSY 1

/*!< hid state ! Data can be sent only when state is idle  */
static volatile uint8_t custom_state;

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
        /* setup first out ep read transfer */
        usbd_ep_start_read(busid, HIDRAW_OUT_EP, read_buffer, HID_REPORT_CNT);
        break;
    case USBD_EVENT_SET_REMOTE_WAKEUP:
        break;
    case USBD_EVENT_CLR_REMOTE_WAKEUP:
        break;

    default:
        break;
    }
}

static void usbd_hid_custom_in_callback(uint8_t busid, uint8_t ep, uint32_t nbytes)
{
    (void)busid;
    (void)ep;

    USB_LOG_RAW("actual in len:%d\r\n", nbytes);
    usbd_ep_start_read(busid, ep, read_buffer, HID_REPORT_CNT);
    custom_state = HID_STATE_IDLE;
}

static void usbd_hid_custom_out_callback(uint8_t busid, uint8_t ep, uint32_t nbytes)
{
    // 接收到数据
    USB_LOG_RAW("actual out len:%d\r\n", nbytes);
    usbd_ep_start_read(busid, ep, read_buffer, HID_REPORT_CNT);
    printf("Input:");
    for (int i = 0; i < nbytes; i++)
    {
        printf("%02X", read_buffer[i]);
    }
    printf("\n");
    CTAPHID_OutEvent(read_buffer);
    // read_buffer[0] = 0x02; /* IN: report id */
    // usbd_ep_start_write(busid, HIDRAW_IN_EP, read_buffer, nbytes);
}

static struct usbd_endpoint custom_in_ep = {
    .ep_cb = usbd_hid_custom_in_callback,
    .ep_addr = HIDRAW_IN_EP};

static struct usbd_endpoint custom_out_ep = {
    .ep_cb = usbd_hid_custom_out_callback,
    .ep_addr = HIDRAW_OUT_EP};

/* function ------------------------------------------------------------------*/
/**
 * @brief            hid custom init
 * @pre              none
 * @param[in]        none
 * @retval           none
 */
struct usbd_interface intf0;

void ctaphid_init(uint8_t busid, uint32_t reg_base)
{
    usbd_desc_register(busid, &hid_descriptor);
    usbd_add_interface(busid, usbd_hid_init_intf(busid, &intf0, hid_custom_report_desc, HID_CUSTOM_REPORT_DESC_SIZE));
    usbd_add_endpoint(busid, &custom_in_ep);
    usbd_add_endpoint(busid, &custom_out_ep);

    CTAPHID_Init();

    usbd_initialize(busid, reg_base, usbd_event_handler);
}

// Canokey Code
static CTAPHID_FRAME frame;
static CTAPHID_Channel channel;
static volatile uint8_t has_frame;
static CAPDU apdu_cmd;
static RAPDU apdu_resp;

const uint16_t ISIZE = sizeof(frame.init.data);
const uint16_t CSIZE = sizeof(frame.cont.data);

uint8_t CTAPHID_Init(void)
{
    channel.state = CTAPHID_IDLE;
    has_frame = 0;
    return 0;
}

uint8_t CTAPHID_OutEvent(uint8_t *data)
{
    if (has_frame)
    {
        ERR_MSG("overrun\n");
        return 0;
    }
    memcpy(&frame, data, sizeof(frame));
    has_frame = 1;
    return 0;
}

static void CTAPHID_SendFrame(void)
{
    uint8_t *uData = (uint8_t *)&frame;
    printf("Output:");
    for (int i = 0; i < sizeof(CTAPHID_FRAME); i++)
    {
        printf("%02X", uData[i]);
    }
    printf("\n");
    //  callback_send_report(&usb_device, (uint8_t *)&frame, sizeof(CTAPHID_FRAME));
    usbd_ep_start_write(0, HIDRAW_IN_EP, &frame, sizeof(CTAPHID_FRAME));
}

static void CTAPHID_SendResponse(uint32_t cid, uint8_t cmd, uint8_t *data, uint16_t len)
{
    uint16_t off = 0;
    size_t copied;
    uint8_t seq = 0;

    memset(&frame, 0, sizeof(frame));
    frame.cid = cid;
    frame.type = TYPE_INIT;
    frame.init.cmd |= cmd;
    frame.init.bcnth = (uint8_t)((len >> 8) & 0xFF);
    frame.init.bcntl = (uint8_t)(len & 0xFF);

    copied = MIN(len, ISIZE);
    if (!data)
        return;
    memcpy(frame.init.data, data, copied);
    CTAPHID_SendFrame();
    off += copied;

    while (len > off)
    {
        memset(&frame.cont, 0, sizeof(frame.cont));
        frame.cont.seq = (uint8_t)seq++;
        copied = MIN(len - off, CSIZE);
        memcpy(frame.cont.data, data + off, copied);
        CTAPHID_SendFrame();
        off += copied;
    }
}

static void CTAPHID_SendErrorResponse(uint32_t cid, uint8_t code)
{
    DBG_MSG("error code 0x%x\n", (int)code);
    memset(&frame, 0, sizeof(frame));
    frame.cid = cid;
    frame.init.cmd = CTAPHID_ERROR;
    frame.init.bcnth = 0;
    frame.init.bcntl = 1;
    frame.init.data[0] = code;
    CTAPHID_SendFrame();
}

static void CTAPHID_Execute_Init(void)
{
    CTAPHID_INIT_RESP *resp = (CTAPHID_INIT_RESP *)channel.data;
    uint32_t resp_cid;
    if (channel.cid == CID_BROADCAST)
        random_buffer((uint8_t *)&resp_cid, 4);
    else
        resp_cid = channel.cid;
    resp->cid = resp_cid;
    resp->versionInterface = CTAPHID_IF_VERSION; // Interface version
    resp->versionMajor = 1;                      // Major version number
    resp->versionMinor = 0;                      // Minor version number
    resp->versionBuild = 0;                      // Build version number
    resp->capFlags = CAPABILITY_CBOR;            // Capabilities flags
    CTAPHID_SendResponse(channel.cid, channel.cmd, (uint8_t *)resp, sizeof(CTAPHID_INIT_RESP));
}

static void CTAPHID_Execute_Msg(void)
{
    CAPDU *capdu = &apdu_cmd;
    RAPDU *rapdu = &apdu_resp;
    CLA = channel.data[0];
    INS = channel.data[1];
    P1 = channel.data[2];
    P2 = channel.data[3];
    LC = (channel.data[5] << 8) | channel.data[6];
    DATA = &channel.data[7];
    LE = 0x10000;
    RDATA = channel.data;
    DBG_MSG("C: ");
    PRINT_HEX(channel.data, channel.bcnt_total);
    ctap_process_apdu_with_src(capdu, rapdu, CTAP_SRC_HID);
    channel.data[LL] = HI(SW);
    channel.data[LL + 1] = LO(SW);
    DBG_MSG("R: ");
    PRINT_HEX(RDATA, LL + 2);
    CTAPHID_SendResponse(channel.cid, channel.cmd, channel.data, LL + 2);
}

static void CTAPHID_Execute_Cbor(void)
{
    DBG_MSG("C: ");
    PRINT_HEX(channel.data, channel.bcnt_total);
    size_t len = sizeof(channel.data);
    ctap_process_cbor_with_src(channel.data, channel.bcnt_total, channel.data, &len, CTAP_SRC_HID);
    DBG_MSG("R: ");
    PRINT_HEX(channel.data, len);
    CTAPHID_SendResponse(channel.cid, CTAPHID_CBOR, channel.data, len);
}

uint8_t CTAPHID_Loop(uint8_t wait_for_user)
{
    uint8_t ret = LOOP_SUCCESS;
    if (channel.state == CTAPHID_BUSY && device_get_tick() > channel.expire)
    {
        DBG_MSG("CTAP Timeout\n");
        channel.state = CTAPHID_IDLE;
        CTAPHID_SendErrorResponse(channel.cid, ERR_MSG_TIMEOUT);
    }

    if (!has_frame)
        return LOOP_SUCCESS;

    if (frame.cid == 0 || (frame.cid == CID_BROADCAST && frame.init.cmd != CTAPHID_INIT))
    {
        CTAPHID_SendErrorResponse(frame.cid, ERR_INVALID_CID);
        goto consume_frame;
    }
    if (channel.state == CTAPHID_BUSY && frame.cid != channel.cid)
    {
        CTAPHID_SendErrorResponse(frame.cid, ERR_CHANNEL_BUSY);
        goto consume_frame;
    }

    channel.cid = frame.cid;

    if (FRAME_TYPE(frame) == TYPE_INIT)
    {
        // DBG_MSG("CTAP init frame, cmd=0x%x\n", (int)frame.init.cmd);
        if (!wait_for_user && channel.state == CTAPHID_BUSY && frame.init.cmd != CTAPHID_INIT)
        { // self abort is ok
            DBG_MSG("wait_for_user=%d, cmd=0x%x\n", (int)wait_for_user, (int)frame.init.cmd);
            channel.state = CTAPHID_IDLE;
            CTAPHID_SendErrorResponse(channel.cid, ERR_INVALID_SEQ);
            goto consume_frame;
        }
        channel.bcnt_total = (uint16_t)MSG_LEN(frame);
        if (channel.bcnt_total > MAX_CTAP_BUFSIZE)
        {
            DBG_MSG("bcnt_total=%hu exceeds MAX_CTAP_BUFSIZE\n", channel.bcnt_total);
            CTAPHID_SendErrorResponse(frame.cid, ERR_INVALID_LEN);
            goto consume_frame;
        }
        uint16_t copied;
        channel.bcnt_current = copied = MIN(channel.bcnt_total, ISIZE);
        channel.state = CTAPHID_BUSY;
        channel.cmd = frame.init.cmd;
        channel.seq = 0;
        memcpy(channel.data, frame.init.data, copied);
        channel.expire = device_get_tick() + CTAPHID_TRANS_TIMEOUT;
    }
    else
    {
        // DBG_MSG("CTAP cont frame, state=%d cmd=0x%x seq=%d\n", (int)channel.state, (int)channel.cmd, (int)FRAME_SEQ(frame));
        if (channel.state == CTAPHID_IDLE)
            goto consume_frame; // ignore spurious continuation packet
        if (FRAME_SEQ(frame) != channel.seq++)
        {
            DBG_MSG("seq=%d\n", (int)FRAME_SEQ(frame));
            channel.state = CTAPHID_IDLE;
            CTAPHID_SendErrorResponse(channel.cid, ERR_INVALID_SEQ);
            goto consume_frame;
        }
        uint16_t copied;
        copied = MIN(channel.bcnt_total - channel.bcnt_current, CSIZE);
        memcpy(channel.data + channel.bcnt_current, frame.cont.data, copied);
        channel.bcnt_current += copied;
    }
    has_frame = 0;

    if (channel.bcnt_current == channel.bcnt_total)
    {
        channel.expire = UINT32_MAX;
        switch (channel.cmd)
        {
        case CTAPHID_MSG:
            DBG_MSG("MSG\n");
            if (wait_for_user)
                CTAPHID_SendErrorResponse(channel.cid, ERR_CHANNEL_BUSY);
            else if (channel.bcnt_total < 4) // APDU CLA...P2
                CTAPHID_SendErrorResponse(channel.cid, ERR_INVALID_LEN);
            else
                CTAPHID_Execute_Msg();
            break;
        case CTAPHID_CBOR:
            DBG_MSG("CBOR\n");
            if (wait_for_user)
                CTAPHID_SendErrorResponse(channel.cid, ERR_CHANNEL_BUSY);
            else if (channel.bcnt_total == 0)
                CTAPHID_SendErrorResponse(channel.cid, ERR_INVALID_LEN);
            else
                CTAPHID_Execute_Cbor();
            break;
        case CTAPHID_INIT:
            DBG_MSG("INIT\n");
            if (wait_for_user)
                CTAPHID_SendErrorResponse(channel.cid, ERR_CHANNEL_BUSY);
            else
                CTAPHID_Execute_Init();
            break;
        case CTAPHID_PING:
            DBG_MSG("PING\n");
            if (wait_for_user)
                CTAPHID_SendErrorResponse(channel.cid, ERR_CHANNEL_BUSY);
            else
                CTAPHID_SendResponse(channel.cid, channel.cmd, channel.data, channel.bcnt_total);
            break;
        case CTAPHID_WINK:
            DBG_MSG("WINK\n");
            if (!wait_for_user)
                ctap_wink();
            CTAPHID_SendResponse(channel.cid, channel.cmd, channel.data, 0);
            break;
        case CTAPHID_CANCEL:
            DBG_MSG("CANCEL when wait_for_user=%d\n", (int)wait_for_user);
            ret = LOOP_CANCEL;
            break;
        default:
            DBG_MSG("Invalid CMD 0x%x\n", (int)channel.cmd);
            CTAPHID_SendErrorResponse(channel.cid, ERR_INVALID_CMD);
            break;
        }
        channel.state = CTAPHID_IDLE;
    }

consume_frame:
    has_frame = 0;
    return ret;
}

void CTAPHID_SendKeepAlive(uint8_t status)
{
    memset(&frame, 0, sizeof(frame));
    frame.cid = channel.cid;
    frame.type = TYPE_INIT;
    frame.init.cmd |= CTAPHID_KEEPALIVE;
    frame.init.bcnth = 0;
    frame.init.bcntl = 1;
    frame.init.data[0] = status;
    CTAPHID_SendFrame();
}
