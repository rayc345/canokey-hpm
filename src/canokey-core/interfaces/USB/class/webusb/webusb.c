// SPDX-License-Identifier: Apache-2.0
#include "usbd_core.h"
#include <apdu.h>
#include <ccid.h>
#include <device.h>
#include <webusb.h>

enum {
  STATE_IDLE = -1,
  STATE_PROCESS = 1,
  STATE_SENDING_RESP = 0,
  STATE_SENT_RESP = 2,
  STATE_RECVING = 3,
  STATE_HOLD_BUF = 4,
};

static int8_t state;
static uint16_t apdu_buffer_size;
static CAPDU apdu_cmd;
static RAPDU apdu_resp;
static uint32_t last_keepalive;

uint8_t USBD_WEBUSB_Init(void) {
  state = STATE_IDLE;
  apdu_cmd.data = global_buffer;
  apdu_resp.data = global_buffer;
  last_keepalive = 0;
  return 0;
}

void WebUSB_Loop(void) {
  if (device_get_tick() - last_keepalive > 2000 && state == STATE_HOLD_BUF) {
    DBG_MSG("Release buffer after time-out\n");
    release_apdu_buffer(BUFFER_OWNER_WEBUSB);
    // CCID_insert();
    state = STATE_IDLE;
  }
  if (state != STATE_PROCESS) return;

  DBG_MSG("C: ");
  PRINT_HEX(global_buffer, apdu_buffer_size);

  CAPDU *capdu = &apdu_cmd;
  RAPDU *rapdu = &apdu_resp;

  if (build_capdu(&apdu_cmd, global_buffer, apdu_buffer_size) < 0) {
    // abandon malformed apdu
    LL = 0;
    SW = SW_WRONG_LENGTH;
  } else {
    process_apdu(capdu, rapdu);
  }

  apdu_buffer_size = LL + 2;
  global_buffer[LL] = HI(SW);
  global_buffer[LL + 1] = LO(SW);
  DBG_MSG("R: ");
  PRINT_HEX(global_buffer, apdu_buffer_size);
  state = STATE_SENDING_RESP;
}

uint8_t USBD_WEBUSB_TxSent(uint8_t busid) {
  //DBG_MSG("state = %d\n", state);
  if (state == STATE_SENT_RESP) {
    // release_apdu_buffer(BUFFER_OWNER_WEBUSB);
    state = STATE_HOLD_BUF;
  }
  return 0;
}

uint8_t USBD_WEBUSB_RxReady(uint8_t busid) {
  //  state should be STATE_RECVING now
  state = STATE_PROCESS;
  return 0;
}

// // Recipient = interface
// bool webusb_handle_interface_request(uint8_t rhport, uint8_t request) {
//   // DBG_MSG("bRequest=%d, wLength=%d\r\n", request->bRequest, request->wLength);

//   last_keepalive = device_get_tick();
//   switch (request->bRequest) {
//   case WEBUSB_REQ_CMD:
//     if (state != STATE_IDLE && state != STATE_HOLD_BUF) {
//       ERR_MSG("Wrong state %d\n", state);
//       return false;
//     }
//     if (acquire_apdu_buffer(BUFFER_OWNER_WEBUSB) != 0) {
//       ERR_MSG("Busy\n");
//       return false;
//     }
//     state = STATE_HOLD_BUF;
//     //DBG_MSG("Buf Acquired\n");
//     if (request->wLength > APDU_BUFFER_SIZE) {
//       ERR_MSG("Overflow\n");
//       return false;
//     }
//     if (request->wLength == 0) return true; // Host shouldn't send an empty command
//     // usbd_control_set_complete_callback(webusb_control_xfer_complete_cb);
//     DBG_MSG("Recv data %u bytes\n", request->wLength);
//     tud_control_xfer(rhport, request, global_buffer, request->wLength);
//     apdu_buffer_size = request->wLength;
//     state = STATE_RECVING;
//     return true;

//   case WEBUSB_REQ_RESP:
//     if (state == STATE_SENDING_RESP) {
//       uint16_t len = MIN(apdu_buffer_size, request->wLength);
//       DBG_MSG("Send data %u bytes\n", len);
//       tud_control_xfer(rhport, request, global_buffer, len);
//       state = STATE_SENT_RESP;
//     } else {
//       return false;
//     }
//     return true;

//   case WEBUSB_REQ_STAT:
//     // DBG_MSG("Send data %u bytes\n", 1);
//     tud_control_xfer(rhport, request, (uint8_t*)&state, 1);
//     return true;

//   }

//   // stall unknown request
//   return false;
// }

int USBD_WEBUSB_Setup(uint8_t busid, struct usb_setup_packet *setup, uint8_t **data, uint32_t *len) {
    (void)busid;
    (void)data;
    (void)len;

    USB_LOG_DBG("Vendor Class request: "
                "bRequest 0x%02x\r\n",
                setup->bRequest);

    switch (setup->bRequest)
    {
        // case 0x22:
        //     if (setup->wValue != 0)
        //     {
        //         // board_led_write(!board_get_led_gpio_off_level());
        //     }
        //     else
        //     {
        //         // board_led_write(board_get_led_gpio_off_level());
        //     }
        //     break;

    default:
        USB_LOG_WRN("Unhandled Vendor Class bRequest 0x%02x\r\n", setup->bRequest);
        return -1;
    }

    return 0;
}

int USBD_WEBUSB_Setup2(uint8_t busid, struct usb_setup_packet *setup, uint8_t **data, uint32_t *len) {
    (void)busid;
    (void)data;
    (void)len;

    USB_LOG_DBG("Vendor 2 request: "
                "bRequest 0x%02x\r\n",
                setup->bRequest);

    switch (setup->bRequest)
    {
        // case 0x22:
        //     if (setup->wValue != 0)
        //     {
        //         // board_led_write(!board_get_led_gpio_off_level());
        //     }
        //     else
        //     {
        //         // board_led_write(board_get_led_gpio_off_level());
        //     }
        //     break;

    default:
        USB_LOG_WRN("Unhandled Vendor Class bRequest 0x%02x\r\n", setup->bRequest);
        return -1;
    }

    return 0;
}

// int8_t USBD_WEBUSB_Setup(uint8_t busid, struct usb_setup_packet *setup, uint8_t **data, uint32_t *len) {
//   // CCID_eject();
//   last_keepalive = device_get_tick();
//   switch (req->bRequest) {
//   case WEBUSB_REQ_CMD:
//     if (state != STATE_IDLE && state != STATE_HOLD_BUF) {
//       ERR_MSG("Wrong state %d\n", state);
//       USBD_CtlError(pdev, req);
//       return USBD_FAIL;
//     }
//     if (acquire_apdu_buffer(BUFFER_OWNER_WEBUSB) != 0) {
//       ERR_MSG("Busy\n");
//       USBD_CtlError(pdev, req);
//       return USBD_FAIL;
//     }
//     state = STATE_HOLD_BUF;
//     //DBG_MSG("Buf Acquired\n");
//     if (req->wLength > APDU_BUFFER_SIZE) {
//       ERR_MSG("Overflow\n");
//       USBD_CtlError(pdev, req);
//       return USBD_FAIL;
//     }
//     USBD_CtlPrepareRx(pdev, global_buffer, req->wLength);
//     apdu_buffer_size = req->wLength;
//     state = STATE_RECVING;
//     break;

//   case WEBUSB_REQ_RESP:
//     if (state == STATE_SENDING_RESP) {
//       uint16_t len = MIN(apdu_buffer_size, req->wLength);
//       USBD_CtlSendData(pdev, global_buffer, len, WEBUSB_EP0_SENDER);
//       state = STATE_SENT_RESP;
//     } else {
//       USBD_CtlError(pdev, req);
//       return USBD_FAIL;
//     }
//     break;

//   case WEBUSB_REQ_STAT:
//     USBD_CtlSendData(pdev, (uint8_t*)&state, 1, WEBUSB_EP0_SENDER);
//     break;

//   default:
//     USBD_CtlError(pdev, req);
//     return USBD_FAIL;
//   }

//   return 0;
// }
