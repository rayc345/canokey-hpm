// SPDX-License-Identifier: Apache-2.0
#include "usbd_core.h"
#include "usb_def.h"
#include <apdu.h>
#include <ccid.h>
#include <device.h>
#include <webusb.h>

enum
{
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

uint8_t USBD_WEBUSB_Init(void)
{
  state = STATE_IDLE;
  apdu_cmd.data = global_buffer;
  apdu_resp.data = global_buffer;
  last_keepalive = 0;
  return 0;
}

void WebUSB_Loop(void)
{
  if (device_get_tick() - last_keepalive > 2000 && state == STATE_HOLD_BUF)
  {
    DBG_MSG("Release buffer after time-out\n");
    release_apdu_buffer(BUFFER_OWNER_WEBUSB);
    // CCID_insert();
    state = STATE_IDLE;
  }
  if (state != STATE_PROCESS)
    return;

  DBG_MSG("C: ");
  PRINT_HEX(global_buffer, apdu_buffer_size);

  CAPDU *capdu = &apdu_cmd;
  RAPDU *rapdu = &apdu_resp;

  if (build_capdu(&apdu_cmd, global_buffer, apdu_buffer_size) < 0)
  {
    // abandon malformed apdu
    LL = 0;
    SW = SW_WRONG_LENGTH;
  }
  else
  {
    process_apdu(capdu, rapdu);
  }

  apdu_buffer_size = LL + 2;
  global_buffer[LL] = HI(SW);
  global_buffer[LL + 1] = LO(SW);
  DBG_MSG("R: ");
  PRINT_HEX(global_buffer, apdu_buffer_size);
  state = STATE_SENDING_RESP;
}

// uint8_t USBD_WEBUSB_TxSent(uint8_t busid)
// {
//   // DBG_MSG("state = %d\n", state);
//   if (state == STATE_SENT_RESP)
//   {
//     // release_apdu_buffer(BUFFER_OWNER_WEBUSB);
//     state = STATE_HOLD_BUF;
//   }
//   return 0;
// }

// uint8_t USBD_WEBUSB_RxReady(uint8_t busid)
// {
//   //  state should be STATE_RECVING now
//   state = STATE_PROCESS;
//   return 0;
// }

uint8_t tx_cb_pending = 0;
uint8_t rx_cb_pending = 0;

void ctrl_cplt_cb(uint8_t isin)
{
  if (isin == 0)
  {
    if (tx_cb_pending == 1)
    {
      tx_cb_pending = 0;
      // DBG_MSG("state = %d\n", state);
      if (state == STATE_SENT_RESP)
      {
        // release_apdu_buffer(BUFFER_OWNER_WEBUSB);
        state = STATE_HOLD_BUF;
        printf("tx_cmp\n");
      }
    }
  }
  else
  {
    if (rx_cb_pending == 1)
    {
      rx_cb_pending = 0;
      //  state should be STATE_RECVING now
      state = STATE_PROCESS;
      printf("rx_cmp\n");
    }
  }
}

int USBD_WEBUSB_Setup(uint8_t busid, struct usb_setup_packet *setup, uint8_t **data, uint32_t *len)
{
  (void)busid;
  (void)data;
  (void)len;

 USB_LOG_DBG("Vendor Class request: "
             "bRequest 0x%02x\r\n",
             setup->bRequest);
 if ((setup->bmRequestType & USB_REQUEST_RECIPIENT_MASK) == USB_REQUEST_RECIPIENT_INTERFACE)
 {
   switch (setup->bRequest)
   {
     DBG_MSG("New Request\n");
   case WEBUSB_REQ_CMD:
     if (state != STATE_IDLE && state != STATE_HOLD_BUF)
     {
       ERR_MSG("ErrorState\n");
       ERR_MSG("Wrong state %d\n", state);
       return -1;
     }
     if (acquire_apdu_buffer(BUFFER_OWNER_WEBUSB) != 0)
     {
       ERR_MSG("Busy\n");
       return -1;
     }
     state = STATE_HOLD_BUF;
     // DBG_MSG("Buf Acquired\n");
     if (setup->wLength > APDU_BUFFER_SIZE)
     {
       ERR_MSG("Overflow\n");
       return -1;
     }
     if (setup->wLength == 0)
       return 0; // Host shouldn't send an empty command
     DBG_MSG("Recv data %u bytes\n", setup->wLength);
     rx_cb_pending = 1;
     usbd_ep_start_read(busid, USB_CONTROL_OUT_EP0, global_buffer, setup->wLength);
     apdu_buffer_size = setup->wLength;
     state = STATE_RECVING;
     return 0;

   case WEBUSB_REQ_RESP:
     if (state == STATE_SENDING_RESP)
     {
       uint16_t len = MIN(apdu_buffer_size, setup->wLength);
       DBG_MSG("Send data %u bytes\n", len);
       memcpy(&data, global_buffer, len);
       tx_cb_pending = 1;
       state = STATE_SENT_RESP;
     }
     else
     {
       ERR_MSG("ErrorState\n");
       return -1;
     }
     return 0;

   case WEBUSB_REQ_STAT:
     // DBG_MSG("Send data %u bytes\n", 1);
     memcpy(&data, (uint8_t *)&state, 1);
     tx_cb_pending = 1;
     return 0;

   default:
     USB_LOG_WRN("Unhandled Vendor Class bRequest 0x%02x\r\n", setup->bRequest);
     return -1;
   }
 }
 else
 {
   return -1;
 }
 return 0;
}