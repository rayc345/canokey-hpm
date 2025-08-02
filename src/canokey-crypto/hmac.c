/**
 * Copyright (c) 2013-2014 Tomas Dzetkulic
 * Copyright (c) 2013-2014 Pavol Rusnak
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <hmac.h>
#include <memzero.h>
#include <string.h>
#include "mac/hmac.h"

// void hmac_sha256_Init(HMAC_SHA256_CTX *hctx, const uint8_t *key, const size_t keylen) {
//   uint8_t i_key_pad[SHA256_BLOCK_LENGTH];
//   memzero(i_key_pad, SHA256_BLOCK_LENGTH);
//   if (keylen > SHA256_BLOCK_LENGTH) {
//     sha256_raw(key, keylen, i_key_pad);
//   } else {
//     memcpy(i_key_pad, key, keylen);
//   }
//   for (int i = 0; i < SHA256_BLOCK_LENGTH; i++) {
//     hctx->o_key_pad[i] = i_key_pad[i] ^ 0x5c;
//     i_key_pad[i] ^= 0x36;
//   }
//   sha256_init();
//   sha256_update(i_key_pad, SHA256_BLOCK_LENGTH);
//   memzero(i_key_pad, sizeof(i_key_pad));
// }

// void hmac_sha256_Update(const HMAC_SHA256_CTX *hctx, const uint8_t *msg, const size_t msglen) {
//   (void) hctx;
//   sha256_update(msg, msglen);
// }

// void hmac_sha256_Final(HMAC_SHA256_CTX *hctx, uint8_t *hmac) {
//   sha256_final(hmac);
//   sha256_init();
//   sha256_update(hctx->o_key_pad, SHA256_BLOCK_LENGTH);
//   sha256_update(hmac, SHA256_DIGEST_LENGTH);
//   sha256_final(hmac);
//   memzero(hctx, sizeof(HMAC_SHA256_CTX));
// }

void hmac_sha256(const uint8_t *key, const size_t keylen, const uint8_t *msg, const size_t msglen, uint8_t *hmac) {
  hmacCompute(SHA256_HASH_ALGO, key, keylen, msg, msglen, hmac);
  // HMAC_SHA256_CTX hctx;
  // hmac_sha256_Init(&hctx, key, keylen);
  // hmac_sha256_Update(&hctx, msg, msglen);
  // hmac_sha256_Final(&hctx, hmac);
}
