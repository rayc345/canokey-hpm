// SPDX-License-Identifier: Apache-2.0
#include <des.h>
#ifdef USE_CYCLONECRYPTO
#include "cipher/des.h"
#include "cipher/des3.h"
#endif

__attribute__((weak)) int des_enc(const uint8_t *in, uint8_t *out, const uint8_t *key) {
#ifdef USE_CYCLONECRYPTO
  DesContext ctx;
  if (desInit(&ctx, key, 8) != NO_ERROR) return -1;
  desEncryptBlock(&ctx, in, out);
  desDeinit(&ctx);
  return 0;
#else
  (void)in;
  (void)out;
  (void)key;
  return 0;
#endif
}

__attribute__((weak)) int des_dec(const uint8_t *in, uint8_t *out, const uint8_t *key) {
#ifdef USE_CYCLONECRYPTO
  DesContext ctx;
  if (desInit(&ctx, key, 8) != NO_ERROR) return -1;
  desDecryptBlock(&ctx, in, out);
  desDeinit(&ctx);
  return 0;
#else
  (void)in;
  (void)out;
  (void)key;
  return 0;
#endif
}

__attribute__((weak)) int tdes_enc(const uint8_t *in, uint8_t *out, const uint8_t *key) {
#ifdef USE_CYCLONECRYPTO
  Des3Context ctx;
  if (des3Init(&ctx, key, 24) != NO_ERROR) return -1;
  des3EncryptBlock(&ctx, in, out);
  des3Deinit(&ctx);
  return 0;
#else
  (void)in;
  (void)out;
  (void)key;
  return 0;
#endif
}

__attribute__((weak)) int tdes_dec(const uint8_t *in, uint8_t *out, const uint8_t *key) {
#ifdef USE_CYCLONECRYPTO
  Des3Context ctx;
  if (des3Init(&ctx, key, 24) != NO_ERROR) return -1;
  des3DecryptBlock(&ctx, in, out);
  des3Deinit(&ctx);
  return 0;
#else
  (void)in;
  (void)out;
  (void)key;
  return 0;
#endif
}
