// SPDX-License-Identifier: Apache-2.0
#include <rand.h>
#include <stdio.h>
#include "rng/hmac_drbg.h"

#ifdef USE_CYCLONECRYPTO
HmacDrbgContext rng_ctx;
#endif

__attribute__((weak)) void raise_exception(void) {}

void print_hex(const uint8_t *buf, size_t len) {
  for (size_t i = 0; i < len; ++i)
    printf("%02X", buf[i]);
  printf("\n");
}

int memcmp_s(const void *p, const void *q, size_t len) {
  volatile size_t equal = 0, notequal = 0;
  for (size_t i = 0; i != len; ++i)
    if (((uint8_t*)p)[i] == ((uint8_t*)q)[i])
      ++equal;
    else
      ++notequal;
  if (equal + notequal != len) raise_exception();
  if (equal == len)
    return 0;
  else
    return -1;
}

void random_delay(void) {
  uint16_t delay = random32() & 0xFFFF;
  for (volatile uint16_t i = 0; i != delay; ++i)
    __asm volatile("nop");
}

#ifdef USE_CYCLONECRYPTO
__attribute__((weak)) void crypto_rng_init(void)
{
  uint8_t seed[] = {
      0xaf, 0xb0, 0xb0, 0xb8, 0x71, 0x9f, 0xf9, 0x28,
      0xcc, 0x81, 0x6f, 0xb3, 0x01, 0x7d, 0x8a, 0xbb,
      0xe9, 0x9f, 0x88, 0x34, 0xfc, 0xcc, 0x30, 0x63,
      0x0f, 0x4f, 0xa3, 0x32, 0x70, 0xb1, 0x98, 0x53};
  hmacDrbgInit(&rng_ctx, SHA256_HASH_ALGO);
  hmacDrbgSeed(&rng_ctx, seed, sizeof(seed));
#endif
}