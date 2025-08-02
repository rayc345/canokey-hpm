// SPDX-License-Identifier: Apache-2.0
#include <sha.h>
#include <stdint.h>

#ifdef USE_CYCLONECRYPTO
#include "hash/sha256.h"
static Sha256Context sha256;
#endif

__attribute__((weak)) void sha256_init(void) {
#ifdef USE_CYCLONECRYPTO
  sha256Init(&sha256);
#endif
}

__attribute__((weak)) void sha256_update(const uint8_t *data, uint16_t len) {
#ifdef USE_CYCLONECRYPTO
  sha256Update(&sha256, data, len);
#else
  (void)data;
  (void)len;
#endif
}

__attribute__((weak)) void sha256_final(uint8_t digest[SHA256_DIGEST_LENGTH]) {
#ifdef USE_CYCLONECRYPTO
  sha256Final(&sha256, digest);
#else
  (void)digest;
#endif
}

void sha256_raw(const uint8_t *data, const size_t len, uint8_t digest[SHA256_DIGEST_LENGTH]) {
  sha256_init();
  sha256_update(data, len);
  sha256_final(digest);
}