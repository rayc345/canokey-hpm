// SPDX-License-Identifier: Apache-2.0
#include <sha.h>
#include <stdint.h>

#ifdef USE_CYCLONECRYPTO
#include "hash/sha1.h"
#include "hash/sha256.h"
#include "hash/sha512.h"

static Sha1Context sha1;
static Sha256Context sha256;
static Sha512Context sha512;
#endif

__attribute__((weak)) void sha1_init(void) {
#ifdef USE_CYCLONECRYPTO
  sha1Init(&sha1);
#endif
}

__attribute__((weak)) void sha1_update(const uint8_t *data, uint16_t len) {
#ifdef USE_CYCLONECRYPTO
  sha1Update(&sha1, data, len);
#else
  (void)data;
  (void)len;
#endif
}

__attribute__((weak)) void sha1_final(uint8_t digest[SHA1_DIGEST_LENGTH]) {
#ifdef USE_CYCLONECRYPTO
  sha1Final(&sha1, digest);
#else
  (void)digest;
#endif
}

void sha1_raw(const uint8_t *data, const size_t len, uint8_t digest[SHA1_DIGEST_LENGTH]) {
  sha1_init();
  sha1_update(data, len);
  sha1_final(digest);
}

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

__attribute__((weak)) void sha512_init(void) {
#ifdef USE_CYCLONECRYPTO
  sha512Init(&sha512);
#endif
}

__attribute__((weak)) void sha512_update(const uint8_t *data, uint16_t len) {
#ifdef USE_CYCLONECRYPTO
  sha512Update(&sha512, data, len);
#else
  (void)data;
  (void)len;
#endif
}

__attribute__((weak)) void sha512_final(uint8_t digest[SHA512_DIGEST_LENGTH]) {
#ifdef USE_CYCLONECRYPTO
  sha512Final(&sha512, digest);
#else
  (void)digest;
#endif
}

void sha512_raw(const uint8_t *data, const size_t len, uint8_t digest[SHA512_DIGEST_LENGTH]) {
  sha512_init();
  sha512_update(data, len);
  sha512_final(digest);
}
