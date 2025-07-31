// SPDX-License-Identifier: Apache-2.0
#include <aes.h>
#ifdef USE_CYCLONECRYPTO
#include "cipher/aes.h"

typedef enum {
  AES_ENCRYPT = 0,
  AES_DECRYPT = 1
} CIPHER_MODE;

static int aes(const uint8_t *in, uint8_t *out, const uint8_t *key, const size_t keybytes, CIPHER_MODE mode) {
  AesContext aes;
  error_t err = aesInit(&aes, key, keybytes);
  if(err != NO_ERROR)
  {
    return -1;
  }
  if (mode == AES_ENCRYPT)
    aesEncryptBlock(&aes, in, out);
  else
    aesDecryptBlock(&aes, in, out);
  aesDeinit(&aes);
  return 0;
}
#endif

__attribute__((weak)) int aes128_enc(const uint8_t *in, uint8_t *out, const uint8_t *key) {
#ifdef USE_CYCLONECRYPTO
  return aes(in, out, key, 16, AES_ENCRYPT);
#else
  (void)in;
  (void)out;
  (void)key;
  return 0;
#endif
}

__attribute__((weak)) int aes128_dec(const uint8_t *in, uint8_t *out, const uint8_t *key) {
#ifdef USE_CYCLONECRYPTO
  return aes(in, out, key, 16, AES_DECRYPT);
#else
  (void)in;
  (void)out;
  (void)key;
  return 0;
#endif
}

__attribute__((weak)) int aes256_enc(const uint8_t *in, uint8_t *out, const uint8_t *key) {
#ifdef USE_CYCLONECRYPTO
  return aes(in, out, key, 32, AES_ENCRYPT);
#else
  (void)in;
  (void)out;
  (void)key;
  return 0;
#endif
}

__attribute__((weak)) int aes256_dec(const uint8_t *in, uint8_t *out, const uint8_t *key) {
#ifdef USE_CYCLONECRYPTO
  return aes(in, out, key, 32, AES_DECRYPT);
#else
  (void)in;
  (void)out;
  (void)key;
  return 0;
#endif
}
