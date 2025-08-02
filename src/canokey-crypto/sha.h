/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CRYPTO_SHA_H_
#define CANOKEY_CRYPTO_SHA_H_

#include <stddef.h>
#include <stdint.h>

#define SHA256_BLOCK_LENGTH 64
#define SHA256_DIGEST_LENGTH 32

void sha256_init(void);
void sha256_update(const uint8_t *data, uint16_t len);
void sha256_final(uint8_t digest[SHA256_DIGEST_LENGTH]);
void sha256_raw(const uint8_t *data, size_t len, uint8_t digest[SHA256_DIGEST_LENGTH]);

#endif
