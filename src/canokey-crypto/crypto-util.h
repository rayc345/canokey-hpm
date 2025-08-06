/* SPDX-License-Identifier: Apache-2.0 */
#ifndef _UTILS_H
#define _UTILS_H

#include <stddef.h>
#include <stdint.h>
#include "rng/hmac_drbg.h"

#ifdef USE_CYCLONECRYPTO
extern HmacDrbgContext rng_ctx;
#endif
void raise_exception(void);
void print_hex(const uint8_t *buf, size_t len);
int memcmp_s(const void *p, const void *q, size_t len);
void random_delay(void);
void canokey_rng_init(void);

#endif //_UTILS_H
