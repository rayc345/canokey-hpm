// Modified from https://github.com/AyrA/sm3/blob/master/sm3.c (Dec 24, 2023)
//
// MIT License
//
// Copyright (c) 2019 Kevin Gut
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "sm3.h"
#include <string.h>

#ifdef USE_CYCLONECRYPTO
#include "hash/sm3.h"
#endif

Sm3Context sm3_ctx;

__attribute__((weak)) void sm3_init(void) {
#ifdef USE_CYCLONECRYPTO
  sm3Init(&sm3_ctx);
#endif
}

__attribute__((weak)) void sm3_update(const uint8_t *data, uint16_t len) {
#ifdef USE_CYCLONECRYPTO
  sm3Update(&sm3_ctx, data, len);
#else
  (void)data;
  (void)len;
#endif
}

__attribute__((weak)) void sm3_final(uint8_t digest[SM3_DIGEST_LENGTH]) {
#ifdef USE_CYCLONECRYPTO
  sm3Final(&sm3_ctx, digest);
#else
  (void)digest;
#endif
}

void sm3_raw(const uint8_t *data, size_t len, uint8_t digest[SM3_DIGEST_LENGTH]) {
  sm3_init();
  sm3_update(data, len);
  sm3_final(digest);
}
