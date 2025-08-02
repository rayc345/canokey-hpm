#ifndef CANOKEY_CRYPTO_ALGO_H
#define CANOKEY_CRYPTO_ALGO_H

#include <stddef.h>

typedef enum {
  SECP256R1,
  KEY_TYPE_PKC_END,
  AES128,
  AES256,
} key_type_t;

extern const size_t PRIVATE_KEY_LENGTH[KEY_TYPE_PKC_END];
extern const size_t PUBLIC_KEY_LENGTH[KEY_TYPE_PKC_END];
extern const size_t SIGNATURE_LENGTH[KEY_TYPE_PKC_END];

#define IS_ECC(type) ((type) == SECP256R1)
#define IS_SHORT_WEIERSTRASS(type) ((type) == SECP256R1)

#endif // CANOKEY_CRYPTO_ALGO_H
