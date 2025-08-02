/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CRYPTO_ECC_H
#define CANOKEY_CRYPTO_ECC_H

#include <algo.h>
#include <stddef.h>
#include <stdint.h>
#include "crypto-util.h"

#define MAX_EC_PRIVATE_KEY 32
#define MAX_EC_PUBLIC_KEY 64

typedef struct {
  uint8_t pri[MAX_EC_PRIVATE_KEY];
  uint8_t pub[MAX_EC_PUBLIC_KEY];
} ecc_key_t;

/**
 * Generate an ECDSA key pair
 *
 * @param type      ECC algorithm
 * @param key       Pointer to the generated key
 *
 * @return 0: Success, -1: Error
 */
int ecc_generate(key_type_t type, ecc_key_t *key);

/**
 * Verify the given private key.
 *
 * @param type      ECC algorithm
 * @param key       Pointer to the key
 *
 * @return 1: verified, 0: not verified
 */
int ecc_verify_private_key(key_type_t type, ecc_key_t *key);

/**
 * Compute the corresponding public key using the private key
 *
 * @param type      ECC algorithm
 * @param key       Pointer to the key
 *
 * @return 0: Success, -1: Error
 */
int ecc_complete_key(key_type_t type, ecc_key_t *key);

/**
 * Sign the given data or digest
 *
 * @param type           ECC algorithm
 * @param key            Pointer to the key
 * @param data_or_digest The digest (for other algorithms)
 * @param sig            The output buffer
 *
 * @return 0: Success, -1: Error
 */
int ecc_sign(key_type_t type, const ecc_key_t *key, const uint8_t *data_or_digest, size_t len, uint8_t *sig);

/**
 * Convert r,s signature to ANSI X9.62 format
 *
 * @param key_len Length of the key
 * @param input   The original signature
 * @param output  ANSI X9.62 format. The buffer should be at least 2 * key_size + 6 bytes. The buffer can be identical
 * to the input.
 *
 * @return Length of signature
 */
size_t ecdsa_sig2ansi(uint8_t key_len, const uint8_t *input, uint8_t *output);

/**
 * Compute ECDH result
 *
 * @param type              ECC algorithm
 * @param priv_key          The private key s
 * @param receiver_pub_key  The receiver's public key P
 * @param out               s*P
 *
 * @return 0: Success, -1: Error
 */
int ecdh(key_type_t type, const uint8_t *priv_key, const uint8_t *receiver_pub_key, uint8_t *out);

// Below types and functions should not be used in canokey-core

/**
 * Generate an ECDSA key pair
 *
 * @param type      ECC algorithm
 * @param key       Pointer to the generated key
 *
 * @return 0: Success, -1: Error
 */
int K__short_weierstrass_generate(key_type_t type, ecc_key_t *key);

/**
 * Verify the given private key.
 *
 * @param type      ECC algorithm
 * @param key       Pointer to the key
 *
 * @return 1: verified, 0: not verified
 */
int K__short_weierstrass_verify_private_key(const key_type_t type, const ecc_key_t *key);

/**
 * Compute the corresponding public key using the private key
 *
 * @param type      ECC algorithm
 * @param key       Pointer to the key
 *
 * @return 0: Success, -1: Error
 */
int K__short_weierstrass_complete_key(key_type_t type, ecc_key_t *key);

/**
 * Sign the given data or digest
 *
 * @param type           ECC algorithm
 * @param key            Pointer to the key
 * @param data_or_digest The digest (for other algorithms)
 * @param sig            The output buffer
 *
 * @return 0: Success, -1: Error
 */
int K__short_weierstrass_sign(key_type_t type, const ecc_key_t *key, const uint8_t *data_or_digest, size_t len, uint8_t *sig);

/**
 * Compute ECDH result
 *
 * @param type              ECC algorithm
 * @param priv_key          The private key s
 * @param receiver_pub_key  The receiver's public key P
 * @param out               s*P
 *
 * @return 0: Success, -1: Error
 */
int K__short_weierstrass_ecdh(key_type_t type, const uint8_t *priv_key, const uint8_t *receiver_pub_key, uint8_t *out);

#endif
