// SPDX-License-Identifier: Apache-2.0
#include <ecc.h>
#include <memzero.h>
#include <rand.h>
#include <string.h>
#include "algo.h"

#ifdef USE_CYCLONECRYPTO
#include "ecc/ecdh.h"
#include "ecc/ecdsa.h"

static const EcCurve *grp_id[] = {
    [SECP256R1] = SECP256R1_CURVE,
};

#endif

int ecc_generate(key_type_t type, ecc_key_t *key) {
  if (!IS_ECC(type)) return -1;

  if (IS_SHORT_WEIERSTRASS(type)) {
    return K__short_weierstrass_generate(type, key);
  } else {
    return -1;
  }
}

int ecc_sign(key_type_t type, const ecc_key_t *key, const uint8_t *data_or_digest, size_t len, uint8_t *sig) {
  if (!IS_ECC(type)) return -1;

  if (IS_SHORT_WEIERSTRASS(type)) {
    return K__short_weierstrass_sign(type, key, data_or_digest, len, sig);
  } else {
    return -1;
  }
}

int ecc_verify_private_key(key_type_t type, ecc_key_t *key) {
  if (!IS_ECC(type)) return -1;

  if (IS_SHORT_WEIERSTRASS(type)) {
    return K__short_weierstrass_verify_private_key(type, key);
  } else {
    return -1;
  }
}

int ecc_complete_key(key_type_t type, ecc_key_t *key) {
  if (!IS_ECC(type)) return -1;

  if (IS_SHORT_WEIERSTRASS(type)) {
    return K__short_weierstrass_complete_key(type, key);
  } else {
    return -1;
  }
}

int ecdh(key_type_t type, const uint8_t *priv_key, const uint8_t *receiver_pub_key, uint8_t *out) {
  if (!IS_ECC(type)) return -1;

  if (IS_SHORT_WEIERSTRASS(type)) {
    return K__short_weierstrass_ecdh(type, priv_key, receiver_pub_key, out);
  } else {
    return -1;
  }
}

size_t ecdsa_sig2ansi(uint8_t key_len, const uint8_t *input, uint8_t *output) {
  int leading_zero_len1 = 0;
  int leading_zero_len2 = 0;
  for (uint8_t i = 0; i < key_len; ++i)
    if (input[i] == 0)
      ++leading_zero_len1;
    else {
      if (input[i] >= 0x80) --leading_zero_len1;
      break;
    }
  for (uint8_t i = key_len; i < key_len * 2; ++i)
    if (input[i] == 0)
      ++leading_zero_len2;
    else {
      if (input[i] >= 0x80) --leading_zero_len2;
      break;
    }
  uint8_t part1_len = key_len - leading_zero_len1;
  uint8_t part2_len = key_len - leading_zero_len2;
  if (leading_zero_len1 < 0) leading_zero_len1 = 0;
  if (leading_zero_len2 < 0) leading_zero_len2 = 0;
  memmove(output + 6 + part1_len + (part2_len == key_len + 1 ? 1 : 0), input + key_len + leading_zero_len2,
          key_len - leading_zero_len2);
  memmove(output + 4 + (part1_len == key_len + 1 ? 1 : 0), input + leading_zero_len1, key_len - leading_zero_len1);
  output[0] = 0x30;
  output[1] = part1_len + part2_len + 4;
  output[2] = 0x02;
  output[3] = part1_len;
  if (part1_len == key_len + 1) output[4] = 0;
  output[4 + part1_len] = 0x02;
  output[5 + part1_len] = part2_len;
  if (part2_len == key_len + 1) output[6 + part1_len] = 0;
  return 6 + part1_len + part2_len;
}

__attribute__((weak)) int K__short_weierstrass_generate(key_type_t type, ecc_key_t *key) {
  int ret = 1;
#ifdef USE_CYCLONECRYPTO
  error_t err;
  EcPrivateKey prikey;
  EcPublicKey pubkey;
  ecInitPrivateKey(&prikey);
  ecInitPublicKey(&pubkey);
  err = ecGenerateKeyPair(HMAC_DRBG_PRNG_ALGO, &rng_ctx, grp_id[type], &prikey, &pubkey);
  if(err != NO_ERROR)
  {
    ret = -1;
    goto end;
  }
  size_t sz;
  err = ecExportPrivateKey(&prikey, key->pri, &sz);
  if(err != NO_ERROR)
  {
    ret = -1;
    goto end;
  }
  err = ecGeneratePublicKey(&prikey, &pubkey);
  if(err != NO_ERROR)
  {
    ret = -1;
    goto end;
  }
  err = ecExportPublicKey(&pubkey, key->pub, &sz, EC_PUBLIC_KEY_FORMAT_RAW);
  if(err != NO_ERROR)
  {
    ret = -1;
    goto end;
  }
end:
  ecFreePrivateKey(&prikey);
  ecFreePublicKey(&pubkey);

#else
  (void)type;
  (void)key;
#endif
  return 0;
}

__attribute__((weak)) int K__short_weierstrass_verify_private_key(key_type_t type, const ecc_key_t *key) {
  int ret = 1;
#ifdef USE_CYCLONECRYPTO
  error_t err;
  EcPrivateKey prikey;
  ecInitPrivateKey(&prikey);
  err = ecImportPrivateKey(&prikey, grp_id[type], key->pri, PRIVATE_KEY_LENGTH[type]);
  if(err != NO_ERROR)
  {
    ret = 0;
    goto end;
  }
end:
  ecFreePrivateKey(&prikey);
  return ret;
#else
  (void)type;
  (void)key;
  return 0;
#endif
}

__attribute__((weak)) int K__short_weierstrass_complete_key(key_type_t type, ecc_key_t *key) {
  int ret = 0;
#ifdef USE_CYCLONECRYPTO
  error_t err;
  EcPrivateKey prikey;
  EcPublicKey pubkey;
  ecInitPrivateKey(&prikey);
  ecInitPublicKey(&pubkey);
  err = ecImportPrivateKey(&prikey, grp_id[type], key->pri, PRIVATE_KEY_LENGTH[type]);
  if(err != NO_ERROR)
  {
    ret = -1;
    goto end;
  }
  err = ecGeneratePublicKey(&prikey, &pubkey);
  if(err != NO_ERROR)
  {
    ret = -1;
    goto end;
  }
  size_t sz;
  err = ecExportPublicKey(&pubkey, key->pub, &sz, EC_PUBLIC_KEY_FORMAT_RAW);
  if(err != NO_ERROR)
  {
    ret = -1;
    goto end;
  }
end:
  ecFreePrivateKey(&prikey);
  ecFreePublicKey(&pubkey);
#else
  (void)type;
  (void)key;
#endif
  return 0;
}

__attribute__((weak)) int K__short_weierstrass_sign(key_type_t type, const ecc_key_t *key,
                                                    const uint8_t *data_or_digest, size_t len, uint8_t *sig) {
  int ret = 0;
#ifdef USE_CYCLONECRYPTO
  EcdsaSignature raw_sig;
  ecdsaInitSignature(&raw_sig);
  EcPrivateKey priKey;
  error_t err;
  err = ecImportPrivateKey(&priKey, grp_id[type], key->pri, PRIVATE_KEY_LENGTH[type]);
  if(err != NO_ERROR)
  {
    ret = -1;
    goto end;
  }
  err = ecdsaGenerateSignature(HMAC_DRBG_PRNG_ALGO, &rng_ctx, &priKey, data_or_digest, len, &raw_sig);
  if(err != NO_ERROR)
  {
    ret = -1;
    goto end;
  }
  size_t rtn;
  err = ecdsaExportSignature(&raw_sig, sig, &rtn, ECDSA_SIGNATURE_FORMAT_RAW);
  if(err != NO_ERROR)
  {
    ret = -1;
    goto end;
  } 
end:
  ecdsaFreeSignature(&raw_sig);
#else
  (void)type;
  (void)key;
  (void)data_or_digest;
  (void)len;
  (void)sig;
#endif
  return 0;
}

__attribute__((weak)) int K__short_weierstrass_ecdh(key_type_t type, const uint8_t *priv_key,
                                                    const uint8_t *receiver_pub_key, uint8_t *out) {
  int ret = 0;
#ifdef USE_CYCLONECRYPTO
  EcdhContext ecdhctx;
  error_t err;
  ecdhInit(&ecdhctx);
  err = ecdhSetCurve(&ecdhctx, grp_id[type]);
  if(err != NO_ERROR)
  {
    ret = -1;
    goto end;
  }
  err = ecImportPrivateKey(&ecdhctx.da, grp_id[type], priv_key, PRIVATE_KEY_LENGTH[type]);
  if(err != NO_ERROR)
  {
    ret = -1;
    goto end;
  }
  err = ecGeneratePublicKey(&ecdhctx.da, &ecdhctx.da.q);
  if(err != NO_ERROR)
  {
    ret = -1;
    goto end;
  }
  err = ecdhImportPeerPublicKey(&ecdhctx, receiver_pub_key, PUBLIC_KEY_LENGTH[type], EC_PUBLIC_KEY_FORMAT_RAW);
  if(err != NO_ERROR)
  {
    ret = -1;
    goto end;
  }
  size_t sz;
  err = ecdhComputeSharedSecret(&ecdhctx, out, PRIVATE_KEY_LENGTH[type], &sz);
  if(err != NO_ERROR)
  {
    ret = -1;
    goto end;
  }
end:
  ecdhFree(&ecdhctx);
#else
  (void)type;
  (void)priv_key;
  (void)receiver_pub_key;
  (void)out;
#endif
  return ret;
}
