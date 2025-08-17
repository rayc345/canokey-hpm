// SPDX-License-Identifier: Apache-2.0
#include <ecc.h>
#include <memzero.h>
#include <rand.h>
#include <sm3.h>
#include <string.h>
#include "algo.h"
#include "ecc/ec.h"
#include "ecc/ecdsa.h"

const uint8_t SM2_ID_DEFAULT[] = {0x10, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35,
                                  0x36, 0x37, 0x38};

#ifdef USE_CYCLONECRYPTO
#include "ecc/ecdh.h"
#include "ecc/ecdsa.h"
#include "ecc/sm2.h"
#include "ecc/x25519.h"
#include "ecc/ed25519.h"

static const EcCurve *grp_id[] = {
    [SECP256R1] = SECP256R1_CURVE,
    [SECP256K1] = SECP256K1_CURVE,
    [SECP384R1] = SECP384R1_CURVE,
    [SM2] = SM2_CURVE,
};

#endif

static const K__ed25519_public_key gx = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9};

void x25519_key_from_random(K__x25519_key private_key)
{
  private_key[31] &= 0xf8;
  private_key[0] &= 0x7f;
  private_key[0] |= 0x40;
}

void swap_big_number_endian(uint8_t buf[32])
{
  for (int i = 0; i < 16; ++i)
  {
    uint8_t tmp = buf[31 - i];
    buf[31 - i] = buf[i];
    buf[i] = tmp;
  }
}

int ecc_generate(key_type_t type, ecc_key_t *key)
{
  if (!IS_ECC(type))
    return -1;

  if (IS_SHORT_WEIERSTRASS(type))
  {
    return K__short_weierstrass_generate(type, key);
  }
  else
  { // ed25519 & x25519
    random_buffer(key->pri, PRIVATE_KEY_LENGTH[type]);
    if (type == ED25519)
    {
      K__ed25519_publickey(key->pri, key->pub);
    }
    else
    {
      x25519_key_from_random(key->pri);
      K__x25519(key->pub, key->pri, gx);
    }
    return 0;
  }
}

int ecc_sign(key_type_t type, const ecc_key_t *key, const uint8_t *data_or_digest, size_t len, uint8_t *sig)
{
  if (!IS_ECC(type))
    return -1;

  if (IS_SHORT_WEIERSTRASS(type))
  {
    return K__short_weierstrass_sign(type, key, data_or_digest, len, sig);
  }
  else
  { // ed25519 & x25519
    if (type == X25519)
      return -1;
    K__ed25519_signature sig_buf;
    K__ed25519_sign(data_or_digest, len, key->pri, key->pub, sig_buf);
    memcpy(sig, sig_buf, SIGNATURE_LENGTH[ED25519]);
    return 0;
  }
}

int ecc_verify_private_key(key_type_t type, ecc_key_t *key)
{
  if (!IS_ECC(type))
    return -1;

  if (IS_SHORT_WEIERSTRASS(type))
  {
    return K__short_weierstrass_verify_private_key(type, key);
  }
  else
  { // ed25519 & x25519
    return 1;
  }
}

int ecc_complete_key(key_type_t type, ecc_key_t *key)
{
  if (!IS_ECC(type))
    return -1;

  if (IS_SHORT_WEIERSTRASS(type))
  {
    return K__short_weierstrass_complete_key(type, key);
  }
  else
  { // ed25519 & x25519
    if (type == ED25519)
    {
      K__ed25519_publickey(key->pri, key->pub);
    }
    else
    {
      K__x25519(key->pub, key->pri, gx);
    }
    return 0;
  }
}

int ecdh(key_type_t type, const uint8_t *priv_key, const uint8_t *receiver_pub_key, uint8_t *out)
{
  if (!IS_ECC(type))
    return -1;

  if (IS_SHORT_WEIERSTRASS(type))
  {
    return K__short_weierstrass_ecdh(type, priv_key, receiver_pub_key, out);
  }
  else
  { // ed25519 & x25519
    if (type == ED25519)
      return -1;
    uint8_t pub[32];
    memcpy(pub, receiver_pub_key, 32);
    swap_big_number_endian(pub);
    K__x25519(out, priv_key, pub);
    swap_big_number_endian(out);
    return 0;
  }
}

size_t ecdsa_sig2ansi(uint8_t key_len, const uint8_t *input, uint8_t *output)
{
  int leading_zero_len1 = 0;
  int leading_zero_len2 = 0;
  for (uint8_t i = 0; i < key_len; ++i)
    if (input[i] == 0)
      ++leading_zero_len1;
    else
    {
      if (input[i] >= 0x80)
        --leading_zero_len1;
      break;
    }
  for (uint8_t i = key_len; i < key_len * 2; ++i)
    if (input[i] == 0)
      ++leading_zero_len2;
    else
    {
      if (input[i] >= 0x80)
        --leading_zero_len2;
      break;
    }
  uint8_t part1_len = key_len - leading_zero_len1;
  uint8_t part2_len = key_len - leading_zero_len2;
  if (leading_zero_len1 < 0)
    leading_zero_len1 = 0;
  if (leading_zero_len2 < 0)
    leading_zero_len2 = 0;
  memmove(output + 6 + part1_len + (part2_len == key_len + 1 ? 1 : 0), input + key_len + leading_zero_len2,
          key_len - leading_zero_len2);
  memmove(output + 4 + (part1_len == key_len + 1 ? 1 : 0), input + leading_zero_len1, key_len - leading_zero_len1);
  output[0] = 0x30;
  output[1] = part1_len + part2_len + 4;
  output[2] = 0x02;
  output[3] = part1_len;
  if (part1_len == key_len + 1)
    output[4] = 0;
  output[4 + part1_len] = 0x02;
  output[5 + part1_len] = part2_len;
  if (part2_len == key_len + 1)
    output[6 + part1_len] = 0;
  return 6 + part1_len + part2_len;
}

__attribute__((weak)) int sm2_z(const uint8_t *id, const ecc_key_t *key, uint8_t *z)
{
  const uint8_t a[] = {0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                       0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC};
  const uint8_t b[] = {0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34, 0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
                       0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92, 0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93};
  const uint8_t xg[] = {0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, 0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
                        0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1, 0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7};
  const uint8_t yg[] = {0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C, 0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
                        0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40, 0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0};
  const uint8_t entl[2] = {id[0] * 8 >> 8, id[0] * 8 & 0xFF};

  sm3_init();
  sm3_update(entl, sizeof(entl));
  sm3_update(id + 1, id[0]);
  sm3_update(a, sizeof(a));
  sm3_update(b, sizeof(b));
  sm3_update(xg, sizeof(xg));
  sm3_update(yg, sizeof(yg));
  sm3_update(key->pub, PUBLIC_KEY_LENGTH[SM2]);
  sm3_final(z);

  return 0;
}

__attribute__((weak)) int K__short_weierstrass_generate(key_type_t type, ecc_key_t *key)
{
  int ret = 1;
#ifdef USE_CYCLONECRYPTO
  error_t err;
  EcPrivateKey prikey;
  EcPublicKey pubkey;
  ecInitPrivateKey(&prikey);
  ecInitPublicKey(&pubkey);
  err = ecGenerateKeyPair(HMAC_DRBG_PRNG_ALGO, &rng_ctx, grp_id[type], &prikey, &pubkey);
  if (err != NO_ERROR)
  {
    ret = -1;
    goto end;
  }
  size_t sz;
  err = ecExportPrivateKey(&prikey, key->pri, &sz);
  if (err != NO_ERROR)
  {
    ret = -1;
    goto end;
  }
  err = ecGeneratePublicKey(&prikey, &pubkey);
  if (err != NO_ERROR)
  {
    ret = -1;
    goto end;
  }
  err = ecExportPublicKey(&pubkey, key->pub, &sz, EC_PUBLIC_KEY_FORMAT_RAW);
  if (err != NO_ERROR)
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
  return ret;
}

__attribute__((weak)) int K__short_weierstrass_verify_private_key(key_type_t type, const ecc_key_t *key)
{
  int ret = 1;
#ifdef USE_CYCLONECRYPTO
  error_t err;
  EcPrivateKey prikey;
  ecInitPrivateKey(&prikey);
  err = ecImportPrivateKey(&prikey, grp_id[type], key->pri, PRIVATE_KEY_LENGTH[type]);
  if (err != NO_ERROR)
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

__attribute__((weak)) int K__short_weierstrass_complete_key(key_type_t type, ecc_key_t *key)
{
  int ret = 0;
#ifdef USE_CYCLONECRYPTO
  error_t err;
  EcPrivateKey prikey;
  EcPublicKey pubkey;
  ecInitPrivateKey(&prikey);
  ecInitPublicKey(&pubkey);
  err = ecImportPrivateKey(&prikey, grp_id[type], key->pri, PRIVATE_KEY_LENGTH[type]);
  if (err != NO_ERROR)
  {
    ret = -1;
    goto end;
  }
  err = ecGeneratePublicKey(&prikey, &pubkey);
  if (err != NO_ERROR)
  {
    ret = -1;
    goto end;
  }
  size_t sz;
  err = ecExportPublicKey(&pubkey, key->pub, &sz, EC_PUBLIC_KEY_FORMAT_RAW);
  if (err != NO_ERROR)
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
  return ret;
}

__attribute__((weak)) int K__short_weierstrass_sign(key_type_t type, const ecc_key_t *key,
                                                    const uint8_t *data_or_digest, size_t len, uint8_t *sig)
{
  int ret = 0;
#ifdef USE_CYCLONECRYPTO
  EcdsaSignature raw_sig;
  ecdsaInitSignature(&raw_sig);
  EcPrivateKey priKey;
  error_t err;
  err = ecImportPrivateKey(&priKey, grp_id[type], key->pri, PRIVATE_KEY_LENGTH[type]);
  if (err != NO_ERROR)
  {
    ret = -1;
    goto end;
  }
  err = ecdsaGenerateSignature(HMAC_DRBG_PRNG_ALGO, &rng_ctx, &priKey, data_or_digest, len, &raw_sig);
  if (err != NO_ERROR)
  {
    ret = -1;
    goto end;
  }
  size_t rtn;
  err = ecdsaExportSignature(&raw_sig, sig, &rtn, ECDSA_SIGNATURE_FORMAT_RAW);
  if (err != NO_ERROR)
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
  return ret;
}

__attribute__((weak)) int K__short_weierstrass_ecdh(key_type_t type, const uint8_t *priv_key,
                                                    const uint8_t *receiver_pub_key, uint8_t *out)
{
  int ret = 0;
#ifdef USE_CYCLONECRYPTO
  EcdhContext ecdhctx;
  error_t err;
  ecdhInit(&ecdhctx);
  err = ecdhSetCurve(&ecdhctx, grp_id[type]);
  if (err != NO_ERROR)
  {
    ret = -1;
    goto end;
  }
  err = ecImportPrivateKey(&ecdhctx.da, grp_id[type], priv_key, PRIVATE_KEY_LENGTH[type]);
  if (err != NO_ERROR)
  {
    ret = -1;
    goto end;
  }
  err = ecGeneratePublicKey(&ecdhctx.da, &ecdhctx.da.q);
  if (err != NO_ERROR)
  {
    ret = -1;
    goto end;
  }
  err = ecdhImportPeerPublicKey(&ecdhctx, receiver_pub_key, PUBLIC_KEY_LENGTH[type], EC_PUBLIC_KEY_FORMAT_RAW);
  if (err != NO_ERROR)
  {
    ret = -1;
    goto end;
  }
  size_t sz;
  err = ecdhComputeSharedSecret(&ecdhctx, out, PRIVATE_KEY_LENGTH[type], &sz);
  if (err != NO_ERROR)
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

__attribute__((weak)) void K__ed25519_publickey(const K__ed25519_secret_key sk, K__ed25519_public_key pk)
{
#ifdef USE_CYCLONECRYPTO
  ed25519GeneratePublicKey(sk, pk);
#else
  (void)sk;
  (void)pk;
#endif
}

__attribute__((weak)) void K__ed25519_sign(const unsigned char *m, size_t mlen, const K__ed25519_secret_key sk,
                                           const K__ed25519_public_key pk, K__ed25519_signature rs)
{

#ifdef USE_CYCLONECRYPTO
  ed25519GenerateSignature(sk, pk, m, mlen, NULL, 0, 0, rs);
#else
  (void)m;
  (void)mlen;
  (void)sk;
  (void)pk;
  (void)rs;
#endif
}

__attribute__((weak)) void K__x25519(K__x25519_key shared_secret, const K__x25519_key private_key,
                                     const K__x25519_key public_key)
{
#ifdef USE_CYCLONECRYPTO
  K__ed25519_public_key pkey;
  K__ed25519_secret_key skey;
  memcpy(pkey, public_key, 32);
  swap_big_number_endian(pkey);
  memcpy(skey, private_key, 32);
  swap_big_number_endian(skey);
  x25519(shared_secret, skey, pkey);
  swap_big_number_endian(shared_secret);
#else
  (void)shared_secret;
  (void)private_key;
  (void)public_key;
#endif
}
