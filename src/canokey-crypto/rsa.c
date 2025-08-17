// SPDX-License-Identifier: Apache-2.0
#include <rand.h>
#include <rsa.h>
#include <string.h>

#ifdef USE_CYCLONECRYPTO
#include "core/crypto.h"
#include "pkc/rsa.h"
#include "pkc/rsa_misc.h"
#include "debug.h"
#include "rng/hmac_drbg.h"
#include "crypto-util.h"

error_t rsaImportPrivateKey(RsaPrivateKey *privateKey, size_t k, const uint8_t *pe, const uint8_t *p, size_t lp, const uint8_t *q, size_t lq)
{
  error_t error;
  Mpi t1;
  Mpi t2;
  Mpi phy;

  //Check parameters
  if(privateKey == NULL)
    return ERROR_INVALID_PARAMETER;

  //Check the length of the modulus
  if(k < 8)
    return ERROR_INVALID_PARAMETER;

  uint_t e = LOAD32BE(pe);

  //Check the value of the public exponent
  if(e != 3 && e != 5 && e != 17 && e != 257 && e != 65537)
    return ERROR_INVALID_PARAMETER;

  //Initialize multiple precision integers
  mpiInit(&t1);
  mpiInit(&t2);
  mpiInit(&phy);

  //Save public exponent
  MPI_CHECK(mpiSetValue(&privateKey->e, e));

  MPI_CHECK(mpiImport(&privateKey->p, p, lp, MPI_FORMAT_BIG_ENDIAN));

  //Compute p mod e
  MPI_CHECK(mpiMod(&t1, &privateKey->p, &privateKey->e));

  MPI_CHECK(mpiImport(&privateKey->q, q, lq, MPI_FORMAT_BIG_ENDIAN));

  //Compute q mod e
  MPI_CHECK(mpiMod(&t2, &privateKey->q, &privateKey->e));

  //Make sure p an q are distinct
  if(mpiComp(&privateKey->p, &privateKey->q) == 0)
  {
    MPI_CHECK(ERROR_FAILURE);
  }

  //If p < q, then swap p and q (this only matters if the CRT form of
  //the private key is used)
  if(mpiComp(&privateKey->p, &privateKey->q) < 0)
  {
    //Swap primes
    mpiCopy(&t1, &privateKey->p);
    mpiCopy(&privateKey->p, &privateKey->q);
    mpiCopy(&privateKey->q, &t1);
  }

  //Compute the modulus n = pq
  MPI_CHECK(mpiMul(&privateKey->n, &privateKey->p, &privateKey->q));

  //Compute phy = (p-1)(q-1)
  MPI_CHECK(mpiSubInt(&t1, &privateKey->p, 1));
  MPI_CHECK(mpiSubInt(&t2, &privateKey->q, 1));
  MPI_CHECK(mpiMul(&phy, &t1, &t2));

  //Compute d = e^-1 mod phy
  MPI_CHECK(mpiInvMod(&privateKey->d, &privateKey->e, &phy));
  //Compute dP = d mod (p-1)
  MPI_CHECK(mpiMod(&privateKey->dp, &privateKey->d, &t1));
  //Compute dQ = d mod (q-1)
  MPI_CHECK(mpiMod(&privateKey->dq, &privateKey->d, &t2));
  //Compute qInv = q^-1 mod p
  MPI_CHECK(mpiInvMod(&privateKey->qinv, &privateKey->q, &privateKey->p));

  //Debug message
  TRACE_DEBUG("RSA private key:\r\n");
  TRACE_DEBUG("  Modulus:\r\n");
  TRACE_DEBUG_MPI("    ", &privateKey->n);
  TRACE_DEBUG("  Public exponent:\r\n");
  TRACE_DEBUG_MPI("    ", &privateKey->e);
  TRACE_DEBUG("  Private exponent:\r\n");
  TRACE_DEBUG_MPI("    ", &privateKey->d);
  TRACE_DEBUG("  Prime 1:\r\n");
  TRACE_DEBUG_MPI("    ", &privateKey->p);
  TRACE_DEBUG("  Prime 2:\r\n");
  TRACE_DEBUG_MPI("    ", &privateKey->q);
  TRACE_DEBUG("  Prime exponent 1:\r\n");
  TRACE_DEBUG_MPI("    ", &privateKey->dp);
  TRACE_DEBUG("  Prime exponent 2:\r\n");
  TRACE_DEBUG_MPI("    ", &privateKey->dq);
  TRACE_DEBUG("  Coefficient:\r\n");
  TRACE_DEBUG_MPI("    ", &privateKey->qinv);

end:
  //Release multiple precision integers
  mpiFree(&t1);
  mpiFree(&t2);
  mpiFree(&phy);

  //Any error to report?
  if(error)
  {
    //Release RSA private key
    rsaFreePrivateKey(privateKey);
  }

  //Return status code
  return error;
}

#endif

static int pkcs1_v15_add_padding(const void *in, uint16_t in_len, uint8_t *out, uint16_t out_len) {
  if (out_len < 11 || in_len > out_len - 11) return -1;
  uint16_t pad_size = out_len - in_len - 3;
  memmove(out + pad_size + 3, in, in_len);
  out[0] = 0x00;
  out[1] = 0x01;
  memset(out + 2, 0xFF, pad_size);
  out[2 + pad_size] = 0x00;
  return 0;
}

static int pkcs1_v15_remove_padding(const uint8_t *in, uint16_t in_len, uint8_t *out) {
  if (in_len < 11) return -1;
  if (in[0] != 0x00 || in[1] != 0x02) return -1;
  uint16_t i;
  for (i = 2; i < in_len; ++i)
    if (in[i] == 0x00) break;
  if (i == in_len || i - 2 < 8) return -1;
  memmove(out, in + i + 1, in_len - (i + 1));
  return in_len - (i + 1);
}

__attribute__((weak)) int rsa_generate_key(rsa_key_t *key, uint16_t nbits) {
  int ret = 0;
  RsaPrivateKey priKey;
  rsaInitPrivateKey(&priKey);
  error_t err = rsaGeneratePrivateKey(HMAC_DRBG_PRNG_ALGO, &rng_ctx, nbits, 65537, &priKey);
  if(err != NO_ERROR)
  {
    ret = 1;
    goto end;
  }
  key->nbits = nbits;
  err = mpiExport(&priKey.dp, key->dp, sizeof(key->dp), MPI_FORMAT_BIG_ENDIAN);
  if(err != NO_ERROR)
  {
    ret = 1;
    goto end;
  }
  err = mpiExport(&priKey.dq, key->dq, sizeof(key->dq), MPI_FORMAT_BIG_ENDIAN);
  if(err != NO_ERROR)
  {
    ret = 1;
    goto end;
  }
  err = mpiExport(&priKey.p, key->p, sizeof(key->p), MPI_FORMAT_BIG_ENDIAN);
  if(err != NO_ERROR)
  {
    ret = 1;
    goto end;
  }
  err = mpiExport(&priKey.q, key->q, sizeof(key->q), MPI_FORMAT_BIG_ENDIAN);
  if(err != NO_ERROR)
  {
    ret = 1;
    goto end;
  }
  err = mpiExport(&priKey.qinv, key->qinv, sizeof(key->qinv), MPI_FORMAT_BIG_ENDIAN);
  if(err != NO_ERROR)
  {
    ret = 1;
    goto end;
  }
  err = mpiExport(&priKey.e, key->e, sizeof(key->e), MPI_FORMAT_BIG_ENDIAN);
  if(err != NO_ERROR)
  {
    ret = 1;
    goto end;
  }
end:
  rsaFreePrivateKey(&priKey);
  return ret;
}

__attribute__((weak)) int rsa_get_public_key(rsa_key_t *key, uint8_t *n) {
  int ret = 0;
  RsaPrivateKey priKey;
  rsaInitPrivateKey(&priKey);
  error_t err;
  err = rsaImportPrivateKey(&priKey, key->nbits, key->e, key->p, key->nbits / 16, key->q, key->nbits / 16);
  if(err != NO_ERROR)
  {
    ret = 1;
    goto end;
  }
  mpiExport(&priKey.n, n, key->nbits / 8, MPI_FORMAT_BIG_ENDIAN);
end:
  rsaFreePrivateKey(&priKey);
  return ret;
}

__attribute__((weak)) int rsa_private(const rsa_key_t *key, const uint8_t *input, uint8_t *output) {
  int ret = 0;
  RsaPrivateKey priKey;
  Mpi m,c;
  mpiInit(&m);
  mpiInit(&c);
  rsaInitPrivateKey(&priKey);
  error_t err = rsaImportPrivateKey(&priKey, key->nbits, key->e, key->p, key->nbits / 16, key->q, key->nbits / 16);
  if(err != NO_ERROR)
  {
    ret = 1;
    goto end;
  }
  err = mpiImport(&c, input, key->nbits / 8, MPI_FORMAT_BIG_ENDIAN);
  if(err != NO_ERROR)
  {
    ret = 1;
    goto end;
  }
  err = rsadp(&priKey, &c, &m);
  if(err != NO_ERROR)
  {
    ret = 1;
    goto end;
  }
  err = mpiExport(&m, output, key->nbits / 8, MPI_FORMAT_BIG_ENDIAN);
  if(err != NO_ERROR)
  {
    ret = 1;
    goto end;
  }
end:
  mpiFree(&m);
  mpiFree(&c);
  rsaFreePrivateKey(&priKey);
  return ret;
}

int rsa_sign_pkcs_v15(const rsa_key_t *key, const uint8_t *data, const size_t len, uint8_t *sig) {
  if (pkcs1_v15_add_padding(data, len, sig, key->nbits / 8) < 0) return -1;
  return rsa_private(key, sig, sig);
}

int rsa_decrypt_pkcs_v15(const rsa_key_t *key, const uint8_t *in, size_t *olen, uint8_t *out, uint8_t *invalid_padding) {
  *invalid_padding = 0;
  if (rsa_private(key, in, out) < 0) return -1;
  const int len = pkcs1_v15_remove_padding(out, key->nbits / 8, out);
  if (len < 0) {
    *invalid_padding = 1;
    return -1;
  }
  *olen = len;
  return 0;
}
