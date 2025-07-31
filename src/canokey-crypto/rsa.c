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


error_t rsaImportPrivateKey(size_t k, uint_t e, RsaPrivateKey *privateKey, const uint8_t *p, size_t lp, const uint8_t *q, size_t lq)
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

   //Check the value of the public exponent
   if(e != 3 && e != 5 && e != 17 && e != 257 && e != 65537)
      return ERROR_INVALID_PARAMETER;

   //Initialize multiple precision integers
   mpiInit(&t1);
   mpiInit(&t2);
   mpiInit(&phy);

   //Save public exponent
   MPI_CHECK(mpiSetValue(&privateKey->e, e));

   //Generate a large random prime p
  //  do
  //  {
  //     do
  //     {
        //  //Generate a random number of bit length k/2
        //  MPI_CHECK(mpiRand(&privateKey->p, k / 2, prngAlgo, prngContext));
         MPI_CHECK(mpiImport(&privateKey->p, p, lp, MPI_FORMAT_BIG_ENDIAN));
         //Set the low bit (this ensures the number is odd)
         MPI_CHECK(mpiSetBitValue(&privateKey->p, 0, 1));
         //Set the two highest bits (this ensures that the high bit of n is also set)
         MPI_CHECK(mpiSetBitValue(&privateKey->p, k / 2 - 1, 1));
         MPI_CHECK(mpiSetBitValue(&privateKey->p, k / 2 - 2, 1));

         //Test whether p is a probable prime
         error = mpiCheckProbablePrime(&privateKey->p);

      //    //Repeat until an acceptable value is found
      // } while(error == ERROR_INVALID_VALUE);

      //Check status code
      MPI_CHECK(error);

      //Compute p mod e
      MPI_CHECK(mpiMod(&t1, &privateKey->p, &privateKey->e));

  //     //Repeat as long as p mod e = 1
  //  } while(mpiCompInt(&t1, 1) == 0);

   //Generate a large random prime q
  //  do
  //  {
      // do
      // {
         //Generate random number of bit length k - k/2
        //  MPI_CHECK(mpiRand(&privateKey->q, k - (k / 2), prngAlgo, prngContext));
         MPI_CHECK(mpiImport(&privateKey->q, q, lq, MPI_FORMAT_BIG_ENDIAN));
         //Set the low bit (this ensures the number is odd)
         MPI_CHECK(mpiSetBitValue(&privateKey->q, 0, 1));
         //Set the two highest bits (this ensures that the high bit of n is also set)
         MPI_CHECK(mpiSetBitValue(&privateKey->q, k - (k / 2) - 1, 1));
         MPI_CHECK(mpiSetBitValue(&privateKey->q, k - (k / 2) - 2, 1));

      //    //Test whether q is a probable prime
      //    error = mpiCheckProbablePrime(&privateKey->q);

      //    //Repeat until an acceptable value is found
      // } while(error == ERROR_INVALID_VALUE);

      //Check status code
      MPI_CHECK(error);

      //Compute q mod e
      MPI_CHECK(mpiMod(&t2, &privateKey->q, &privateKey->e));

  //     //Repeat as long as p mod e = 1
  //  } while(mpiCompInt(&t2, 1) == 0);

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
  RsaPublicKey pubKey;
  RsaPrivateKey priKey;
  rsaInitPublicKey(&pubKey);
  rsaInitPrivateKey(&priKey);
  error_t err = rsaGenerateKeyPair(HMAC_DRBG_PRNG_ALGO, &rng_ctx, nbits, 65537, &priKey, &pubKey);
  if(err != NO_ERROR)
    printf("RSA Error %s %d %02X", __func__, __LINE__, err);
  key->nbits = nbits;
  mpiExport(&priKey.dp, key->dp, sizeof(key->dp), MPI_FORMAT_BIG_ENDIAN);
  mpiExport(&priKey.dq, key->dq, sizeof(key->dq), MPI_FORMAT_BIG_ENDIAN);
  mpiExport(&priKey.p, key->p, sizeof(key->p), MPI_FORMAT_BIG_ENDIAN);
  mpiExport(&priKey.q, key->q, sizeof(key->q), MPI_FORMAT_BIG_ENDIAN);
  mpiExport(&priKey.qinv, key->qinv, sizeof(key->qinv), MPI_FORMAT_BIG_ENDIAN);
  mpiExport(&priKey.e, key->e, sizeof(key->e), MPI_FORMAT_BIG_ENDIAN);
  // key->dp = priKey.dp;
  // key->dq = priKey.dq;
  // key->p = priKey.p;
  // key->q = priKey.q;
  // key->qinv = priKey.qinv;
  // key->e = priKey.e;

  rsaFreePrivateKey(&priKey);
  rsaFreePublicKey(&pubKey);
  
// #ifdef USE_CYCLONECRYPTO
//   mbedtls_rsa_context rsa;
//   mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
//   if (mbedtls_rsa_gen_key(&rsa, mbedtls_rnd, NULL, nbits, 65537) < 0) {
//     ret = -1;
//     goto cleanup;
//   }
//   key->nbits = nbits;
//   int pq_len = nbits / 16;
//   if (mbedtls_rsa_export_raw(&rsa, NULL, 0, key->p, pq_len, key->q, pq_len, NULL, 0, key->e, 4) < 0) {
//     ret = -1;
//     goto cleanup;
//   }
// cleanup:
//   mbedtls_rsa_free(&rsa);
// #else
//   (void)key;
//   (void)nbits;
// #endif
  return ret;
}

__attribute__((weak)) int rsa_get_public_key(rsa_key_t *key, uint8_t *n) {
  int ret = 0;
  RsaPublicKey pubKey;
  RsaPrivateKey priKey;
  rsaInitPublicKey(&pubKey);
  rsaInitPrivateKey(&priKey);
  error_t err;
  //Mpi ne;
  //mpiInit(&ne);
  //error_t err = mpiImport(&ne, key->e, sizeof(key->e), MPI_FORMAT_BIG_ENDIAN);
  //if(err != NO_ERROR)
  //  printf("RSA Error %s %d %02X", __func__, __LINE__, err);
  //mpiFree(&ne);
  
  err = rsaImportPrivateKey(key->nbits, 65537, &priKey, key->p, sizeof(key->p), key->q, sizeof(key->q));
  if(err != NO_ERROR)
    printf("RSA Error %s %d %02X", __func__, __LINE__, err);
  err = rsaGeneratePublicKey(&priKey, &pubKey);
  if(err != NO_ERROR)
    printf("RSA Error %s %d %02X", __func__, __LINE__, err);
  // error_t err = rsaGenerateKeyPair(HMAC_DRBG_PRNG_ALGO, &rng_ctx, nbits, 65537, &priKey, &pubKey);
  // if(err != NO_ERROR)
  //   printf("RSA Error %s %d %02X", __func__, __LINE__, err);
  // key->nbits = nbits;
  // mpiExport(&priKey.dp, key->dp, sizeof(key->dp), MPI_FORMAT_BIG_ENDIAN);
  // mpiExport(&priKey.dq, key->dq, sizeof(key->dq), MPI_FORMAT_BIG_ENDIAN);
  // mpiExport(&priKey.p, key->p, sizeof(key->p), MPI_FORMAT_BIG_ENDIAN);
  // mpiExport(&priKey.q, key->q, sizeof(key->q), MPI_FORMAT_BIG_ENDIAN);
  // mpiExport(&priKey.qinv, key->qinv, sizeof(key->qinv), MPI_FORMAT_BIG_ENDIAN);
  // mpiExport(&priKey.e, key->e, sizeof(key->e), MPI_FORMAT_BIG_ENDIAN);
  mpiExport(&priKey.n, n, key->nbits / 8, MPI_FORMAT_BIG_ENDIAN);
  
  // key->dp = priKey.dp;
  // key->dq = priKey.dq;
  // key->p = priKey.p;
  // key->q = priKey.q;
  // key->qinv = priKey.qinv;
  // key->e = priKey.e;
  rsaFreePrivateKey(&priKey);
  rsaFreePublicKey(&pubKey);
// #ifdef USE_CYCLONECRYPTO
//   mbedtls_rsa_context rsa;
//   mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
//   int pq_len = key->nbits / 16;
//   if (mbedtls_rsa_import_raw(&rsa, NULL, 0, key->p, pq_len, key->q, pq_len, NULL, 0, key->e, 4) < 0) {
//     ret = -1;
//     goto cleanup;
//   }
//   if (mbedtls_rsa_complete(&rsa) < 0) {
//     ret = -1;
//     goto cleanup;
//   }
//   if (mbedtls_rsa_export_raw(&rsa, n, pq_len * 2, NULL, 0, NULL, 0, NULL, 0, NULL, 0) < 0) {
//     ret = -1;
//     goto cleanup;
//   }
// cleanup:
//   mbedtls_rsa_free(&rsa);
// #else
//   (void)key;
//   (void)n;
// #endif
  return ret;
}

__attribute__((weak)) int rsa_private(const rsa_key_t *key, const uint8_t *input, uint8_t *output) {
  int ret = 0;
  RsaPrivateKey priKey;
  rsaInitPrivateKey(&priKey);
  error_t err = rsaImportPrivateKey(key->nbits, 65537, &priKey, key->p, sizeof(key->p), key->q, sizeof(key->q));
  if(err != NO_ERROR)
    printf("RSA Error %s %d %02X", __func__, __LINE__, err);
  Mpi m,c;
  mpiInit(&m);
  mpiInit(&c);
  err = mpiImport(&c, input, key->nbits / 8, MPI_FORMAT_BIG_ENDIAN);
  if(err != NO_ERROR)
    printf("RSA Error %s %d %02X", __func__, __LINE__, err);
  err = rsadp(&priKey, &c, &m);
  if(err != NO_ERROR)
    printf("RSA Error %s %d %02X", __func__, __LINE__, err);
  err = mpiExport(&m, output, key->nbits / 8, MPI_FORMAT_BIG_ENDIAN);
  if(err != NO_ERROR)
    printf("RSA Error %s %d %02X", __func__, __LINE__, err);
  mpiFree(&m);
  mpiFree(&c);
  rsaFreePrivateKey(&priKey);
// #ifdef USE_CYCLONECRYPTO
//   mbedtls_rsa_context rsa;
//   mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
//   int pq_len = key->nbits / 16;
//   if (mbedtls_rsa_import_raw(&rsa, NULL, 0, key->p, pq_len, key->q, pq_len, NULL, 0, key->e, 4) < 0) {
//     ret = -1;
//     goto cleanup;
//   }
//   if (mbedtls_rsa_complete(&rsa) < 0) {
//     ret = -1;
//     goto cleanup;
//   }
//   if (mbedtls_rsa_private(&rsa, mbedtls_rnd, NULL, input, output) < 0) {
//     ret = -1;
//     goto cleanup;
//   }
// cleanup:
//   mbedtls_rsa_free(&rsa);
// #else
//   (void)key;
//   (void)input;
//   (void)output;
// #endif
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
