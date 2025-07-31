/**
 * @file crypto_config.h
 * @brief CycloneCrypto configuration file
 *
 * @section License
 *
 * Copyright (C) 2021-2025 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneBOOT Open
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.5.2
 **/

#ifndef _CRYPTO_CONFIG_H
#define _CRYPTO_CONFIG_H

#define GPL_LICENSE_TERMS_ACCEPTED

// Desired trace level (for debugging purposes)
#define CRYPTO_TRACE_LEVEL TRACE_LEVEL_VERBOSE

// Static memory allocation
#define CRYPTO_STATIC_MEM_SUPPORT ENABLED

// Multiple precision integer support
#define MPI_SUPPORT ENABLED

// Assembly optimizations for time-critical routines
#define MPI_ASM_SUPPORT DISABLED

// Base64 encoding support
#define BASE64_SUPPORT DISABLED

// Base64url encoding support
#define BASE64URL_SUPPORT DISABLED

// Radix64 encoding support
#define RADIX64_SUPPORT DISABLED

// MD2 hash support
#define MD2_SUPPORT DISABLED

// MD4 hash support
#define MD4_SUPPORT DISABLED

// MD5 hash support
#define MD5_SUPPORT DISABLED

// RIPEMD-128 hash support
#define RIPEMD128_SUPPORT DISABLED

// RIPEMD-160 hash support
#define RIPEMD160_SUPPORT DISABLED

// SHA-1 hash support
#define SHA1_SUPPORT ENABLED

// SHA-224 hash support
#define SHA224_SUPPORT DISABLED

// SHA-256 hash support
#define SHA256_SUPPORT ENABLED

// SHA-384 hash support
#define SHA384_SUPPORT DISABLED

// SHA-512 hash support
#define SHA512_SUPPORT ENABLED

// SHA-512/224 hash support
#define SHA512_224_SUPPORT DISABLED

// SHA-512/256 hash support
#define SHA512_256_SUPPORT DISABLED

// SHA3-224 hash support
#define SHA3_224_SUPPORT DISABLED

// SHA3-256 hash support
#define SHA3_256_SUPPORT DISABLED

// SHA3-384 hash support
#define SHA3_384_SUPPORT DISABLED

// SHA3-512 hash support
#define SHA3_512_SUPPORT DISABLED

// Ascon-Hash256 hash support
#define ASCON_HASH256_SUPPORT DISABLED

// BLAKE2b support
#define BLAKE2B_SUPPORT DISABLED

// BLAKE2b-160 hash support
#define BLAKE2B160_SUPPORT DISABLED

// BLAKE2b-256 hash support
#define BLAKE2B256_SUPPORT DISABLED

// BLAKE2b-384 hash support
#define BLAKE2B384_SUPPORT DISABLED

// BLAKE2b-512 hash support
#define BLAKE2B512_SUPPORT DISABLED

// BLAKE2s support
#define BLAKE2S_SUPPORT DISABLED

// BLAKE2s-128 hash support
#define BLAKE2S128_SUPPORT DISABLED

// BLAKE2s-160 hash support
#define BLAKE2S160_SUPPORT DISABLED

// BLAKE2s-224 hash support
#define BLAKE2S224_SUPPORT DISABLED

// BLAKE2s-256 hash support
#define BLAKE2S256_SUPPORT DISABLED

// SM3 hash support
#define SM3_SUPPORT ENABLED

// Tiger hash support
#define TIGER_SUPPORT DISABLED

// Whirlpool hash support
#define WHIRLPOOL_SUPPORT DISABLED

// Keccak support
#define KECCAK_SUPPORT DISABLED

// SHAKE support
#define SHAKE_SUPPORT DISABLED

// cSHAKE support
#define CSHAKE_SUPPORT DISABLED

// Ascon-XOF128 support
#define ASCON_XOF128_SUPPORT DISABLED

// Ascon-CXOF128 support
#define ASCON_CXOF128_SUPPORT DISABLED

// CMAC support
#define CMAC_SUPPORT DISABLED

// HMAC support
#define HMAC_SUPPORT ENABLED

// GMAC support
#define GMAC_SUPPORT DISABLED

// KMAC support
#define KMAC_SUPPORT DISABLED

// XCBC-MAC support
#define XCBC_MAC_SUPPORT DISABLED

// Poly1305 support
#define POLY1305_SUPPORT DISABLED

// RC2 block cipher support
#define RC2_SUPPORT DISABLED

// RC4 stream cipher support
#define RC4_SUPPORT DISABLED

// RC6 block cipher support
#define RC6_SUPPORT DISABLED

// CAST-128 block cipher support
#define CAST128_SUPPORT DISABLED

// CAST-256 block cipher support
#define CAST256_SUPPORT DISABLED

// IDEA block cipher support
#define IDEA_SUPPORT DISABLED

// DES block cipher support
#define DES_SUPPORT ENABLED

// Triple DES block cipher support
#define DES3_SUPPORT ENABLED

// AES block cipher support
#define AES_SUPPORT ENABLED

// Blowfish block cipher support
#define BLOWFISH_SUPPORT DISABLED

// Twofish block cipher support
#define TWOFISH_SUPPORT DISABLED

// MARS block cipher support
#define MARS_SUPPORT DISABLED

// Serpent block cipher support
#define SERPENT_SUPPORT DISABLED

// Camellia block cipher support
#define CAMELLIA_SUPPORT DISABLED

// ARIA block cipher support
#define ARIA_SUPPORT DISABLED

// SEED block cipher support
#define SEED_SUPPORT DISABLED

// SM4 block cipher support
#define SM4_SUPPORT DISABLED

// PRESENT block cipher support
#define PRESENT_SUPPORT DISABLED

// TEA block cipher support
#define TEA_SUPPORT DISABLED

// XTEA block cipher support
#define XTEA_SUPPORT DISABLED

// ChaCha stream cipher support
#define CHACHA_SUPPORT DISABLED

// Salsa20 stream cipher support
#define SALSA20_SUPPORT DISABLED

// Trivium stream cipher support
#define TRIVIUM_SUPPORT DISABLED

// ZUC stream cipher support
#define ZUC_SUPPORT DISABLED

// ECB mode support
#define ECB_SUPPORT DISABLED

// CBC mode support
#define CBC_SUPPORT ENABLED

// CFB mode support
#define CFB_SUPPORT DISABLED

// OFB mode support
#define OFB_SUPPORT DISABLED

// CTR mode support
#define CTR_SUPPORT DISABLED

// XTS mode support
#define XTS_SUPPORT DISABLED

// CCM mode support
#define CCM_SUPPORT DISABLED

// GCM mode support
#define GCM_SUPPORT DISABLED

// SIV mode support
#define SIV_SUPPORT DISABLED

// Ascon-AEAD128 support
#define ASCON_AEAD128_SUPPORT DISABLED

// ChaCha20Poly1305 support
#define CHACHA20_POLY1305_SUPPORT DISABLED

// Diffie-Hellman support
#define DH_SUPPORT DISABLED

// RSA support
#define RSA_SUPPORT ENABLED

// DSA support
#define DSA_SUPPORT DISABLED

// Elliptic curve cryptography support
#define EC_SUPPORT ENABLED

// ECDH support
#define ECDH_SUPPORT ENABLED

// ECDSA support
#define ECDSA_SUPPORT ENABLED

// ED25519 support
#define ED25519_SUPPORT ENABLED

// X25519 support
#define X25519_SUPPORT ENABLED

// SECP256K1 support
#define SECP256K1_SUPPORT ENABLED

// SM2 support
#define SM2_SUPPORT ENABLED

// Key encapsulation mechanism support
#define KEM_SUPPORT DISABLED

// ML-KEM-512 support
#define MLKEM512_SUPPORT DISABLED

// ML-KEM-768 support
#define MLKEM768_SUPPORT DISABLED

// ML-KEM-1024 support
#define MLKEM1024_SUPPORT DISABLED

// Streamlined NTRU Prime 761 support
#define SNTRUP761_SUPPORT DISABLED

// HKDF support
#define HKDF_SUPPORT DISABLED

// PBKDF support
#define PBKDF_SUPPORT DISABLED

// Concat KDF support
#define CONCAT_KDF_SUPPORT DISABLED

// bcrypt support
#define BCRYPT_SUPPORT DISABLED

// scrypt support
#define SCRYPT_SUPPORT DISABLED

// MD5-crypt support
#define MD5_CRYPT_SUPPORT DISABLED

// SHA-crypt support
#define SHA_CRYPT_SUPPORT DISABLED

// HMAC_DRBG PRNG support
#define HMAC_DRBG_SUPPORT ENABLED

// Yarrow PRNG support
#define YARROW_SUPPORT DISABLED

// Object identifier support
#define OID_SUPPORT DISABLED

// ASN.1 syntax support
#define ASN1_SUPPORT ENABLED

// PEM file support
#define PEM_SUPPORT DISABLED

// X.509 certificate support
#define X509_SUPPORT DISABLED

// PKCS #5 support
#define PKCS5_SUPPORT DISABLED

// PKCS #7 support
#define PKCS7_SUPPORT DISABLED
//////

#endif //!_CRYPTO_CONFIG_H
