// SPDX-License-Identifier: Apache-2.0
#include "ecc.h"
#include "memzero.h"
#include <common.h>
#include <key.h>

#define KEY_META_ATTR 0xFF
#define CEIL_DIV_SQRT2 0xB504F334
#define MAX_KEY_TEMPLATE_LENGTH 0x16

int ck_encode_public_key(ck_key_t *key, uint8_t *buf, bool include_length) {
  int off = 0;

  switch (key->meta.type) {
  case SECP256R1:
  case SECP256K1:
  case SECP384R1:
    if (include_length) {
      buf[off++] = PUBLIC_KEY_LENGTH[key->meta.type] + 3; // tag, length, and 0x04
    }
    buf[off++] = 0x86;
    buf[off++] = PUBLIC_KEY_LENGTH[key->meta.type] + 1; // 0x04
    buf[off++] = 0x04;
    memcpy(&buf[off], key->ecc.pub, PUBLIC_KEY_LENGTH[key->meta.type]);
    off += PUBLIC_KEY_LENGTH[key->meta.type];
    break;

  case RSA2048:
  case RSA3072:
  case RSA4096:
    if (include_length) { // 3-byte length
      buf[off++] = 0x82;
      // 6 = modulus: tag (1), length (3); exponent: tag (1), length (1)
      buf[off++] = HI(6 + PUBLIC_KEY_LENGTH[key->meta.type] + E_LENGTH);
      buf[off++] = LO(6 + PUBLIC_KEY_LENGTH[key->meta.type] + E_LENGTH);
    }
    buf[off++] = 0x81; // modulus
    buf[off++] = 0x82;
    buf[off++] = HI(PUBLIC_KEY_LENGTH[key->meta.type]);
    buf[off++] = LO(PUBLIC_KEY_LENGTH[key->meta.type]);
    rsa_get_public_key(&key->rsa, &buf[off]);
    off += PUBLIC_KEY_LENGTH[key->meta.type];
    buf[off++] = 0x82; // exponent
    buf[off++] = E_LENGTH;
    memcpy(&buf[off], key->rsa.e, E_LENGTH);
    off += E_LENGTH;
    break;

  default:
    return -1;
  }

  return off;
}

int ck_parse_piv_policies(ck_key_t *key, const uint8_t *buf, size_t buf_len) {
  const uint8_t *end = buf + buf_len;

  while (buf < end) {
    switch (*buf++) {
    case 0xAA:
      DBG_MSG("May have pin policy\n");
      if (buf < end && *buf++ != 0x01) {
        DBG_MSG("Wrong length for pin policy\n");
        return KEY_ERR_LENGTH;
      }
      if (buf < end && (*buf > PIN_POLICY_ALWAYS || *buf < PIN_POLICY_NEVER)) {
        DBG_MSG("Wrong data for pin policy\n");
        return KEY_ERR_DATA;
      }
      key->meta.pin_policy = *buf++;
      break;

    case 0xAB:
      DBG_MSG("May have touch policy\n");
      if (buf < end && *buf++ != 0x01) {
        DBG_MSG("Wrong length for touch policy\n");
        return KEY_ERR_LENGTH;
      }
      if (buf < end && (*buf > TOUCH_POLICY_CACHED || *buf < TOUCH_POLICY_NEVER)) {
        DBG_MSG("Wrong data for touch policy\n");
        return KEY_ERR_DATA;
      }
      key->meta.touch_policy = *buf++;
      break;
    
    default:
      buf = end;
      break;
    }
  }

  return 0;
}

int ck_parse_piv(ck_key_t *key, const uint8_t *buf, size_t buf_len) {
  memzero(key->data, sizeof(rsa_key_t));
  key->meta.origin = KEY_ORIGIN_IMPORTED;

  const uint8_t *p = buf;

  switch (key->meta.type) {
  case SECP256R1:
  case SECP256K1:
  case SECP384R1: {

    if (buf_len < PRIVATE_KEY_LENGTH[key->meta.type] + 2) {
      DBG_MSG("too short\n");
      return KEY_ERR_LENGTH;
    }
    if (*p != 0x06) {
      DBG_MSG("invalid tag\n");
      return KEY_ERR_DATA;
    }
    p++;
    if (*p++ != PRIVATE_KEY_LENGTH[key->meta.type]) {
      DBG_MSG("invalid private key length\n");
      return KEY_ERR_LENGTH;
    }
    memcpy(key->ecc.pri, p, PRIVATE_KEY_LENGTH[key->meta.type]);
    if (!ecc_verify_private_key(key->meta.type, &key->ecc)) {
      memzero(key, sizeof(ck_key_t));
      return KEY_ERR_DATA;
    }
    if (ecc_complete_key(key->meta.type, &key->ecc) < 0) {
      memzero(key, sizeof(ck_key_t));
      return KEY_ERR_PROC;
    }
    p += PRIVATE_KEY_LENGTH[key->meta.type];
    break;
  }

  case RSA2048:
  case RSA3072:
  case RSA4096: {
    int fail;
    size_t length_size;

    key->rsa.nbits = PRIVATE_KEY_LENGTH[key->meta.type] * 16;
    *(uint32_t *)key->rsa.e = htobe32(65537);

    uint8_t *data_ptr[] = {key->rsa.p, key->rsa.q, key->rsa.dp, key->rsa.dq, key->rsa.qinv};

    for (int i = 1; i <= 5; ++i) {
      if ((size_t)(p - buf) >= buf_len) return KEY_ERR_LENGTH;
      if (*p++ != i) return KEY_ERR_DATA;
      const size_t len = tlv_get_length_safe(p, buf_len - (p - buf), &fail, &length_size);
      if (fail) return KEY_ERR_LENGTH;
      if (len > PRIVATE_KEY_LENGTH[key->meta.type]) return KEY_ERR_DATA;
      p += length_size;
      memcpy(data_ptr[i - 1] + (PRIVATE_KEY_LENGTH[key->meta.type] - len), p, len);
      p += len;
    }

    if (be32toh(*(uint32_t *)key->rsa.p) < CEIL_DIV_SQRT2 || be32toh(*(uint32_t *)key->rsa.q) < CEIL_DIV_SQRT2) {
      memzero(key, sizeof(ck_key_t));
      return KEY_ERR_DATA;
    }

    break;
  }

  default:
    return -1;
  }

  return ck_parse_piv_policies(key, p, buf + buf_len - p);
}

int ck_read_key_metadata(const char *path, key_meta_t *meta) {
  return read_attr(path, KEY_META_ATTR, meta, sizeof(key_meta_t));
}

int ck_write_key_metadata(const char *path, const key_meta_t *meta) {
  return write_attr(path, KEY_META_ATTR, meta, sizeof(key_meta_t));
}

int ck_read_key(const char *path, ck_key_t *key) {
  const int err = ck_read_key_metadata(path, &key->meta);
  if (err < 0) return err;
  return read_file(path, key->data, 0, sizeof(rsa_key_t));
}

int ck_write_key(const char *path, const ck_key_t *key) {
  const int err = write_file(path, key->data, 0, sizeof(rsa_key_t), 1);
  if (err < 0) return err;
  return ck_write_key_metadata(path, &key->meta);
}

int ck_generate_key(ck_key_t *key) {
  key->meta.origin = KEY_ORIGIN_GENERATED;

  if (IS_ECC(key->meta.type)) {
    if (ecc_generate(key->meta.type, &key->ecc) < 0) {
      memzero(key, sizeof(ck_key_t));
      return -1;
    }
    return 0;
  } else if (IS_RSA(key->meta.type)) {
    if (rsa_generate_key(&key->rsa, PUBLIC_KEY_LENGTH[key->meta.type] * 8) < 0) {
      memzero(key, sizeof(ck_key_t));
      return -1;
    }
    return 0;
  } else {
    return -1;
  }
}

int ck_sign(const ck_key_t *key, const uint8_t *input, size_t input_len, uint8_t *sig) {
  DBG_MSG("Data: ");
  PRINT_HEX(input, input_len);
  if (IS_ECC(key->meta.type)) {
    DBG_MSG("Private Key: ");
    PRINT_HEX(key->ecc.pri, PRIVATE_KEY_LENGTH[key->meta.type]);
    DBG_MSG("Public Key: ");
    PRINT_HEX(key->ecc.pub, PUBLIC_KEY_LENGTH[key->meta.type]);
    if (ecc_sign(key->meta.type, &key->ecc, input, input_len, sig) < 0) {
      ERR_MSG("ECC signing failed\n");
      DBG_KEY_META(&key->meta);
      return -1;
    }
  } else if (IS_RSA(key->meta.type)) {
    DBG_MSG("Key: ");
    PRINT_HEX(key->rsa.p, PRIVATE_KEY_LENGTH[key->meta.type]);
    PRINT_HEX(key->rsa.q, PRIVATE_KEY_LENGTH[key->meta.type]);
    if (rsa_sign_pkcs_v15(&key->rsa, input, input_len, sig) < 0) {
      ERR_MSG("RSA signing failed\n");
      DBG_KEY_META(&key->meta);
      return -1;
    }
  } else {
    return -1;
  }
  DBG_MSG("Sig: ");
  PRINT_HEX(sig, SIGNATURE_LENGTH[key->meta.type]);
  return SIGNATURE_LENGTH[key->meta.type];
}
