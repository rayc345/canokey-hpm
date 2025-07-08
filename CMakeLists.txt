# Copyright (c) 2021-2025 HPMicro
# SPDX-License-Identifier: BSD-3-Clause

cmake_minimum_required(VERSION 3.13)

set(CONFIG_MBEDTLS 1)
# set(CONFIG_MBEDTLS_USE_HPM_SDP 1)

set(CONFIG_CHERRYUSB 1)
set(CONFIG_USB_DEVICE 1)
set(CONFIG_USB_DEVICE_HID 1)

find_package(hpm-sdk REQUIRED HINTS $ENV{HPM_SDK_BASE})

project(Canokey-hpm)

# tinycbor
sdk_app_inc(src/3rd_party/tinycbor)
sdk_app_src(src/3rd_party/tinycbor/cborencoder.c)
sdk_app_src(src/3rd_party/tinycbor/cborencoder_close_container_checked.c)
sdk_app_src(src/3rd_party/tinycbor/cborencoder_float.c)
sdk_app_src(src/3rd_party/tinycbor/cborerrorstrings.c)
sdk_app_src(src/3rd_party/tinycbor/cborparser.c)
sdk_app_src(src/3rd_party/tinycbor/cborparser_dup_string.c)
sdk_app_src(src/3rd_party/tinycbor/cborparser_float.c)
sdk_app_src(src/3rd_party/tinycbor/cborpretty.c)
sdk_app_src(src/3rd_party/tinycbor/cborpretty_stdio.c)
sdk_app_src(src/3rd_party/tinycbor/cbortojson.c)
sdk_app_src(src/3rd_party/tinycbor/cborvalidation.c)
# sdk_app_src(src/3rd_party/tinycbor/open_memstream.c)

# Canokey-crypto
sdk_app_inc(src/canokey-crypto/include)
sdk_app_src(src/canokey-crypto/src/aes.c)
sdk_app_src(src/canokey-crypto/src/algo.c)
sdk_app_src(src/canokey-crypto/src/block-cipher.c)
sdk_app_src(src/canokey-crypto/src/crypto-util.c)
sdk_app_src(src/canokey-crypto/src/ecc.c)
sdk_app_src(src/canokey-crypto/src/hmac.c)
sdk_app_src(src/canokey-crypto/src/memzero.c)
sdk_app_src(src/canokey-crypto/src/rand.c)
sdk_app_src(src/canokey-crypto/src/rsa.c)
sdk_app_src(src/canokey-crypto/src/sha.c)
sdk_app_src(src/canokey-crypto/src/sha3.c)
sdk_app_src(src/canokey-crypto/src/sm3.c)

# Canokey-core
# sdk_app_inc(src/canokey-core/applets/admin)
sdk_app_inc(src/canokey-core/applets/ctap)
# sdk_app_inc(src/canokey-core/applets/ndef)
# sdk_app_inc(src/canokey-core/applets/oath)
# sdk_app_inc(src/canokey-core/applets/openpgp)
# sdk_app_inc(src/canokey-core/applets/pass)
# sdk_app_inc(src/canokey-core/applets/piv)

sdk_app_src(src/canokey-core/applets/ctap/ctap-parser.c)
sdk_app_src(src/canokey-core/applets/ctap/ctap.c)
sdk_app_src(src/canokey-core/applets/ctap/secret.c)
sdk_app_src(src/canokey-core/applets/ctap/u2f.c)


# sdk_app_inc(src/canokey-core/interfaces/USB/class/ctaphid)
# sdk_app_inc(src/canokey-core/interfaces/USB/device)
sdk_app_inc(src/canokey-core/interfaces/USB/class/ctaphid)
sdk_app_src(src/canokey-core/interfaces/USB/class/ctaphid/ctaphid_device.c)

sdk_app_inc(src/canokey-core/include)
# sdk_app_src(src/canokey-core/src/apdu.c)
# sdk_app_src(src/canokey-core/src/applets.c)
sdk_app_src(src/canokey-core/src/common.c)
sdk_app_src(src/canokey-core/src/device.c)
sdk_app_src(src/canokey-core/src/fs.c)
sdk_app_src(src/canokey-core/src/key.c)
sdk_app_src(src/canokey-core/src/pin.c)

# sdk_app_src(src/canokey-core/interfaces\NFC\fm.c)
# sdk_app_src(src/canokey-core/interfaces\NFC\nfc.c)



# LittleFS
sdk_app_inc(src/3rd_party/littlefs)
sdk_app_src(src/3rd_party/littlefs/lfs_util.c)
sdk_app_src(src/3rd_party/littlefs/lfs.c)
sdk_app_inc(src/3rd_party/littlefs/port)
sdk_app_src(src/3rd_party/littlefs/port/lfs_port.c)
sdk_app_src(src/3rd_party/littlefs/port/xpi_util.c)

# Main
sdk_app_inc(src)
sdk_app_src(src/main.c)
sdk_app_src(src/device2.c)

sdk_compile_options(-fno-inline)

sdk_ses_opt_lib_io_type(RTT)

sdk_compile_definitions(USE_MBEDCRYPTO)
sdk_compile_definitions(DEBUG_OUTPUT)

generate_ide_projects()
