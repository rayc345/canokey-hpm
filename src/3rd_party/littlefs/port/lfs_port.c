// SPDX-License-Identifier: Apache-2.0
#include <stdalign.h>
#include <string.h>
#include "board.h"
#include "lfs.h"
#include "hpm_flash.h"
#include "fs.h"
#include <ndef.h>
#include <oath.h>
#include <openpgp.h>
#include <pass.h>
#include <pin.h>
#include <piv.h>
#include <admin.h>
#include <ctap.h>

#define READ_SIZE 32
#define STORAGE_SECTOR 80
#define FLASH_ADDR(b, o) (nor_config.flash_size - nor_config.sector_size * STORAGE_SECTOR + nor_config.base_addr + (b) * nor_config.sector_size + (o))
#define LOOKAHEAD_SIZE 256

static struct lfs_config config;
static nor_flash_config_t nor_config;

static alignas(64) uint8_t read_buffer[LFS_CACHE_SIZE];
static alignas(64) uint8_t prog_buffer[LFS_CACHE_SIZE];
static alignas(64) uint8_t lookahead_buffer[LOOKAHEAD_SIZE];

int block_read(const struct lfs_config *c, lfs_block_t block, lfs_off_t off, void *buffer, lfs_size_t size)
{
  (void)(c);
  return nor_flash_read(&nor_config, buffer, FLASH_ADDR(block, off), size) == status_success ? 0 : -1;
}

int block_prog(const struct lfs_config *c, lfs_block_t block, lfs_off_t off, const void *buffer, lfs_size_t size)
{
  (void)(c);
  return nor_flash_write(&nor_config, buffer, FLASH_ADDR(block, off), size) == status_success ? 0 : -1;
}

int block_erase(const struct lfs_config *c, lfs_block_t block)
{
  (void)(c);
  return nor_flash_erase_sector(&nor_config, FLASH_ADDR(block, 0)) == status_success ? 0 : -1;
}

int block_sync(const struct lfs_config *c)
{
  (void)(c);
  return 0;
}

void littlefs_init(void)
{
  nor_config.xpi_base = BOARD_APP_XPI_NOR_XPI_BASE;
  nor_config.base_addr = BOARD_FLASH_BASE_ADDRESS;

  nor_config.opt_header = BOARD_APP_XPI_NOR_CFG_OPT_HDR;
  nor_config.opt0 = BOARD_APP_XPI_NOR_CFG_OPT_OPT0;
  nor_config.opt1 = BOARD_APP_XPI_NOR_CFG_OPT_OPT1;

  nor_flash_init(&nor_config);

  printf("Flash Size:%dMBytes\nFlash Sector Size:%dKBytes\nFlash Page Size:%dBytes\n",
         nor_config.flash_size / 1024U / 1024U,
         nor_config.sector_size / 1024U,
         nor_config.page_size);

  memset(&config, 0, sizeof(config));
  // configuration of the filesystem is provided by this struct
  config.read = block_read;
  config.prog = block_prog;
  config.erase = block_erase;
  config.sync = block_sync;
  config.read_size = READ_SIZE;
  config.prog_size = nor_config.page_size;
  config.block_size = nor_config.sector_size;
  config.block_count = STORAGE_SECTOR;
  config.block_cycles = 100000;
  config.cache_size = LFS_CACHE_SIZE;
  config.lookahead_size = LOOKAHEAD_SIZE;
  config.read_buffer = read_buffer;
  config.prog_buffer = prog_buffer;
  config.lookahead_buffer = lookahead_buffer;

  // mount the filesystem
  int err;
  // int err = fs_mount(&config);

  // reformat if we can't mount the filesystem
  // this should only happen on the first boot
  // if (err)
  {
    printf("Mount Failed, formatting\n");
    err = fs_format(&config);
    printf("Formatting %02X\n", err);
    err = fs_mount(&config);
    printf("Remount %02X\n", err);
    openpgp_install(1);
    piv_install(1);
    oath_install(1);
    ctap_install(1);
    ndef_install(1);
    pass_install(1);
    admin_install(1);
  }

  return;
}

// #include "lfs_util.h"
// static xpi_nor_config_t s_xpi_nor_config;

// extern lfs_t lfs;
// static uint32_t sector_sz;
// static uint32_t page_sz;
// static uint32_t base_address;

// XPI_Type *base = BOARD_APP_XPI_NOR_XPI_BASE;

// static lfs_t lfs;

// lfs_file_t file;

// // write_file(DC_FILE, NULL, 0, 0, 1)

// // read current count
// uint32_t boot_count = 0;
// err = lfs_file_open(&lfs, &file, "boot_count", LFS_O_RDWR | LFS_O_CREAT);
// printf("Open1 %02X\n", err);
// err = lfs_file_read(&lfs, &file, &boot_count, sizeof(boot_count));
// printf("Read1 %02X\n", err);
// // update boot count
// boot_count += 1;
// err = lfs_file_rewind(&lfs, &file);
// printf("Rewind %02X\n", err);
// err = lfs_file_write(&lfs, &file, &boot_count, sizeof(boot_count));
// printf("write2 %02X\n", err);
// // remember the storage is not updated until the file is closed successfully
// err = lfs_file_close(&lfs, &file);
// printf("close %02X\n", err);
// // release any resources we were using
// // err = lfs_unmount(&lfs);
// // printf("unmount %02X\n", err);
// // print the boot count
// // printf("boot_count: %d\n", boot_count);

// lfs_file_t f;
// int flags = LFS_O_WRONLY | LFS_O_CREAT;
// if (1)
//   flags |= LFS_O_TRUNC;
// err = lfs_file_open(&lfs, &f, "ctap_test", flags);
// // if (err < 0)
// //   return err;
// err = lfs_file_seek(&lfs, &f, 0, LFS_SEEK_SET);
// err = lfs_file_close(&lfs, &f);
// return;
// read_attr(CTAP_CERT_FILE, PIN_ATTR, &tmp, 1)
// uint8_t tmp;
// err = lfs_getattr(&lfs, "ctap_cert", 0x02, &tmp, 1);
// err = fs_format(&config);
// printf("Formatting %02X\n", err);

// while (1)
// {
// }

// int block_read(const struct lfs_config *c, lfs_block_t block, lfs_off_t off, void *buffer, lfs_size_t size)
// {
//   (void)(c);
//   int ret = 0;
//   hpm_stat_t status;

//   // printf("RdS\n");
//   status = rom_xpi_nor_read(base, xpi_xfer_channel_auto, &s_xpi_nor_config,
//                             buffer, FLASH_ADDR(block, off), size);
//   if (status != status_success)
//   {
//     ret = LFS_ERR_CORRUPT;
//   }

//   // printf("RdE\n");
//   return ret;
// }

// int block_prog(const struct lfs_config *c, lfs_block_t block, lfs_off_t off, const void *buffer, lfs_size_t size)
// {
//   (void)(c);
//   int ret = 0;
//   hpm_stat_t status;

//   // printf("PrgS\n");
//   if (size % page_sz != 0 || off % page_sz != 0)
//     return LFS_ERR_INVAL;

//   status = rom_xpi_nor_program(base, xpi_xfer_channel_auto, &s_xpi_nor_config,
//                                buffer, FLASH_ADDR(block, off), size);
//   if (status != status_success)
//   {
//     ret = LFS_ERR_CORRUPT;
//   }

//   // printf("PrgE\n");
//   return ret;
// }

// int block_erase(const struct lfs_config *c, lfs_block_t block)
// {
//   (void)(c);
//   int ret = 0;

//   // printf("ErsS\n");
//   hpm_stat_t status;
//   status = rom_xpi_nor_erase(base, xpi_xfer_channel_auto, &s_xpi_nor_config,
//                              base_address + sector_sz * block, sector_sz);
//   if (status != status_success)
//   {
//     ret = LFS_ERR_CORRUPT;
//   }

//   // printf("ErsE\n");
//   return ret;
// }

// int block_sync(const struct lfs_config *c)
// {
//   (void)(c);
//   return 0;
// }
// xpi_nor_config_option_t option;
// option.header.U = BOARD_APP_XPI_NOR_CFG_OPT_HDR;
// option.option0.U = BOARD_APP_XPI_NOR_CFG_OPT_OPT0;
// option.option1.U = BOARD_APP_XPI_NOR_CFG_OPT_OPT1;

// XPI_Type *base = BOARD_APP_XPI_NOR_XPI_BASE;

// hpm_stat_t status = rom_xpi_nor_auto_config(base, &s_xpi_nor_config, &option);
// if (status != status_success)
// {
//   return;
// }
// uint32_t flash_size;
// uint32_t sector_size;
// uint32_t page_size;
// rom_xpi_nor_get_property(BOARD_APP_XPI_NOR_XPI_BASE, &s_xpi_nor_config, xpi_nor_property_total_size, &flash_size);
// rom_xpi_nor_get_property(BOARD_APP_XPI_NOR_XPI_BASE, &s_xpi_nor_config, xpi_nor_property_sector_size, &sector_size);
// rom_xpi_nor_get_property(BOARD_APP_XPI_NOR_XPI_BASE, &s_xpi_nor_config, xpi_nor_property_page_size, &page_size);

// printf("Flash Size:%dMBytes\nFlash Sector Size:%dKBytes\nFlash Page Size:%dBytes\n",
//        flash_size / 1024U / 1024U,
//        sector_size / 1024U,
//        page_size);

// sector_sz = sector_size;
// page_sz = page_size;
// base_address = flash_size - sector_size * STORAGE_SECTOR;
