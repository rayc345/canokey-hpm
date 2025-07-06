// SPDX-License-Identifier: Apache-2.0
#include <stdalign.h>
#include <string.h>
#include "board.h"
#include "hpm_clock_drv.h"
#include "hpm_l1c_drv.h"
#include "xpi_util.h"
#include "lfs.h"
#include "lfs_util.h"

static xpi_nor_config_t s_xpi_nor_config;

#define READ_SIZE 8
#define STORAGE_SECTOR 8
#define FLASH_ADDR(b, o) (base_address + (b) * page_sz + (o))

static uint32_t sector_sz;
static uint32_t page_sz;
static uint32_t base_address;

XPI_Type *base = BOARD_APP_XPI_NOR_XPI_BASE;

static lfs_t lfs;
static struct lfs_config config;

#define LFS_CACHE_SIZE 512
#define LOOKAHEAD_SIZE 512

static alignas(4) uint8_t read_buffer[LFS_CACHE_SIZE];
static alignas(4) uint8_t prog_buffer[LFS_CACHE_SIZE];
static alignas(4) uint8_t lookahead_buffer[LOOKAHEAD_SIZE];

int block_read(const struct lfs_config *c, lfs_block_t block, lfs_off_t off, void *buffer, lfs_size_t size)
{
  int ret = 0;
  hpm_stat_t status;

  status = rom_xpi_nor_read(base, xpi_xfer_channel_auto, &s_xpi_nor_config,
                            buffer, FLASH_ADDR(block, off), size);
  if (status != status_success)
  {
    ret = LFS_ERR_CORRUPT;
  }

  return ret;
}

int block_prog(const struct lfs_config *c, lfs_block_t block, lfs_off_t off, const void *buffer, lfs_size_t size)
{
  int ret = 0;
  hpm_stat_t status;

  if (size % page_sz != 0 || off % page_sz != 0)
    return LFS_ERR_INVAL;

  status = rom_xpi_nor_program(base, xpi_xfer_channel_auto, &s_xpi_nor_config,
                               buffer, FLASH_ADDR(block, off), size);
  if (status != status_success)
  {
    ret = LFS_ERR_CORRUPT;
  }

  return ret;
}

int block_erase(const struct lfs_config *c, lfs_block_t block)
{
  int ret = 0;

  hpm_stat_t status;
  status = rom_xpi_nor_erase(base, xpi_xfer_channel_auto, &s_xpi_nor_config,
                             base_address + sector_sz * block, sector_sz);
  if (status != status_success)
  {
    ret = LFS_ERR_CORRUPT;
  }

  return ret;
}

int block_sync(const struct lfs_config *c)
{
  return 0;
}

void littlefs_init(void)
{
  xpi_nor_config_option_t option;
  option.header.U = BOARD_APP_XPI_NOR_CFG_OPT_HDR;
  option.option0.U = BOARD_APP_XPI_NOR_CFG_OPT_OPT0;
  option.option1.U = BOARD_APP_XPI_NOR_CFG_OPT_OPT1;

  XPI_Type *base = BOARD_APP_XPI_NOR_XPI_BASE;

  hpm_stat_t status = rom_xpi_nor_auto_config(base, &s_xpi_nor_config, &option);
  if (status != status_success)
  {
    return;
  }
  uint32_t flash_size;
  uint32_t sector_size;
  uint32_t page_size;
  rom_xpi_nor_get_property(BOARD_APP_XPI_NOR_XPI_BASE, &s_xpi_nor_config, xpi_nor_property_total_size, &flash_size);
  rom_xpi_nor_get_property(BOARD_APP_XPI_NOR_XPI_BASE, &s_xpi_nor_config, xpi_nor_property_sector_size, &sector_size);
  rom_xpi_nor_get_property(BOARD_APP_XPI_NOR_XPI_BASE, &s_xpi_nor_config, xpi_nor_property_page_size, &page_size);

  printf("Flash Size:%dMBytes\nFlash Sector Size:%dKBytes\nFlash Page Size:%dBytes\n",
         flash_size / 1024U / 1024U,
         sector_size / 1024U,
         page_size);

  sector_sz = sector_size;
  page_sz = page_size;
  base_address = flash_size - sector_size * STORAGE_SECTOR;

  memset(&config, 0, sizeof(config));
  // configuration of the filesystem is provided by this struct
  config.read = block_read;
  config.prog = block_prog;
  config.erase = block_erase;
  config.sync = block_sync;
  config.read_size = READ_SIZE;
  config.prog_size = page_size;
  config.block_size = sector_size;
  config.block_count = STORAGE_SECTOR;
  config.block_cycles = 100000;
  config.cache_size = LFS_CACHE_SIZE;
  config.lookahead_size = LOOKAHEAD_SIZE;
  config.read_buffer = read_buffer;
  config.prog_buffer = prog_buffer;
  config.lookahead_buffer = lookahead_buffer;

  // mount the filesystem
  int err = lfs_mount(&lfs, &config);

  // reformat if we can't mount the filesystem
  // this should only happen on the first boot
  if (err)
  {
    printf("Mount Failed, formatting\n");
    err = lfs_format(&lfs, &config);
    printf("Formatting %02X\n", err);
    err = lfs_mount(&lfs, &config);
    printf("Remount %02X\n", err);
  }

  lfs_file_t file;

  // read current count
  uint32_t boot_count = 0;
  err = lfs_file_open(&lfs, &file, "boot_count", LFS_O_RDWR | LFS_O_CREAT);
  printf("Open1 %02X\n", err);
  err = lfs_file_read(&lfs, &file, &boot_count, sizeof(boot_count));
  printf("Read1 %02X\n", err);
  // update boot count
  boot_count += 1;
  err = lfs_file_rewind(&lfs, &file);
  printf("Rewind %02X\n", err);
  err = lfs_file_write(&lfs, &file, &boot_count, sizeof(boot_count));
  printf("write2 %02X\n", err);
  // remember the storage is not updated until the file is closed successfully
  err = lfs_file_close(&lfs, &file);
  printf("close %02X\n", err);
  // release any resources we were using
  err = lfs_unmount(&lfs);
  printf("unmount %02X\n", err);
  // print the boot count
  printf("boot_count: %d\n", boot_count);
}
