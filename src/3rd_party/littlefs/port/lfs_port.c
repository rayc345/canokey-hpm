// SPDX-License-Identifier: Apache-2.0
#include <stdalign.h>
#include <string.h>
#include "board.h"
#include "lfs.h"
#include "hpm_flash.h"
#include "fs.h"

#define READ_SIZE 32
#define STORAGE_SECTOR 40
#define FLASH_ADDR(b, o) (nor_config.flash_size - nor_config.sector_size * STORAGE_SECTOR + nor_config.base_addr + (b) * nor_config.sector_size + (o))
#define LOOKAHEAD_SIZE 512

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
  // int err = 1;
  int err = fs_mount(&config);

  // reformat if we can't mount the filesystem
  // this should only happen on the first boot
  if (err)
  {
    printf("Mount Failed, formatting\n");
    err = fs_format(&config);
    printf("Formatting %02X\n", err);
    err = fs_mount(&config);
    printf("Remount %02X\n", err);
  }

  return;
}
