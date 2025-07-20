// SPDX-License-Identifier: Apache-2.0
#include <admin.h>
#include <applets.h>
#include <ctap.h>
#include <ndef.h>
#include <oath.h>
#include <openpgp.h>
#include <pass.h>
#include <piv.h>

int applets_install(const uint8_t reset)
{
  if (openpgp_install(reset) < 0)
    return -1;
  if (piv_install(reset))
    return -1;
  if (oath_install(reset))
    return -1;
  if (ctap_install(reset))
    return -1;
  if (admin_install(reset))
    return -1;
  if (ndef_install(reset))
    return -1;
  if (pass_install(reset))
    return -1;
  return 0;
}

void applets_poweroff(void)
{
  piv_poweroff();
  oath_poweroff();
  admin_poweroff();
  openpgp_poweroff();
  ndef_poweroff();
}
