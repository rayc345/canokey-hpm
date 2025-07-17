// SPDX-License-Identifier: Apache-2.0
#include <applets.h>
#include <ctap.h>

void applets_install(void) {
  // openpgp_install(0);
  // piv_install(0);
  // oath_install(0);
  ctap_install(0);
  // admin_install(0);
  // ndef_install(0);
  // pass_install(0);
}

void applets_poweroff(void) {
  // piv_poweroff();
  // oath_poweroff();
  // admin_poweroff();
  // openpgp_poweroff();
  // ndef_poweroff();
}
