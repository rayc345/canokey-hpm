Adapted from Canokey Canary firmware version 3.0.3

# Attention:
Current code does not use TRNG, posing a security risk as HPM5301 does not have one. Relavent code is commented on ```main.c```, you can turn it on for HPM6E00 or other series.
In the future, HMAC_DRBG would be used, using unique chip ID and user set salt to provide secure randon numbers.

## A little tweak is needed no matter what hardware you use:
Situation 1. If your HPM chip does not have its debug UART port connected just like my HPM5301evklite, please do these:
1. Remove the ```components/debug_console/hpm_debug_console.c``` file from Segger Embedded Studio IDE.
2. Comment out call to ```console_init``` in ```boards/hpm5301evklite/board.c```.

Situation 2. If your chip has UART connection to its debug port, please remove the ```sdk_ses_opt_lib_io_type(RTT)```  line in  ```CMakeLists.txt```.

# Ways to compile

1. Clone [SDK_ENV](https://github.com/hpmicro/sdk_env)
2. Set user environment HPM_SDK_BASE to the SDK path
3. Set user environment GNURISCV_TOOLCHAIN_PATH to the embedded GCC toolchain inside SDK
4. Clone this repo and open a terminal inside
5. ```
   mkdir build
   cd build
   cmake .. -DBOARD=hpm5301evklite -G Ninja -DCMAKE_BUILD_TYPE=flash_xip
   ```
