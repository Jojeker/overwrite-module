# Overwrite Module

THis is a 4.14.98 kernel module.

```bash

# Wget the source
wget https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.14.98.tar.xz
# Build in the directory
cd linux-4.14.98
# Copy the kernel_config.txt to .config
cp ../module-overwrite/kernel_config.txt .config
# build
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- oldconfig
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- modules_prepare

# Now here build the module
make
```
## Command to overwrite the byte that is responsible for checking the signature

```bash
# Bypass OK
insmod o.ko pattern=fd7bbda90210c0d2

# This is some output when running the module
# Jul  5 11:15:29.195 udx710-module user.alert kernel: [  988.347776] c0 swapper pgtable: 4k pages, 39-bit VAs, pgd = ffffff8008dc4000
# Jul  5 11:15:29.211 udx710-module user.alert kernel: [  988.354770] c0 [ffffff8009205000] *pgd=000000009fffe803, *pud=000000009fffe803, *pmd=000000009e3c6003, *pte=3
```
