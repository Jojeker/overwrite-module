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
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- modules_prepare

# Now here build the module
make
```
