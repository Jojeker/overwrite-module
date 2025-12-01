obj-m += overwrite.o
# ccflags-y += -Wno-missing-attributes
# ccflags-y += ""

# Let caller set KDIR; fall back to running kernel's build dir
PWD  := $(shell pwd)
ARCH := arm64
CROSS_COMPILE := aarch64-linux-gnu-
LD := $(CROSS_COMPILE)ld.bfd
# KCFLAGS := "-mbranch-protection=none"
KCFLAGS := ""
MK := make

KVER := 4.14.98
KURL := https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-$(KVER).tar.xz
KDIR := $(CURDIR)/linux-$(KVER)
TARBALL := /tmp/linux-$(KVER).tar.xz

IMG_NAME := kernel_mod_builder

$(TARBALL):
	wget -O $(TARBALL) $(KURL)

$(KDIR): $(TARBALL)
	tar -xf $(TARBALL)

.PHONY: prepare
prepare: $(KDIR)
	cd $(KDIR) && \
	cp $(CURDIR)/kernel_config.txt .config && \
	$(MAKE) ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- oldconfig && \
	$(MAKE) ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- modules_prepare


all: prepare
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) LD=$(LD) KCFLAGS=$(KCFLAGS) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

docker:
	docker build -t $(IMG_NAME) .

get-module:
	CONTAINER_ID=$$(docker create $(IMG_NAME)); \
	docker start $$CONTAINER_ID; \
	docker cp $$CONTAINER_ID:/src/overwrite.ko ./overwrite.ko; \
	docker rm -f $$CONTAINER_ID
