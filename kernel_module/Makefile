obj-m += overwrite.o
ccflags-y += -Wno-missing-attributes

# Let caller set KDIR; fall back to running kernel's build dir
KDIR ?= ../linux-4.14.98
PWD  := $(shell pwd)
ARCH := arm64
CROSS_COMPILE := aarch64-linux-gnu-
LD := $(CROSS_COMPILE)ld.bfd
KCFLAGS := "-mbranch-protection=none"

all:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) LD=$(LD) KCFLAGS=$(KCFLAGS) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
