# musl is quite nice with -static if needed
#CC=musl-gcc

MAIN_TARGET := main_shellcode
MAIN_SRCS := $(MAIN_TARGET).c
MAIN_OBJS := $(MAIN_TARGET).o

INIT_TARGET := init_shellcode
INIT_SRCS := $(INIT_TARGET).c
INIT_OBJS := $(INIT_TARGET).o

TRAMPOLINE_TARGET := trampoline_shellcode
TRAMPOLINE_SRCS := $(TRAMPOLINE_TARGET).c
TRAMPOLINE_OBJS := $(TRAMPOLINE_TARGET).o

TRAMPOLINE_ARM_TARGET := trampoline_shellcode_arm32
TRAMPOLINE_ARM_SRCS := $(TRAMPOLINE_ARM_TARGET).c
TRAMPOLINE_ARM_OBJS := $(TRAMPOLINE_ARM_TARGET).o

upload: patch
	adb push ubi_modem.out.mod /tmp/ubi_modem.out.mod

patch: all
	. ~/.venv/bin/activate && \
	python patch.py

all: $(MAIN_TARGET).bin $(INIT_TARGET).bin $(TRAMPOLINE_TARGET).bin $(TRAMPOLINE_ARM_TARGET).bin


$(MAIN_TARGET).bin: stdlib.h $(MAIN_SRCS)
	arm-none-eabi-gcc -mthumb -march=armv8-a+thumb -march=armv8-a -Os -Wall -static -nostdlib -fno-asynchronous-unwind-tables -fpic -c -o $(MAIN_OBJS) $(MAIN_SRCS)
	arm-none-eabi-gcc -static -nostdlib -fno-asynchronous-unwind-tables -fpic $(MAIN_OBJS) -Wl,-Tscript.T,--build-id=none -o $(MAIN_TARGET).elf
	arm-none-eabi-objcopy -O binary $(MAIN_TARGET).elf $(MAIN_TARGET).bin

$(INIT_TARGET).bin: stdlib.h $(INIT_SRCS)
	arm-none-eabi-gcc -mthumb -march=armv8-a+thumb -march=armv8-a -Os -Wall -static -nostdlib -fno-asynchronous-unwind-tables -fpic -c -o $(INIT_OBJS) $(INIT_SRCS)
	arm-none-eabi-gcc -static -nostdlib -fno-asynchronous-unwind-tables -fpic $(INIT_OBJS) -Wl,-Tscript.T,--build-id=none -o $(INIT_TARGET).elf
	arm-none-eabi-objcopy -O binary $(INIT_TARGET).elf $(INIT_TARGET).bin

$(TRAMPOLINE_TARGET).bin: stdlib.h $(TRAMPOLINE_SRCS)
	arm-none-eabi-gcc -mthumb -march=armv8-a+thumb -march=armv8-a -Os -Wall -static -nostdlib -fno-asynchronous-unwind-tables -fpic -c -o $(TRAMPOLINE_OBJS) $(TRAMPOLINE_SRCS)
	arm-none-eabi-gcc -static -nostdlib -fno-asynchronous-unwind-tables -fpic $(TRAMPOLINE_OBJS) -Wl,-Tscript.T,--build-id=none -o $(TRAMPOLINE_TARGET).elf
	arm-none-eabi-objcopy -O binary $(TRAMPOLINE_TARGET).elf $(TRAMPOLINE_TARGET).bin

$(TRAMPOLINE_ARM_TARGET).bin: stdlib.h $(TRAMPOLINE_SRCS)
	arm-none-eabi-gcc -march=armv8-a -march=armv8-a -Os -Wall -static -nostdlib -fno-asynchronous-unwind-tables -fpic -c -o $(TRAMPOLINE_ARM_OBJS) $(TRAMPOLINE_SRCS)
	arm-none-eabi-gcc -static -nostdlib -fno-asynchronous-unwind-tables -fpic $(TRAMPOLINE_ARM_OBJS) -Wl,-Tscript.T,--build-id=none -o $(TRAMPOLINE_ARM_TARGET).elf
	arm-none-eabi-objcopy -O binary $(TRAMPOLINE_ARM_TARGET).elf $(TRAMPOLINE_ARM_TARGET).bin
clean: 
	rm -f $(MAIN_TARGET).elf $(MAIN_TARGET).bin $(MAIN_TARGET).o $(MAIN_TARGET)
	rm -f $(INIT_TARGET).elf $(INIT_TARGET).bin $(INIT_TARGET).o $(INIT_TARGET)
	rm -f $(TRAMPOLINE_TARGET).elf $(TRAMPOLINE_TARGET).bin $(TRAMPOLINE_TARGET).o $(TRAMPOLINE_TARGET)
