# musl is quite nice with -static if needed
#CC=musl-gcc
TARGET=shellcode
SRCS=shellcode.c

all: $(TARGET).bin


shellcode.bin: stdlib.h shellcode.c
	arm-none-eabi-gcc -mthumb -march=armv8-a+thumb -march=armv8-a -Os -Wall -static -nostdlib -fno-asynchronous-unwind-tables -fpic -c -o shellcode.o shellcode.c
	arm-none-eabi-gcc -static -nostdlib -fno-asynchronous-unwind-tables -fpic shellcode.o -Wl,-Tscript.T,--build-id=none -o shellcode.elf
	arm-none-eabi-objcopy -O binary $(TARGET).elf $(TARGET).bin

clean: 
	rm -f $(TARGET).elf $(TARGET).bin $(TARGET).o $(TARGET)
