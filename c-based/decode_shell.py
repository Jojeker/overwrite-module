import sys

from capstone import *

CODE = sys.stdin.buffer.read()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)  # use THUMB; change if needed
for i in md.disasm(CODE, 0xA3A182):
    print(f"0x{i.address:08x}:\t{i.mnemonic}\t{i.op_str}")
