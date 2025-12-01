modem = bytearray(open("ubi_modem.out", "rb").read())

sc = open("shellcode.bin", "rb").read()

# rebase: 0x8F81FE00

# TARGET_HOLE: 9047f304 at runtime
# TARGET_HOLE: 00c5f504 in image
shellcode_addr = 0x00E00C70
for i in range(0, len(sc)):
    modem[shellcode_addr + i] = sc[i]


from keystone import KS_ARCH_ARM, KS_MODE_THUMB, Ks

# 905ac2b8 - string
# 8ffd77a2 - printk
# 8ffc9434
# my string 90600308
# CODE = """
#     movw    r1, #0x0308
#     movt    r1, #0x9060
# 905aba98
# """
# CODE = """
#     nop
#     movw    r0, #0xba98
#     movt    r0, #0x905a
#     movw    r3, #0x9434
#     movt    r3, #0x8FFC
#     orr     r3, r3, #1
#     blx     r3;
#     nop
#     nop
#     nop
#     nop
#     nop
#     nop
#     nop
#     nop
#     nop
#     nop
#     nop
#     nop
#     nop
#     nop
#     nop
# """

patch_address = 0x00A0F342
# patch_address = 0x00A0F324
# call_address = 0x00A0F32C
# offset = shellcode_addr - call_address
# jump to end: 0x90620A70

CODE = f"""
    bl     #{hex(shellcode_addr)};
"""


# CODE = f"""
#     bl     #{hex(shellcode_addr)};
#     nop
#     nop
#     nop
#     nop
#     nop
#     nop
#     nop
#     nop
#     nop
#     nop
#     nop
# """

print(CODE)
# CODE = """
#     nop
#     movw    r0, #0xbeef
#     movt    r0, #0xdead
#     movw    r3, #0xf304
#     movt    r3, #0x9047
#     orr     r3, r3, #1
#     blx     r3;
#     nop
#     nop
#     nop
#     nop
#     nop
#     nop
#     nop
#     nop
#     nop
#     nop
#     nop
#     nop
#     nop
#     nop
#     nop
# """

# orr     r3, r3, #1

# print_version_offset = 0x0095697A
ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
encoding, _ = ks.asm(CODE, addr=patch_address)
patch = bytes(encoding)
print("X:", patch.hex())
print("L:", len(patch))

assert len(patch) == 4

# #######################################
#
# # OK -- we got the address
# CODE = """
#     mov r4, pc;
#     mov r3, pc;
#     mov r2, pc;
# """
#
# ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
# encoding, _ = ks.asm(CODE, addr=print_version_offset)
# stuff_patch = bytes(encoding)
# print(stuff_patch.hex())
#
# stuff_offset = 0x0000E370
#
# for i in range(0, len(stuff_patch)):
#     modem[stuff_offset + i] = stuff_patch[i]
#
# #######################################
#
#
# ################################################
#
# # Sanity check: we can actually patch
# string_version = 0x00956B18
# string_patch = "THIS IS CUSTOM".encode("ascii")
#
# for i in range(0, len(string_patch)):
#     modem[string_version + i] = string_patch[i]
#
# ################################################


for i in range(0, len(patch)):
    modem[patch_address + i] = patch[i]

open("ubi_modem.out.mod", "wb").write(modem)
