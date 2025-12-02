from keystone import KS_ARCH_ARM, KS_MODE_THUMB, Ks

#### GLOBALS ###
DEBUG = True
################

class ShellcodeTarget():
    def __init__(self, sc_addr, sc_bin):
        self._sc_addr = sc_addr
        self._sc_bin = sc_bin

    def inject_sc(self, target, debug: bool = False):
        '''
        Injects shellcode into target code for given idx.
        '''
        if debug:
            print(f"LEN of TARGET={len(target)}")
        for i in range(0, len(self._sc_bin)):
            target[self._sc_addr + i] = self._sc_bin[i]


    def fixup_sc(self, buf, idx, length):
        '''
        Overwrite parts of the shellcode w/ another buffer.
        '''
        for i in range(idx, idx+length):
            self._sc_bin[i] = buf[i - idx]


def ShellcodeSynth():
    def __init__(self, addr, mode, code, debug: bool = False):
        '''
        Creates ASM that does some action for a given code from
        a given addr in mode e {THUMB, ARM32}.

        Returns the bytes of the patch.
        '''

        ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
        encoding, _ = ks.asm(code, addr=addr)
        patch = bytes(encoding)
 
        if debug:
            print(f"Code (HEX)={patch.hex()} LEN={len(patch)}")

        return patch

#####################
#      SOURCES      #
#####################

modem = bytearray(open("ubi_modem.out", "rb").read())
init_sc = bytearray(open("init_shellcode.bin", "rb").read())
main_sc = bytearray(open("main_shellcode.bin", "rb").read())
tr_thumb_sc = bytearray(open("trampoline_shellcode.bin", "rb").read())
tr_arm32_sc = bytearray(open("trampoline_shellcode_arm32.bin", "rb").read())

#####################
#  INIT SHELLCODE   #
#####################

# Must overwrite nothing, since we just jump back and continue
init_sc_addr = 0x00e00dc4
init_sc_caller = 0x00a0f33e

init_sc_tgt = ShellcodeTarget(init_sc_addr, init_sc)
init_sc_tgt.inject_sc(modem, DEBUG)

#####################
#  MAIN SHELLCODE   #
#####################

# Must overwrite the vars to get the pointers to INIT right (TODO: later)
# NO caller must be overwritten because we just `ret`
main_sc_addr = 0x00e00851

# Fixup the code to get the constants right...
main_sc_tgt = ShellcodeTarget(main_sc_addr, main_sc)
# Fix up every address manually
main_sc_tgt.fixup_sc(b'\xde\xad\xbe\xef', 99, 4)
main_sc_tgt.fixup_sc(b'\xde\xad\xbe\xef', 99, 4)
main_sc_tgt.fixup_sc(b'\xde\xad\xbe\xef', 99, 4)
# Done...
main_sc_tgt.inject_sc(modem, DEBUG)

#####################
#  TRAMP SHELLCODE  #
#####################

# Must overwrite the main_shellcode pointer to get it right (exec it)
# once per target
tramp_arm32_addr = 0x00e00cd1 + ... # Imagine having x of them...
tramp_thumb_addr = 0x00e00ad1 + ... # Imagine haveing x of them... (multiple)
CONST_OFF_THUMB =  0x20 # TODO: check
CONST_OFF_ARM32 =  0x20 # TODO: check

# Must overwrite return insn since we jump to the actual call target
# only once since we should know what mode we come from
tramp_arm32_caller = ... # TODO: put something random here that we got from GHIDRA
tramp_thumb_caller = ... # TODO: put something THUMB here from GHIDRA

# There should only be one CODE necessary for bl
# since it is the same instruction for ARM32 and THUBM
# therefore... we just do one thing...
# and TODO: check it later with both modes and make sure that
# we actually have the same payload from both

dispatch_synth_patch = ShellcodeSynth(tramp_thumb_addr + ... + CONST_OFF,  KS_MODE_THUMB, CODE_THUMB, DEBUG)


# Now keystone them ...

# We need to put the main address here as well
# CAUTION: we need to do the ORR trick to get it right...
tramp_main_shellcode_caller = main_sc_addr

CODE_ARM32 = f"""
    blx     #{hex(tramp_main_shellcode_caller | 0x1)};
"""
CODE_THUMB = f"""
    bl     #{hex(tramp_main_shellcode_caller)};
"""

thumb_synth_patch = ShellcodeSynth(tramp_thumb_addr + ..., KS_MODE_THUMB, CODE_THUMB, DEBUG)
arm32_synth_patch = ShellcodeSynth(tramp_thumb_addr + ..., KS_MODE_ARM32, CODE_ARM32, DEBUG)


# Now keystone them ...

# patch_address = 0x00A0F342
# 00a0f312 calling FUN_0038b224

shellcode_addr = 0x00E00C70
new_target_address = 0x0038b224
new_patch_address = 0x00A0F312

CODE = f"""
    bl     #{hex(shellcode_addr)};
"""

# print_version_offset = 0x0095697A
ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
encoding, _ = ks.asm(CODE, addr=new_patch_address)
patch = bytes(encoding)
print("X:", patch.hex())
print("L:", len(patch))

#### 
CODEBACK = f"""
    b     #{hex(new_target_address)};
"""

ks2 = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
back_encoding, _ = ks2.asm(CODEBACK, addr=shellcode_addr+0x20)
back_code = bytes(back_encoding)
print(f"BACK: {back_code.hex()}")

assert len(patch) == 4

#sc = bytearray(sc)
#for i in range(0x20,0x24):
#    sc[i] = back_code[i - 0x20]

# Write it to the modem file .....

#####O

open("ubi_modem.out.mod", "wb").write(modem)
