from keystone import KS_ARCH_ARM, KS_MODE_THUMB, Ks
import struct
from pwn import disasm

#### GLOBALS ###
DEBUG = True
################

class ShellcodeTarget():
    def __init__(self, sc_addr, sc_bin):
        self._sc_addr = sc_addr
        self._sc_bin = sc_bin

    def inject_sc(self, target, length = -1, debug: bool = False, arch: str = "thumb"):
        '''
        Injects shellcode into target code for given idx.
        '''
        write_len = len(self._sc_bin)
        if length != -1:
            write_len = length

        if debug:
            print(f"Replacing at {hex(self._sc_addr)}")
            print(f"Replacing in src: {target[self._sc_addr: self._sc_addr + write_len].hex()}\nDisassembly:\n{disasm(target[self._sc_addr: self._sc_addr + write_len], arch=arch)}")
            print(f"Replacing with: {self._sc_bin.hex()}\nDisassembly:\n{disasm(self._sc_bin, arch=arch)}")

        # We want to save the code to replace it later accordingly
        previous_code = target[self._sc_addr: self._sc_addr + write_len]

        for i in range(0, write_len):
            target[self._sc_addr + i] = self._sc_bin[i]

        return previous_code


    def fixup_sc(self, buf, idx, length, debug: bool = True, arch: str ="thumb"):
        '''
        Overwrite parts of the shellcode w/ another buffer.
        '''
        if debug:
            print(f"Fixup: src: {self._sc_bin[idx: idx + length]}\nDisassembly:\n{disasm(self._sc_bin[idx: idx + length], arch=arch)}")
            print(f"Fixup replace with: {buf}\nDisassembly:\n{disasm(buf, arch=arch)}")

        for i in range(idx, idx+length):
            self._sc_bin[i] = buf[i - idx]


class ShellcodeSynth():
    def __init__(self, addr, mode, code, debug: bool = False):
        '''
        Creates ASM that does some action for a given code from
        a given addr in mode e {THUMB, ARM32}.

        Returns the bytes of the patch.
        '''

        ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
        encoding, _ = ks.asm(code, addr=addr)
        self.patch = bytes(encoding)
 
        if debug:
            print(f"Code (HEX)={self.patch.hex()} LEN={len(self.patch)}")

    def get_patch(self):
        return self.patch

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

# We have to change the caller to jump to our address now
init_sc_caller = 0x00a0f30e

# We jump to the init_sc_addr
CODE_INIT = f'bl     #{hex(init_sc_addr | 0x1)};'
    
# INFO: We might want to patch all stuff in place... 
# (i.e. copy paste shellcode into our trampoline...)
init_sc_call_synth = ShellcodeSynth(init_sc_caller, KS_MODE_THUMB, CODE_INIT, DEBUG)
init_sc_call_patch = init_sc_call_synth.get_patch()

# We want to retain the previous code to inject it into our shellcode :)
init_sc_caller_tgt = ShellcodeTarget(init_sc_caller, init_sc_call_patch)
prev_code_init_sc_caller = init_sc_caller_tgt.inject_sc(modem, -1, DEBUG)

# Now inject the shellcode to our target address
# We discard the previous_code since we overwrite empty space
init_sc_tgt = ShellcodeTarget(init_sc_addr, init_sc)

offset_into_init_sc = init_sc.find(b'\x0b"\x02 ')
print(f"[!] Offset for init-shellcode: {hex(offset_into_init_sc)}")

init_sc_tgt.fixup_sc(prev_code_init_sc_caller, offset_into_init_sc, len(prev_code_init_sc_caller))

if(DEBUG):
    print(f"init_sc_addr={hex(init_sc_addr)}\n{init_sc_tgt._sc_bin.hex()}\n{disasm(init_sc_tgt._sc_bin, arch='thumb')}")

_ = init_sc_tgt.inject_sc(modem, -1, False)


#####################
#  MAIN SHELLCODE   #
#####################

if(DEBUG):
    print("Patching main shellcode now!")

# Must overwrite the vars to get the pointers to INIT right
# NO caller must be overwritten because we just `ret`
main_sc_addr = 0x00e00850

# Fixup the code to get the constants right...
main_sc_tgt = ShellcodeTarget(main_sc_addr, main_sc)

# Inject the main_sc_tgt shellcode that we changed
# We are not interested in the empty bytes...
_ = main_sc_tgt.inject_sc(modem, -1, DEBUG)

#####################
#  TRAMP SHELLCODE  #
#####################

if DEBUG:
    print("Patching trampoline shellcode now!")

# Must overwrite the main_shellcode pointer to get it right (exec it)
# once per target, they are offset by 16 bytes (c.f. below)
tramp_addr_base = 0x00e00cd0 # Imagine having x of them...

# We truncate after 16 bytes (c.f. below)
# THUMB:
# ------
# 00000000 <_start>:
#    0:   e92d 4fff       stmdb   sp!, {r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, sl, fp, lr}
#    4:   f7ff fffc       bl      0 <_start>
#    8:   e8bd 0fff       ldmia.w sp!, {r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, sl, fp}
#    c:   f1ff d7f8       bl      e00000 <spipe_open_addr+0xdfffe4>
# ARM32:
# ------
# 00000000 <_start>:
#    0:   e92d4fff        push    {r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, sl, fp, lr}
#    4:   ebfffffd        bl      0 <_start>
#    8:   e8bd0fff        pop     {r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, sl, fp}
#    c:   eb37fffb        bl      e00000 <spipe_open_addr+0xdfffe4>
len_sc_trunc = 16

# We need to adjust the branch to our main shellcode
MAIN_SHELLCODE_ADDR_OFF_THUMB =  0x04
MAIN_SHELLCODE_ADDR_OFF_ARM32 =  0x04

# We need to adjust the call target to go back to the actual 
TGT_ADDR_OFF_THUMB =  0x0c
TGT_ADDR_OFF_ARM32 =  0x0c

# Must overwrite return insn since we jump to the actual call target
# only once since we should know what mode we come from

# Format [call-site address; callee address]
tramp_arm32_to_thumb_pairs = [(0x00d09f14,0x00a0ec70)]
tramp_arm32_to_arm32_pairs = [] # Don't seem to exist? Need to scan with ghidrascript..
tramp_thumb_to_thumb_pairs = [(0x00a0f312,0x0038b224)]
tramp_thumb_to_arm32_pairs = [(0x00a1df44,0x007a8cb0)] # TODO: How do i check that it works?


# multiplier for our offsets
trampolie_inject_counter = 0

# We need to put the main address here as well
# WARN: we need to do the ORR trick in thumb to get it right...
tramp_main_shellcode_caller = main_sc_addr
CODE_ARM32 = f"""
    blx     #{hex(tramp_main_shellcode_caller | 0x1)};
"""
CODE_THUMB = f"""
    bl     #{hex(tramp_main_shellcode_caller)};
"""

# Thumb -[bl]-> Thumb pairs
# => Transformed to thumb -[bl]-> thumb shellcode tramp -[bl]-> thumb main shellcode -[ret]-> thumb shellcode tramp -[bl]-> Thumb callee
for call_site, callee in tramp_thumb_to_thumb_pairs:
    trampoline_address = tramp_addr_base + trampolie_inject_counter * len_sc_trunc
    # First: jump to our main shellcode....
    dispatch_synth = ShellcodeSynth(trampoline_address + MAIN_SHELLCODE_ADDR_OFF_THUMB, KS_MODE_THUMB, CODE_THUMB, DEBUG)
    main_shellcode_bl_patch = dispatch_synth.get_patch()

    # Second: jump to our actual callee...
    CODE_BL_TO_CALLEE_THUMB_TO_THUMB = f'''
        b #{hex(callee)}
    '''
    callee_synth = ShellcodeSynth(trampoline_address + TGT_ADDR_OFF_THUMB, KS_MODE_THUMB, CODE_BL_TO_CALLEE_THUMB_TO_THUMB, DEBUG)
    callee_bl_patch = callee_synth.get_patch()

    sc_tgt_trampoline = ShellcodeTarget(trampoline_address, tr_thumb_sc)

    # Fixup our shellcode with the rigth addresses
    sc_tgt_trampoline.fixup_sc(main_shellcode_bl_patch, MAIN_SHELLCODE_ADDR_OFF_THUMB, 4)
    sc_tgt_trampoline.fixup_sc(callee_bl_patch, TGT_ADDR_OFF_THUMB, 4)

    if(DEBUG):
        print(f"addr={hex(trampoline_address)}\nsc_tgt_trampoline={sc_tgt_trampoline._sc_bin[:16].hex()}\nTrampoline:\n{disasm(sc_tgt_trampoline._sc_bin[:16], arch='thumb')}")

    # Put it in the modem
    _ = sc_tgt_trampoline.inject_sc(modem, 16, False)

    # Finally: patch the actual address... to go to our shellcode trampoline
    CODE_BL_TO_SHELLCODE_TRAMPOLINE = f'bl     #{hex(trampoline_address)};'
        
    call_site_synth = ShellcodeSynth(call_site, KS_MODE_THUMB, CODE_BL_TO_SHELLCODE_TRAMPOLINE, DEBUG)
    call_site_patch = call_site_synth.get_patch()

    # Now that we have the shellcode, we have to inject it...
    # Discard the jump (we have to recompute anyways...)
    call_site_patch_tgt = ShellcodeTarget(call_site, call_site_patch)
    _ = call_site_patch_tgt .inject_sc(modem, 4, DEBUG)

    # One trampoline injected!
    trampolie_inject_counter += 1

# Thumb -[blx]-> arm32 pairs
# => Transformed to thumb -[bl]-> thumb shellcode tramp -[bl]-> thumb main shellcode -[ret]-> thumb shellcode tramp -[blx]-> ARM32 callee
# for call_site, callee in tramp_thumb_to_arm32_pairs:
#     pass

#
# ARM32 -[blx]-> Thumb pairs
# => Transformed to ARM32 -[blx]-> thumb shellcode tramp -[bl]-> thumb main shellcode -[ret]-> thumb shellcode tramp -[bl]-> Thumb callee
# for call_site, callee in tramp_arm32_to_thumb_pairs:
#     trampoline_address = tramp_addr_base + trampolie_inject_counter * len_sc_trunc
#     # First: jump to our main shellcode....
#     dispatch_synth = ShellcodeSynth(trampoline_address + MAIN_SHELLCODE_ADDR_OFF_ARM32, KS_MODE_ARM, CODE_ARM32, DEBUG)
#     main_shellcode_bl_patch = dispatch_synth.get_patch()
#
#     # Second: jump to our actual callee...
#     CODE_B_TO_CALLEE_ARM32_TO_THUMB = f'''
#         b #{hex(callee)}
#     '''
#     callee_synth = ShellcodeSynth(trampoline_address + TGT_ADDR_OFF_ARM32, KS_MODE_THUMB, CODE_BL_TO_CALLEE_THUMB_TO_THUMB, DEBUG)
#     callee_bl_patch = callee_synth.get_patch()
#
#     sc_tgt_trampoline = ShellcodeTarget(trampoline_address, tr_thumb_sc)
#
#     # Fixup our shellcode with the rigth addresses
#     sc_tgt_trampoline.fixup_sc(main_shellcode_bl_patch, MAIN_SHELLCODE_ADDR_OFF_THUMB, 4)
#     sc_tgt_trampoline.fixup_sc(callee_bl_patch, TGT_ADDR_OFF_THUMB, 4)
#
#     if(DEBUG):
#         print(f"addr={hex(trampoline_address)}\nsc_tgt_trampoline={sc_tgt_trampoline._sc_bin[:16].hex()}\nTrampoline:\n{disasm(sc_tgt_trampoline._sc_bin[:16], arch='thumb')}")
#
#     # Put it in the modem
#     _ = sc_tgt_trampoline.inject_sc(modem, 16, False)
#
#     # Finally: patch the actual address... to go to our shellcode trampoline
#     CODE_BL_TO_SHELLCODE_TRAMPOLINE = f'bl     #{hex(trampoline_address)};'
#         
#     call_site_synth = ShellcodeSynth(call_site, KS_MODE_THUMB, CODE_BL_TO_SHELLCODE_TRAMPOLINE, DEBUG)
#     call_site_patch = call_site_synth.get_patch()
#
#     # Now that we have the shellcode, we have to inject it...
#     # Discard the jump (we have to recompute anyways...)
#     call_site_patch_tgt = ShellcodeTarget(call_site, call_site_patch)
#     _ = call_site_patch_tgt .inject_sc(modem, 4, DEBUG)
#
#     # One trampoline injected!
#     trampolie_inject_counter += 1
# #

# # ARM32 -[bl]-> ARM32 pairs
# # => Transformed to ARM -[blx]-> thumb shellcode tramp -[bl]-> thumb main shellcode -[ret]-> thumb shellcode tramp -[blx]-> ARM32 callee
# for call_site, callee in tramp_thumb_to_arm32_pairs:
#     pass

# Write it out...

open("ubi_modem.out.mod", "wb").write(modem)
