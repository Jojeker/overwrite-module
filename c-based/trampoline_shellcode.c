#include "stdlib.h"

// ==============================================
// --------------------- NOTE: ------------------
//  - This shellcode starts at: {0x00e00cd1}
//  - This is called from: {BL AND BLX instructions}
//  - The call site is {ARM OR THUMB} 
//  	=> This is COMPILED FOR ARM OR THUMB!
//  - The call site executes:
//    	bl       24-bit-value (THUMB)
//      blx      24-bit-value (ARM32)
// ==============================================

// === Patch for instructions ===
// >> This will be replaced by keystone to be relative <<
#define CALL_TO_MAIN_SHELLCODE_INSN() do { \
	asm volatile ("bl 0x000000\n" \
			: \
			: \
			:); \
} while(0)

#define ACTUAL_CALL_TARGET_INSN() do { \
	asm volatile ("bl 0xe00001\n" \
			: \
			: \
			:); \
} while(0)
// ===++++++++++++++++++++++++===

// Trampoline for both arm and thumb
// === SHELLCODE ===
__attribute__((section(".text.prologue")))
__attribute__((naked))
void _start () {
    store_context_and_lr();

    // We want to branch away to our shellcode
    // (replaced by keystone)
    CALL_TO_MAIN_SHELLCODE_INSN();

    // TODO: MUST BE WITH LR?
    restore_context_no_lr();

    // Now we are done, so we can branch to the
    // actual call target (replaced by keystone)
    ACTUAL_CALL_TARGET_INSN();
}
// ===+++++++++++===


