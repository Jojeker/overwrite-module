#include "stdlib.h"

// === Static variables pointers ===
#define STATIC_BASE 0x91D409E4 
#define CAN_FUZZ_NOW_ADDR (0xa04 + STATIC_BASE)
#define IS_INIT_ADDR (0xa00 + STATIC_BASE)
#define REGION_FOR_WRITES_ADDR (0xa08 + STATIC_BASE)
// ===+++++++++++++++++++++++++++===

// === Patch for getting LR ===
// we increase SP by 0x100 so we have to
// add 100 (our stack frame) + 12*4 for the other registers (r0 - r11)
#define PATCHED_INSN(val_out) do { \
	asm volatile( \
	    "ldr %0, [sp, #152]" \
	    : "=r" (val_out) \
	    : \
	    : "memory" \
	); \
} while (0)
// ===++++++++++++++++++++++++===

// ==============================================
// --------------------- NOTE: ------------------
//  - This shellcode starts at: {0x00e00851}
//  - This is called from: {OUR TRAMPOLINES (switching to THUMB)}
//  - The call site is {ARM OR THUMB} 
//  	=> We end up in THUMB with the right call site change!
//  	=> CAUTION: we need to respect the change to get back to the right m???
//  - The call site executes:
//      blx      24-bit-value (ARM32 TRAMPOLINE)
//      bl       24-bit-value (THUMB TRAMPLOINE)
// ==============================================

// main shellcode 
__attribute__((section(".text.prologue")))
__attribute__((naked))
void _start () {
    save_lr();
    make_space_stack();

    // Define fns for outward communication
    spipe_open_t sofn = (spipe_open_t)(void*)SPIPE_OPEN_ADDR;
    spipe_write_t swfn = (spipe_write_t)(void*)SPIPE_WRITE_ADDR;
    int lr_addr = 0;
    sofn(9);

    // If we are not init, just return early and don't log anything
    // CAUTION: must be populated by the keystone component s.t. we
    // can actually use them and do not crash right away.
    if (! (*(int*)IS_INIT_ADDR == 0x13371337)){
	swfn(9, "UNINIT", 6, 0);
    } else {

	// TODO: figure out where lr is and read it from the stack (right offset)
	PATCHED_INSN(lr_addr);
      
	// Write the stuff into our buffer (TODO)
	
	// Write the address verbatim out
	// swfn(9, (char*)lr_addr, 4, 0);
	swfn(9, "OUT:", 4, 0);
	// We give the address of lr_address since the function
	// dereferences the ptr and prints whatever is stored in
	// the variable (and beyond ;*)
	swfn(9, (char*)&lr_addr, 4, 0);
    }

    restore_space_stack();
    ret();
}


