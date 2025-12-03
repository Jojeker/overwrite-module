#include "stdlib.h"

// === Static variables pointers ===
int* CAN_FUZZ_NOW_PTR = 0x11111111;
int* IS_INIT = 0x22222222;
int** REGION_FOR_WRITES = 0x33333333;
// ===+++++++++++++++++++++++++++===

// === Patch for getting LR ===
// we increase SP by 0x100 so we have to
// add 0x100 + 4 for the LR as the last one
#define PATCHED_INSN(val_out) do { \
	asm volatile( \
	    "ldr %0, [sp, #0x104]" \
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

    // TODO: function prologue
    // ???
    make_space_stack();

    // If we are not init, just return early and don't log anything
    // CAUTION: must be populated by the keystone component s.t. we
    // can actually use them and do not crash right away.
    if (! *IS_INIT){
	return;
    }

    // Define fns for outward communication
    spipe_open_t sofn = (spipe_open_t)(void*)SPIPE_OPEN_ADDR;
    spipe_write_t swfn = (spipe_write_t)(void*)SPIPE_WRITE_ADDR;
    int lr_addr = 0;
   
    // TODO: figure out where lr is and read it from the stack (right offset)
    PATCHED_INSN(lr_addr);
  
    // Write the stuff into our buffer (TODO)
    
    // Write the address verbatim out
    sofn(9);
    swfn(9, (char*)lr_addr, 4, 0);

    restore_space_stack();
    // TODO: function epilogue (restore lr)
    ret();
}


