#include "stdlib.h"

/// For now lets assume that there are no races :)

// ==== Static variables ====
int CAN_FUZZ_NOW = 0xeeeeeeed;
int IS_INIT = 0xdddddddd;
int* REGION_FOR_WRITES = 0xcccccccc;
// ====++++++++++++++++++====

// === Patch for instructions ===
#define PATCHED_INSN() do { \
	asm volatile ("movs r2, #0xb\n" \
		      "movs r0, #0x2\n" \
			: \
			: \
			: "r0", "r2"); \
} while(0)
// ===++++++++++++++++++++++++===

// ==============================================
// --------------------- NOTE: ------------------
//  - This shellcode starts at: {0x00e00ec4}
//  - This is called from: {0x00a0f33e}
//  - The call site is {THUMB} => This is THUMB!
//  - The call site executes:
//    	movs       r2,#0xb
//      movs       r0,#0x2
// ==============================================

// === SHELLCODE ===
__attribute__((section(".text.prologue")))
__attribute__((naked))
void _start () {
    store_context_and_lr();
    make_space_stack();

    // malloc_t mallocfn = (malloc_t)(void*)malloc_addr;
    spipe_open_t openfn = (spipe_open_t)(void*)SPIPE_OPEN_ADDR;
    spipe_write_t writefn = (spipe_write_t)(void*)SPIPE_WRITE_ADDR;
    
    // For now we just set the IS_INIT flag and get a region via malloc
    IS_INIT = 1;
    openfn(9);
    writefn(9, "INIT", 4, 0);
    // REGION_FOR_WRITES = mallocfn(1024, "", 0);

    // Make sure we can actually request some data
    // Otherwise we signal that we died.
    if(!REGION_FOR_WRITES){
	    die();
    }

    restore_space_stack();
    restore_context_no_lr();

    // Do the actual instruction that we patched out
    PATCHED_INSN();

    // Jump back to where we came from (continue)
    ret();
}
// ===+++++++++++===

