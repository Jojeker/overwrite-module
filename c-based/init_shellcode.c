#include "stdlib.h"

/// For now lets assume that there are no races :)

// ==== Static variables ====
// Make them non-zero to force the compiler to not put them in .bss and discard it...
#define STATIC_BASE 0x91D409E4 
#define CAN_FUZZ_NOW_ADDR (0xa04 + STATIC_BASE)
#define IS_INIT_ADDR (0xa00 + STATIC_BASE)
#define REGION_FOR_WRITES_ADDR (0xa08 + STATIC_BASE)
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

    malloc_t mallocfn = (malloc_t)(void*)MALLOC_ADDR;
    spipe_open_t openfn = (spipe_open_t)(void*)SPIPE_OPEN_ADDR;
    spipe_write_t writefn = (spipe_write_t)(void*)SPIPE_WRITE_ADDR;
    
    // For now we just set the IS_INIT flag and get a region via malloc
    int* IS_INIT = (int*)IS_INIT_ADDR;
    *IS_INIT = 0x13371337;

    openfn(9);
    writefn(9, "INIT", 4, 0);

    // We use a fixed address for our buffers
    void **REGION_FOR_WRITES = (void**)REGION_FOR_WRITES_ADDR;
    *REGION_FOR_WRITES = 0x0;
    *REGION_FOR_WRITES = mallocfn(1024, "", 0);

    writefn(9, "REGION:", 7, 0);
    writefn(9, (char*)REGION_FOR_WRITES, 4, 0);
  
    // Make sure we can actually request some data
    // Otherwise we signal that we died.
    // if(! *REGION_FOR_WRITES){
	   //  die();
    // }

    restore_space_stack();
    restore_context_no_lr();

    // Do the actual instruction that we patched out
    PATCHED_INSN();

    // Jump back to where we came from (continue)
    ret();
}
// ===+++++++++++===

