#include "fuzzing.h"
#include "stdlib.h"

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

// ---- main shellcode ---
// NOTE: we cannot call any functions here, as we otherwise get
// recursive trampolines... (Reimplement or cov. denylist)
__attribute__((section(".text.prologue")))
__attribute__((naked))
void _start () {
    save_lr();
    make_space_stack();

    // LR is taken from the stack..
    int lr_addr = 0;

    // CTX population from static section..
    cov_ctx_t ctx = {
	.hdr = (cov_hdr_t*)COV_HDR_ADDR,
	.map = (char*)COV_MAP_ADDR
    };
  
    // We have to actively ack the use of our map
    if (!is_cov_ready(&ctx)){
	goto poor_mans_return;
    }
 
    // Get the actual LR address...
    PATCHED_INSN(lr_addr);
    cov_hit(&ctx, lr_addr);

poor_mans_return:
    restore_space_stack();
    ret();
}


