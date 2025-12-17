#include "stdlib.h"
#include "fuzzing.h"
#include "inject.h"

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

void test_call_ccch(const char *payload, short payload_len)
{
    // Get malloc and harness on board
    malloc_t mallocfn = (malloc_t)(void*)MALLOC_ADDR;
    NRRC_RECEIVE_PAYL_t nrrc_receive_payl = (NRRC_RECEIVE_PAYL_t)(void*)NRRC_RECEIVE_PAYL_ADDR;

    // Malloc our stuff
    user_data *ud = (user_data *)mallocfn(sizeof(*ud), "", 0);
    nrrc_msg  *m  = (nrrc_msg  *)mallocfn(sizeof(*m), "", 0);

    ud->refcnt = 1;		    // Valid for parsing..
    ud->from_src_layer = 3;	    // DL-CCCH decode path
    ud->srb_id = 0;		    // not used in this path
    ud->peer_container = 0;	    // safe for CCCH path (NULL)

    ud->buf = (char *)mallocfn(payload_len, "", 0);
    omemcpy(ud->buf, payload, payload_len);
    ud->length = (short)payload_len;

    // Set payload user data
    m->user_data = ud;
    
    nrrc_receive_payl(m);

    // TODO: free the stuff (but their lib is weird...)
}

// XXX: this will be the fuzzing harness!
void do_stuff () {
    char* sib1 = "sdlfksdjl";
    test_call_ccch(sib1, 10);
}


#define OFFSET_START_CODE 0xE3A20C
// HACK: just put it at offset 200 and update 
// because we cannot get linking to work that easily
#define OFFSET_INTO_CODE 0x260

// Inject a task into Threadx
__attribute__((naked))
void init_task() {
	// PROLOGUE
	store_context_and_lr();
	make_space_stack();

	spipe_write_t writefn = (spipe_write_t)(void*)SPIPE_WRITE_ADDR;
	spawn_threadx_thread spawn = (spawn_threadx_thread)(void*)(0x8f829fe6 | 1);

	char *tname = "HEX_TASK";
	char *qname = "HEX_Q";

	writefn(9, "TASK TO INJECT=", 18, 0);
	writefn(9, tname, 8, 0);
	writefn(9, "QUEUE=", 6, 0);
	writefn(9, qname, 5, 0);

  
	// Need to hardcode it since we dont know where we are injected
	// It will be do_stuff (0x9065A20C)
	void* CUST_TASK = (void*)(REBASE + OFFSET_START_CODE + OFFSET_INTO_CODE);


	// Some args...
	int stack_size      = 0x800; 
	int extra_words    = 0;
	// int priority_or_id = 0xCA;
	int preempt_thr    = 1;
	int  time_slice     = 1;
	int  auto_start     = 1;

	//int idx = 0x1337;
	int idx = spawn(
	    tname,
	    qname,
	    CUST_TASK,
	    0,
	    0, //????
	    stack_size,
	    extra_words,
	    preempt_thr,
	    time_slice,
	    auto_start
	);

	writefn(9, "THREAD START:\n", 15, 0);
	writefn(9, (char*)&idx,4, 0);
	writefn(9, "THREAD OK!", 11, 0);

	// EPILOGUE
	restore_space_stack();
	restore_context_no_lr();
	ret();
}

__attribute__((section(".text.task_entry"), used))
void task_entry_fn(){
    spipe_open_t openfn = (spipe_open_t)(void*)SPIPE_OPEN_ADDR;
    spipe_write_t writefn = (spipe_write_t)(void*)SPIPE_WRITE_ADDR;

    int counter = 0;
    openfn(9);

    do {
	// Our task so far...
	writefn(9, "COUNTER TASK:\n", 15, 0);
	writefn(9, (char*)&counter,4, 0);
	counter++;
    }while(1);
}

// === SHELLCODE ===
__attribute__((section(".text.prologue")))
__attribute__((naked))
void _start () {
    store_context_and_lr();
    make_space_stack();

    // malloc_t mallocfn = (malloc_t)(void*)MALLOC_ADDR;
    spipe_open_t openfn = (spipe_open_t)(void*)SPIPE_OPEN_ADDR;
    spipe_write_t writefn = (spipe_write_t)(void*)SPIPE_WRITE_ADDR;
    
    // For now we just set the IS_INIT flag
    int* IS_INIT = (int*)IS_INIT_ADDR;
    *IS_INIT = 0x13371337;

    // CTX population from static section..
    cov_ctx_t ctx = {
	.hdr = (cov_hdr_t*)COV_HDR_ADDR,
	.map = (char*)COV_MAP_ADDR
    };
    // Setup the coverage map
    cov_init(&ctx, (void*)COV_HDR_ADDR, COV_MAP_SIZE);
  
    openfn(9);
    writefn(9, "INIT OK\n", 8, 0);
    writefn(9, "COV MAP\n", 8, 0);
    writefn(9, (char*)COV_HDR_ADDR, 64, 0);

    
    // WARN: inject our own task now!
    init_task();
    
    writefn(9, "INIT TASK OK\n", 14, 0);

    restore_space_stack();
    restore_context_no_lr();

    // Do the actual instruction that we patched out
    PATCHED_INSN();

    // Jump back to where we came from (continue)
    ret();
}
// ===+++++++++++===

