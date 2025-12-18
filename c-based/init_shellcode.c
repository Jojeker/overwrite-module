#include "stdlib.h"
#include "fuzzing.h"
#include "inject.h"

/// For now lets assume that there are no races :)

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
//      movs       r2,#0xb
//      movs       r0,#0x2
// ==============================================

void test_call_bcch(const char *payload, short payload_len){
    // Get malloc and harness on board
    malloc_t mallocfn = (malloc_t)(void*)MALLOC_ADDR;
    BCCH_parse bcchp = (BCCH_parse)(void*)(NRRC_RECEIVE_BCCH_BCH_DATA);
    spipe_write_t writefn = (spipe_write_t)(void*)SPIPE_WRITE_ADDR;

    user_data *ud = (user_data *)mallocfn(sizeof(*ud), "", 0);
    nrrc_msg  *m  = (nrrc_msg  *)mallocfn(sizeof(*m), "", 0);

    ud->refcnt = 1;
    ud->from_src_layer = 3;
    ud->srb_id = 0;
    ud->peer_container = 0;

    ud->buf = (char *)mallocfn(payload_len, "", 0);
    memcpy(ud->buf, payload, payload_len);
    ud->length = (short)payload_len;

    // Set payload user data
    m->user_data = ud;

    writefn(9, "[BCCH] CALLING...\n", 18, 0);
    bcchp(m);
    writefn(9, "[BCCH] CALL OK!!!\n", 18, 0);
}

void test_call_dcch(const char *payload, short payload_len){
    // Get malloc and harness on board
    malloc_t mallocfn = (malloc_t)(void*)MALLOC_ADDR;
    DCCH_parse dcchp = (DCCH_parse)(void*)(NRRC_RECEIVE_BCCH_BCH_DATA);
    spipe_write_t writefn = (spipe_write_t)(void*)SPIPE_WRITE_ADDR;
    void* out = 0;

    // Create a heap ref
    char* payl_alloc = (char *)mallocfn(payload_len, "", 0);
    memcpy(payl_alloc, payload, payload_len);

    // Off we go
    writefn(9, "[DCCH] CALLING...\n", 18, 0);
    dcchp((char*)payload, payload_len, out);
    writefn(9, "[DCCH] CALL OK!!!\n", 18, 0);

    return;
}

void test_call_ccch(const char *payload, short payload_len)
{
    // Get malloc and harness on board
    malloc_t mallocfn = (malloc_t)(void*)MALLOC_ADDR;
    CCCH_parse nrrc_receive_payl = (CCCH_parse)(void*)(NRRC_RECEIVE_PAYL_ADDR);
    spipe_write_t writefn = (spipe_write_t)(void*)SPIPE_WRITE_ADDR;

    // Malloc our stuff
    user_data *ud = (user_data *)mallocfn(sizeof(*ud), "", 0);
    nrrc_msg  *m  = (nrrc_msg  *)mallocfn(sizeof(*m), "", 0);

    // Set the fields
    ud->refcnt = 1;                 // Valid for parsing..
    ud->from_src_layer = 3;         // DL-CCCH decode path (TODO: 3)
    ud->srb_id = 0;                 // not used in this path
    ud->peer_container = 0;         // safe for CCCH path (NULL)

    ud->buf = (char *)mallocfn(payload_len, "", 0);

    // copy the buffer inside
    memcpy(ud->buf, payload, payload_len);
    ud->length = (short)payload_len;

    // Set payload user data
    m->user_data = ud;
    
    //wrong stack alignment (AAPCS expects 8-byte alignment at public interfaces) ?? 
    writefn(9, "[CCCH] CALLING...\n", 18, 0);
    nrrc_receive_payl(m);
    writefn(9, "[CCCH] CALL OK!!!\n", 18, 0);

    return;
}


#define OFFSET_START_CODE 0xE3A20C
__attribute__((visibility("hidden")))
extern const int __task_entry_off;

// Inject a task into Threadx
__attribute__((naked))
void inject_fuzzing_task() {
        // PROLOGUE
        store_context_and_lr();
        make_space_stack();

        spipe_write_t writefn = (spipe_write_t)(void*)SPIPE_WRITE_ADDR;
        spawn_threadx_thread spawn = (spawn_threadx_thread)(void*)(0x8f829fe6 | 1);

        char *tname = "HEX_TASK";
        char *qname = "HEX_Q";

        writefn(9, "TASK TO INJECT=", 15, 0);
        writefn(9, tname, 8, 0);
        writefn(9, " QUEUE=", 7, 0);
        writefn(9, qname, 5, 0);
        writefn(9, "\n", 1, 0);

  
        // NOTE: the address must be Thumb, otherwise we get an undefined exeption
        void* task_fn_ptr = (void*)((REBASE + OFFSET_START_CODE + __task_entry_off) | 1);

        // Initialize task
        int stack_size      = 0x800; 
        int queue_size    = 100;
        int preempt_thr    = 0x1e;
        int  time_slice     = 1;
        int  auto_start     = 1;

        int idx = spawn(
            tname,
            qname,
            task_fn_ptr,
            0, // INPUT NULL
            0, // NO THREADX
            stack_size,
            queue_size,
            preempt_thr,
            time_slice,
            auto_start
        );

        writefn(9, "[T] STARTED=", 15, 0);
        writefn(9, (char*)&idx,4, 0);
        writefn(9, "[OK]\n", 5, 0);

        // EPILOGUE
        restore_space_stack();
        restore_context_no_lr();
        ret();
}

static inline void nop_delay(int cycles)
{
    while (cycles--) {
        __asm__ volatile ("nop");
    }
}

typedef int (*nrrc_sib1_parse)(int* args);

__attribute__((section(".text.task_entry"), used))
__attribute__((naked))
void task_entry_fn(){
    store_context_and_lr();
    make_space_stack();

    // Yeah
    char* sib1 =    "D\240\b \002\001\000\000\001\000\000\000\000\n\001\016\000 \000$d\300\000&\260\000?\000\004\000\000\000I$!\360P\200\000\000\220\000\000\221\223\200\000L\000\002\000E\231\210\200\001Zf\201\300\bR\332\000\240";
    int sib1_len = 66;

    char* mib = "\000\000\004";
    int mib_len = 4;


    char* dcch = ",\205O\300\n\300 @\000\004 ,\266\r\303\245,\266\351\341>X]\001\271Hd\002\v+\362\270\21780\000\022#\222\330Hi]\233"; 
    int dcch_len = 45;


    int msg_cnt = 0;

    do {

        switch (msg_cnt % 3) {
            case 0:
                test_call_bcch(mib, (short)mib_len);
                break;

            case 1:
                test_call_ccch(sib1, (short)sib1_len);
                break;

            case 2:
                //test_call_dcch(dcch, dcch_len);
                break;

            default:
                break;
        }

        msg_cnt++;
        nop_delay(10000000);

    }while(1);

    restore_space_stack();
    restore_context_no_lr();

    // Jump back to where we came from (continue)
    ret();
}

// === SHELLCODE ===
__attribute__((section(".text.prologue")))
__attribute__((naked))
void _start () {
    store_context_and_lr();
    make_space_stack();

    // Some fn pointers
    spipe_open_t openfn = (spipe_open_t)(void*)SPIPE_OPEN_ADDR;
    spipe_write_t writefn = (spipe_write_t)(void*)SPIPE_WRITE_ADDR;
    
    // CTX population from static section..
    cov_ctx_t ctx = {
        .hdr = (cov_hdr_t*)COV_HDR_ADDR,
        .map = (char*)COV_MAP_ADDR
    };

    // Setup: Setup log levels for modules
    int* sbuf_log = (int*)(CONFIG_LOGGING_SBUF_EN);
    int* bcch_log = (int*)(CONFIG_LOGGING_RRC);
    *sbuf_log = 0;
    *bcch_log = 3;

    // Setup the coverage map
    cov_init(&ctx, (void*)COV_HDR_ADDR, COV_MAP_SIZE);
  
    openfn(9);
    writefn(9, "INIT OK\n", 8, 0);
    writefn(9, "COV MAP\n", 8, 0);
    writefn(9, (char*)COV_HDR_ADDR, 64, 0);

    // Inject our own task now!
    inject_fuzzing_task();
    
    writefn(9, "INIT TASK OK\n", 14, 0);

    restore_space_stack();
    restore_context_no_lr();

    // Do the actual instruction that we patched out
    PATCHED_INSN();

    // Jump back to where we came from (continue)
    ret();
}
// ===+++++++++++===

