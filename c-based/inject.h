/* “local_para” style parameter block = your user_data */
typedef struct user_data {
  int   refcnt;         // 0x00: must be 1..4 in many stacks (asserted elsewhere)
  int   from_src_layer; // 0x04: 0/1/2/3/4 selector
  int   srb_id;         // 0x08: used in PDCP path (compared to 3)
  char     *buf;            // 0x0C: heap buffer, freed by INSTRUMENT_nrrc_receive_payl
  int   length;         // 0x10: bytes in buf (often treated as short)
  int   unk14;          // 0x14
  int   unk18;          // 0x18
  int   parsing_state;  // 0x1C: seen as 0/1/2 in DCCH code
  void     *peer_container; // 0x20: “peer_buff”/container handle; freed or dispatched
  int   header_len;     // 0x24: used as a byte in DCCH processing
  int   unk28;          // 0x28
  int   unk2c;          // 0x2C
  int   unk30;          // 0x30
} user_data;

typedef struct pdu_payl {
    short _pad0; // No clue
    char refcnt;
} pdu_payl;

/* Message object: only fields used by INSTRUMENT_nrrc_receive_payl are required */
typedef struct nrrc_msg {
  short  msg_id;         // used elsewhere; not required by INSTRUMENT_... itself
  short  _pad0;
  int   _pad1;          // keep alignment similar to target
  user_data *user_data;     // pointer to local_para/user_data
  void      *pdu_data;      // peer_buff pointer in other code paths; not used here directly
} nrrc_msg;

// Threadx helper
typedef int (*spawn_threadx_thread)(
    char* thread_name,              // char* in practice
    char* queue_name,               // char* in practice
    void (*entry_fn_ar)(int),       // thread entry function
    int entry_input_ar,             // entry argument
    void *thread,       // pointer to TX_THREAD (???)
    int stack_size,                 // bytes (lets make 0x800)
    int extra_stack,               // extra stack reserve in words? (multiplied by 4)
    int preempt_thresh,     // preemption threshold or 0 when time_slice==0
    int time_slice,                // 0 disables threshold handling in wrapper
    int auto_start                 // index into DAT_8f82a168 table (likely 0/1)
);

// At 0x8fba1616 (thumb)
typedef void* (*CCCH_parse)(nrrc_msg*);
typedef void* (*BCCH_parse)(nrrc_msg*);
typedef void* (*DCCH_parse)(char* payl, int size, void* parsed);
