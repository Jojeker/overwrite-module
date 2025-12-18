#ifndef FUZZING_H

#define MAGIC 0xBA5E5C0E 

// We have a couple of bytes slack
// after the shellcode trampolines
// --> this should be more than 1MB, so we are set
// Layout: [HDR (64 bytes)][MAP (128KiB)]
#define SHELL_CODE_END_REGION (0xF016f0  + 0x8F81FE00)
#define COV_HDR_ADDR (SHELL_CODE_END_REGION) + 0x1000
#define COV_MAP_ADDR (COV_HDR_ADDR) + 0x40

// Use a 128KiB map size
#define COV_MAP_SIZE 0x20000 


// Some static variables that we are intested in
#define CONFIG_LOGGING_RRC 0x91810b1c 
#define CONFIG_LOGGING_SBUF_EN 0x91810B1C

#define NRRC_RECEIVE_PAYL_ADDR (0x8fba1616 | 1)
#define NRRC_RECEIVE_BCCH_BCH_DATA (0x8fba4bca | 1)
#define NRRC_RECEIVE_DCCH_DATA (0x8fc5e6e2| 1)
#define DL_SCH_PARSE_ADDR (0x8fc8cd3a)

// Header of our fuzzing setup (64 bytes)
typedef struct __attribute__((packed)) {
  int magic;
  int version;
  int map_size;
  int iter_count;
  int is_ready;
  int dump_ready;
  int last_lr;
  char  reserved[64 - 7*4];
} cov_hdr_t;

// compute an index into our map
// (poor man's avalanche effect)
static __inline int mix32(int x) {
  x ^= x >> 16;
  x *= 0x7feb352dU;
  x ^= x >> 15;
  x *= 0x846ca68bU;
  x ^= x >> 16;
  return x;
}


// Coverage context:
// - header with magic and info
// - map where we actually write into 
//   [idx] contains count of hits (like in AFL)
typedef struct {
  cov_hdr_t *hdr;
  char   *map;
} cov_ctx_t;

// We need it only now..
void __inline *memset(void *str, int c, int n)
{
	for(int i=0; i<n; i++){
		((char*)str)[i] = (char)c;
	}
	return str;
}

static __inline void cov_init(cov_ctx_t *c, void *base, int map_size) {
    c->hdr  = (cov_hdr_t*)base;
    c->map  = (char*)((char*)base + sizeof(cov_hdr_t));

    // Must have header init and size ok
    if (c->hdr->magic != MAGIC || c->hdr->map_size != map_size) {
	// Reset bits to have a clean storage

	// TODO: We clean this in FW code so it is actually better to not
	// spend cycles on this.... (!!)
	memset(base, 0, sizeof(cov_hdr_t) + map_size);

	// Init thee header and extra stuff
	c->hdr->magic = MAGIC;
	c->hdr->version = 1;
	c->hdr->map_size = map_size;
	c->hdr->is_ready = 0x13371337;
    }
}

static __inline int is_cov_ready(cov_ctx_t* c){
  return c->hdr->is_ready == 0x13371337;
}

static __inline void cov_hit(cov_ctx_t *c, int lr) {
    // Keep LR for debugging
    c->hdr->last_lr = lr;
    // compute index and put it in our map
    int idx = mix32(lr) & (c->hdr->map_size - 1u);
    // Wrap ok
    c->map[idx]++;
}

#endif // !FUZZING_H
