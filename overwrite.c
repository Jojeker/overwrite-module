/*
 * insmod overwrite.ko \
 *     printk_off=0x000729e0 target_off=0x0036a560 \
 *     pattern=b40240f994ffffb4e10316aae00314aaab87139480f9ff34593000f039c32491 \
 *     radius_kb=2048 step=4 stop_after_first=1
 *
 * Notes:
 *   - pattern is hex (no 0x / spaces).
 *   - step default is 4 (AArch64 insn alignment).
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/types.h>

// patching stuff
#include <linux/stop_machine.h>
#include <asm/cacheflush.h>
#include <asm/insn.h>
#include <linux/io.h>          // memremap, memunmap
#include <asm/barrier.h>


// Write to page and map it writable on our own:
// 1) Find the pt descriptor that maps va (walk the trns tables starting at kernel top-level table).
// 2) Modify descriptor bits that control access permissions (clear the write-prot bit).
// 3) Make the change visible: write descriptor, sequence of memory barriers and TLB invalidate VA.
// 4) Unmap any temporary mappings used for the table pages.

// Page Table entry shifts for VA
// Level 0 index covers bits [47:39] (shift 39)
// Level 1 index covers bits [38:30] (shift 30)
// Level 2 index covers bits [29:21] (shift 21)
// Level 3 index covers bits [20:12] (shift 12)
// ==> Each is 9 bits (index mask 0x1ff)


// From linux docs:
// +--------+--------+--------+--------+--------+--------+--------+--------+
// |63    56|55    48|47    40|39    32|31    24|23    16|15     8|7      0|
// +--------+--------+--------+--------+--------+--------+--------+--------+
//  |                 |         |         |         |         |
//  |                 |         |         |         |         v
//  |                 |         |         |         |   [11:0]  in-page offset
//  |                 |         |         |         +-> [20:12] L3 index
//  |                 |         |         +-----------> [29:21] L2 index
//  |                 |         +---------------------> [38:30] L1 index
//  |                 +-------------------------------> [47:39] L0 index
//  +-------------------------------------------------> [63] TTBR0/1

// We know that the kernel uses 4KB page size:
// root@udx710-module:/ # cat /proc/self/smaps | grep -i 'PageSize'
// KernelPageSize:        4 kB
// MMUPageSize:           4 kB

#define L3_SHIFT 12
#define IDX_MASK 0x1ffUL

// One descriptor is 8 bytes (64 bits)
#define DESCRIPTOR_SIZE 8UL

// AP[2:1] Access Protection at bits [7:6];
// see: OS use of translation table descriptors
// AP[2]=1 means write-protect (both EL0 and EL1)
// https://documentation-service.arm.com/static/5efa1d23dbdee951c1ccdec5
#define AP2 (1ULL << 7)

// Read TTBR1_EL1 (inline asm mrs ttbr1_el1, x). [Kernel is EL1]
static inline unsigned long rd_ttbr1(void)
{
    // This is the physical base of the level-0 (top) table for kernel addresses
    unsigned long v;
    asm volatile("mrs %0, ttbr1_el1" : "=r"(v));
    return v;
}

static inline phys_addr_t desc_phys(u64 d) { return d & ~((1ULL<<12)-1); }

static inline void tlbi_va(unsigned long va)
{
    unsigned long ipa = va >> 12;
    asm volatile("dsb ishst; tlbi vae1is, %0; dsb ish; isb" :: "r"(ipa));
}

struct pte_loc { void *page_va; size_t off; u64 desc; };

// Returns 0 and fills loc on success. Caller must memunmap(loc->page_va).
static unsigned long* locate_pte(unsigned long va, struct pte_loc *loc)
{
    // -> Clears attribute/flag bits and any offset
    // -> Provide 4 KB-aligned physical base address of the level-0 (top) table
    unsigned long* table = 0xffffff8008dc4000 & ~((1 << 12) - 1);
    pr_warn("table base: %p\n", table);

    // Get the index for the current level
    unsigned long idx = (va >> (30)) & IDX_MASK;
    // Physical page table entry that we have to consult
    unsigned long ent_pa = table[idx];
    // Get page physical address of the next level entry (clear the 12 bits to get to base)
    unsigned long* page_pa = (unsigned long)ent_pa & ~((phys_addr_t)PAGE_SIZE-1);

    pr_warn("page_pa=%p ent_pa=%lx idx=%u\n", page_pa, ent_pa, idx);

    unsigned long *map = memremap(page_pa, PAGE_SIZE, MEMREMAP_WB);

    if (!map) {
        pr_err("ptewalk: FAIL to map");
        return -EINVAL;
    }

    pr_err("ptewalk: virt addr=%lx\n",map);

    // Get the index for the current level
    unsigned long l2idx = (va >> (21)) & IDX_MASK;
    // Physical page table entry that we have to consult
    unsigned long l2ent_pa = map[l2idx];
    // Get page physical address of the next level entry (clear the 12 bits to get to base)
    unsigned long* l2page_pa = (unsigned long)l2ent_pa & ~((phys_addr_t)PAGE_SIZE-1);

    pr_warn("page_pa=%p ent_pa=%lx idx=%u\n", l2page_pa, l2ent_pa, l2idx);

    if ((unsigned long)l2page_pa & 0xFFFF000000000000){
        pr_warn("end of translation reached after 2 steps!");
        return &map[l2idx];
    }


    unsigned long *l2map = memremap(l2page_pa, PAGE_SIZE, MEMREMAP_WB);

    if (!l2map) {
        pr_err("ptewalk: FAIL to map");
        return -EINVAL;
    }

    pr_err("ptewalk: virt addr=%lx\n",l2map);

    // Get the index for the current level
    unsigned long l3idx = (va >> (12)) & IDX_MASK;
    // Physical page table entry that we have to consult
    unsigned long l3ent_pa = l2map[l3idx];
    // Get page physical address of the next level entry (clear the 12 bits to get to base)
    unsigned long* l3page_pa = (unsigned long)l3ent_pa & ~((phys_addr_t)PAGE_SIZE-1);

    pr_warn("page_pa=%p ent_pa=%lx idx=%u\n", l3page_pa, l3ent_pa, l3idx);

    return (unsigned long*) &l2map[l3idx];
        // Get the virtual address for physical page address
        // void *map = memremap(page_pa, PAGE_SIZE, MEMREMAP_WB);

        // if (!map) {
        //     pr_err("ptewalk: FAIL at L%d: TTBR1=0x%016lx idx=%u ent_pa=%pa page_pa=%pa\n",
        //            level, rd_ttbr1(), (unsigned)((va >> (30 - 9*level)) & 0x1ff),
        //            &ent_pa, &page_pa);
        //     return -EINVAL;
        // }

        // pr_err("ptewalk: OK at L%d: TTBR1=0x%016lx idx=%u ent_pa=%pa page_pa=%pa\n",
        //        level, rd_ttbr1(), (unsigned)((va >> (30 - 9*level)) & 0x1ff),
        //        &ent_pa, &page_pa);

        // Now inside the virt. page, get the offset to the entry --> next level base
        // size_t off = ent_pa - page_pa;
        // u64 *ent = (u64 *)((u8 *)map + off);
        // u64 d = READ_ONCE(*ent);

        // table/page bit pattern is 0b11 in low bits for
        // table/page entries (if not we are screwed)
        // if (level < 3) {
        //     // We have something else :S
        //     if ((d & 0x3) != 0x3) { return -EAGAIN; } // block mapping, not handled

        //     // Get page table base (clear 12 bits again)
        //     table = desc_phys(d);
        //     continue;
        // }

        // // final level, must be page descriptor (0b11) otherwise no idea?
        // if ((d & 0x3) != 0x3) { return -EBADF; }

        // // Now we can get the final pte location: our map is the given virt address of the pte
        // // offset and descriptor are also OK
        // loc->page_va = map; loc->off = off; loc->desc = d;
        return 0;
}

// Make VA’s page RW at EL1 by clearing AP[2] in the PTE
int make_page_el1_rw(unsigned long va)
{
    struct pte_loc loc;

    // get the PTE
    int rc = locate_pte(va, &loc);
    if (rc) {
        pr_err("Failed to locate PTE for VA %lx: %d\n", va, rc);
        return rc;
    }

    // Clear the write protection bit
    u64 newd = loc.desc & ~AP2;
    u64 *ent = (u64 *)((u8 *)loc.page_va + loc.off);
    WRITE_ONCE(*ent, newd);

    // dsb: force completion and visibility of prior memory accesses
    dsb(ishst);

    // TLB invalidate that VA we want to modify
    tlbi_va(va);

    // Unmap the page table entry

    //Done
    return 0;
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hexhive");
MODULE_DESCRIPTION("patch cptl stuff [VA->PA]");
MODULE_VERSION("1.0");

// --- params ---
static char *pattern;
module_param(pattern, charp, 0444);
MODULE_PARM_DESC(pattern, "Hex byte pattern (e.g., b40240f9...)");

static unsigned long printk_off=0x000729e0 ;   // offset of printk in *decompressed* Image
module_param(printk_off, ulong, 0644);
MODULE_PARM_DESC(printk_off, "printk offset in Image (hex or dec)");

static unsigned long target_off = 0x00017378;   // offset of target function in Image
module_param(target_off, ulong, 0644);
MODULE_PARM_DESC(target_off, "target offset in Image (hex or dec)");

static char *search = "30000014";   /* 4-byte hex pattern to find */
module_param(search, charp, 0444);
MODULE_PARM_DESC(search, "4-byte hex pattern to search (e.g. 30000014) branch");

// static char *replace = "7b000014";  /* 4-byte hex replacement */
static char *replace = "30000014";   /* 4-byte hex pattern to find */
module_param(replace, charp, 0444);
MODULE_PARM_DESC(replace, "4-byte hex replacement to write (e.g. 7b000014) branch somewhere else");

static unsigned int radius_kb = 2048; // scan ± this many KB around expected VA
module_param(radius_kb, uint, 0644);

static unsigned int step = 4;      // candidate stride (4 for AArch64)
module_param(step, uint, 0644);

static unsigned int stop_after_first = 1;
module_param(stop_after_first, uint, 0644);

static unsigned int keep_loaded = 0; // set to 0 to autounload
module_param(keep_loaded, uint, 0644);

struct patch_ctx {
    void *addr;
    u32   insn;
    int   rc;
};

static size_t safe_read(const void *addr, void *buf, size_t len)
{
    size_t i; u8 v;
    pagefault_disable();
    for (i = 0; i < len; i++) {
        if (probe_kernel_read(&v, (const u8 *)addr + i, 1))
            break;
        ((u8 *)buf)[i] = v;
    }
    pagefault_enable();
    return i;
}

static bool read_u32(const void *addr, u32 *out)
{
    u32 v = 0;
    if (probe_kernel_read(&v, addr, sizeof(v)))
        return false;
    *out = v;
    return true;
}

// Does not exist in kernel :(
// static int patch_one_insn(void *addr, u32 insn)
// {
//     int ret = aarch64_insn_patch_text_nosync(addr, insn);
//     if (ret)
//         return ret;

//     return 0;
// }

static void icache_pou_local(void *info)
{
    struct patch_ctx *ctx = info;
    unsigned long p = (unsigned long)ctx->addr & ~7UL;
    flush_icache_range(p, p + 8);
    isb();
}

static int write4_bytes(void *data)
{
    struct patch_ctx *ctx = data;
    unsigned long va = (unsigned long)ctx->addr;
    u32 orig;
    u8 rc;

    if (va & 3UL) { ctx->rc = -EINVAL; return 0; }

    /* Test: idempotent write */
    if (!read_u32(ctx->addr, &orig)) { ctx->rc = -EIO; return 0; }

    // Now: set the pte to writeable
    rc = make_page_el1_rw(va);
    if (rc) {
        ctx->rc = -ENOMEM;
        return 0;
    }

    WRITE_ONCE(*(u32 __force *)va, ctx->insn);

    /* write globally visible before I-cache maint */
    dsb(ishst);

    /* Invalidate I-cache for those bytes on ALL ***Linux*** CPUs */
    on_each_cpu(icache_pou_local, ctx, 1);

    dsb(ish);
    isb();

    ctx->rc = 0;
    return 0;
}

static void dump_window(unsigned long center, unsigned int before, unsigned int after)
{
    unsigned long start = center - before;
    unsigned long end   = center + after;
    unsigned long addr  = start & ~0xFUL;
    u8 line[16];
    size_t got;
    char hex[3*16 + 1];
    int i;

    pr_info("hexscan: DUMP around %px  [-%u,+%u] bytes\n", (void *)center, before, after);

    for (; addr < end; addr += 16) {
        memset(line, 0, sizeof(line));
        got = safe_read((void *)addr, line, sizeof(line));
        for (i = 0; i < 16; i++)
            snprintf(hex + i*3, 4, "%02x%s", (i < got ? line[i] : 0), (i==15?"":" "));
        pr_info("%px: %s%s\n", (void *)addr, hex, (got<16?" …":""));
    }
}

static unsigned char *pat;
static size_t pat_len;

static int hexnib(int c){
    if (c>='0' && c<='9') return c-'0';
    if (c>='a' && c<='f') return c-'a'+10;
    if (c>='A' && c<='F') return c-'A'+10;
    return -1;
}

static int parse_u32hex(const char *s, u32 *out)
{
    int hi, lo;
    if (!s || strlen(s) != 8) return -EINVAL;
    hi = hexnib(s[0]); if (hi < 0) return -EINVAL;
    hi = (hi << 4) | hexnib(s[1]);
    lo = hexnib(s[2]); if (lo < 0) return -EINVAL;
    lo = (lo << 4) | hexnib(s[3]);
    {
        int i; u32 v = 0;
        for (i = 0; i < 8; i++) {
            int n = hexnib(s[i]);
            if (n < 0) return -EINVAL;
            v = (v << 4) | n;
        }
        *out = v;
        return 0;
    }
}

static int parse_pattern(const char *s){
    size_t n = s ? strlen(s) : 0; size_t i; int hi, lo;
    if (!n || (n & 1)) return -EINVAL;
    pat = kmalloc(n/2, GFP_KERNEL);
    if (!pat) return -ENOMEM;
    pat_len = n/2;
    for (i=0;i<pat_len;i++){
        hi = hexnib(s[2*i]); lo = hexnib(s[2*i+1]);
        if (hi<0 || lo<0){ kfree(pat); pat=NULL; pat_len=0; return -EINVAL; }
        pat[i] = (hi<<4) | lo;
    }
    return 0;
}

void (*show_pte)(unsigned long addr);

static int __init scan_text_init(void)
{
    const size_t page = 4096;
    const size_t chunk = page;
    unsigned long va_printk = (unsigned long)&printk;
    u32 srch = 0, repl = 0;
    // u8 repl_bytes[4];
    long delta;
    unsigned long va_expect, lo, hi, addr;
    u8 *buf = NULL;
    unsigned long matches = 0;
    u32 first4 = 0;
    unsigned long base  = 0;
    size_t start_i = 0;
    size_t gotr = 0;
    int ret;

    if (!pattern) { pr_err("hexscan: need pattern=\n"); return -EINVAL; }
    if (!printk_off || !target_off) {
        pr_err("hexscan: need printk_off= and target_off=\n");
        return -EINVAL;
    }

    if (strlen(search) != 8 || strlen(replace) != 8) {
        pr_err("hexscan: search/replace must be 8 hex chars (4 bytes)\n");
        return -EINVAL;
    }

    if (parse_u32hex(search, &srch) < 0 || parse_u32hex(replace, &repl) < 0) {
        pr_err("hexscan: bad hex\n");
        return -EINVAL;
    }

    // repl_bytes[0] = (repl >> 24) & 0xff;
    // repl_bytes[1] = (repl >> 16) & 0xff;
    // repl_bytes[2] = (repl >> 8) & 0xff;
    // repl_bytes[3] = (repl >> 0) & 0xff;

    if (step == 0 || (step % 4)) step = 4;

    ret = parse_pattern(pattern);
    if (ret) { pr_err("hexscan: bad pattern (%d)\n", ret); return ret; }
    if (pat_len < 8) pr_warn("hexscan: very short pattern (%zu bytes)\n", pat_len);

    // quick peek (proof for reading text)
    {
        u8 peek[16] = {0};
        size_t got = safe_read((void *)va_printk, peek, sizeof(peek));
        pr_info("hexscan: printk=%px peek %zu: %*ph\n",
                (void *)va_printk, got, (int)got, peek);
    }

    // compute expected VA
    delta = (long)target_off - (long)printk_off;
    va_expect = va_printk + delta;

    lo = va_expect - ((unsigned long)radius_kb << 10);
    hi = va_expect + ((unsigned long)radius_kb << 10);

    pr_info("hexscan: printk_off=0x%lx target_off=0x%lx delta=0x%lx\n",
            printk_off, target_off, (unsigned long)delta);
    pr_info("hexscan: expect ~VA=%px; scanning [%px .. %px) (~%lu KB each side, step=%u)\n",
            (void *)va_expect, (void *)lo, (void *)hi, (unsigned long)radius_kb, step);

    buf = kmalloc(chunk + pat_len, GFP_KERNEL);
    if (!buf) { kfree(pat); pat=NULL; pat_len=0; return -ENOMEM; }

    if (pat_len >= 4) {
        first4 = (u32)pat[0] | ((u32)pat[1] << 8) | ((u32)pat[2] << 16) | ((u32)pat[3] << 24);
    }

    pr_info("hexscan: writing %x to target address", repl);

    for (addr = lo; addr < hi; addr += step) {
        if (pat_len >= 4) {
            u32 v;
            if (!read_u32((void *)addr, &v)) continue;
            if (v != first4) continue;
        }

        base = addr & ~(page - 1);
        gotr = safe_read((void *)base, buf, chunk);
        if (!gotr) continue;

        start_i = addr - base;
        if (start_i + pat_len <= gotr) {
            if (!memcmp(buf + start_i, pat, pat_len)) {
                phys_addr_t pa = virt_to_phys((void *)addr);

                struct patch_ctx ctx = { .addr = (void*)addr, .insn =  repl, .rc = -1 };
                pr_info("hexscan: MATCH VA=%px PA=0x%llx\n",
                        (void *)addr, (unsigned long long)pa);
                // dump_window(addr, 96, 96);

                if ((addr & 3UL) != 0) {
                    pr_warn("hexscan: match at non-aligned addr %px — skipping\n", (void *)addr);
                    continue;
                }

                {
                    show_pte = (void *)addr;
                    unsigned long* test = vmalloc(PAGE_SIZE);
                    unsigned long* test2 = vmalloc(PAGE_SIZE);
                    *test = 0x12345678;
                    *test2 = 0x98765432;

                    pr_warn("test=%p", test);
                    unsigned long* ver_pageentry;
                    unsigned long* test_pageentry;
                    // unsigned long ver_entry = (unsigned long)&printk;
                    unsigned long ver_entry = 0xffffff8008298b20;
                    pr_warn("verentry=%lx masked=%lx", ver_entry, ver_entry & ~((1 << 21 )  - 1));
                    dump_window(ver_entry & ~((1 << 21 )  - 1), 0, 96);

                    // show_pte((unsigned long )test);
                    // show_pte((unsigned long )ver_entry);
                    test_pageentry = locate_pte((unsigned long)test, NULL);
                    ver_pageentry = locate_pte((unsigned long)ver_entry, NULL);

                    pr_warn("test_pageentry=%lx", (unsigned long)test_pageentry);
                    pr_warn("ver_pageentry=%lx", (unsigned long)ver_pageentry);

                    pr_warn("*test_pageentry=%p", *(unsigned long*)test_pageentry);
                    pr_warn("*ver_pageentry=%p", *(unsigned long*)ver_pageentry);
                    unsigned long valver = *ver_pageentry;
                    unsigned long valtest = *test_pageentry;

                    valver &= (0x000FFFFFFFFFF000);
                    valtest &= ~(0x000FFFFFFFFFF000);
                    valtest |= (valver + 0x1F4000);


                    pr_warn("valtest=%lx valver=%lx", valtest, valver);
                    *test_pageentry = valtest;
                    // // dsb: force completion and visibility of prior memory accesses

                    dsb(ishst);
                    tlbi_va(test);
                   	dsb(ish);
                   	isb();
                    pr_warn("flushed.");

                    // // unsigned long phys = virt_to_phys(test);


                    int j = 0;
                    while(j < 4000){
                        unsigned long* a = vmalloc(PAGE_SIZE);
                        *a = 0xdeadbeef;
                        j++;
                    }
                    if(*test == 0x12345678){
                        pr_warn("failed to map.");
                        return -1;
                    }

                    // show_pte((unsigned long)test);
                    // // locate_pte((unsigned long)test, NULL);
                    dump_window((char*)test + 350, 0, 96);

                    char* ctest = (char*)test;
                    pr_info("test=%x", *(ctest + 344));
                    *(ctest + 344) = 0x7b;
                    dump_window((char*)test + 350, 0, 96);
                }

                matches++;
                if (stop_after_first) break;
            }
        } else {
            // spillover across page
            u8 tmp[256];
            size_t need = pat_len;
            if (need > sizeof(tmp)) need = sizeof(tmp);
            if (pat_len > sizeof(tmp)) {
                pr_warn_once("hexscan: pattern > 256 bytes; boundary check capped\n");
            }
            if (safe_read((void *)addr, tmp, need) == need) {
                if (!memcmp(tmp, pat, need)) {
                    phys_addr_t pa = virt_to_phys((void *)addr);
                    pr_info("hexscan: MATCH VA=%px PA=0x%llx\n",
                            (void *)addr, (unsigned long long)pa);
                    matches++;
                    if (stop_after_first) break;
                }
            }
        }
    }

    pr_info("hexscan: done; matches=%lu\n", matches);
    kfree(buf);
    kfree(pat); pat=NULL; pat_len=0;

    // "autounload" becaues the kernel does not support unload :)
    return keep_loaded ? 0 : -EINVAL;
}

static void __exit scan_text_exit(void)
{
    pr_info("hexscan: exit\n");
    if (pat) { kfree(pat); pat=NULL; }
}

module_init(scan_text_init);
module_exit(scan_text_exit);
