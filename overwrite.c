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

static unsigned long target_off = 0x0036a560;   // offset of target function in Image
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

    if (va & 3UL) { ctx->rc = -EINVAL; return 0; }

    /* Test: idempotent write */
    if (!read_u32(ctx->addr, &orig)) { ctx->rc = -EIO; return 0; }

    /* 1) SAME value */
    WRITE_ONCE(*(u32 __force *)ctx->addr, orig);

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
                dump_window(addr, 96, 96);

                if ((addr & 3UL) != 0) {
                    pr_warn("hexscan: match at non-aligned addr %px — skipping\n", (void *)addr);
                    continue;
                }

                ret = stop_machine(write4_bytes, &ctx, NULL);
                if (ret || ctx.rc) {
                    pr_err("hexscan: write failed (%d)\n", ret);
                } else {
                    pr_info("hexscan: write OK at %px new bytes %x\n", (void *)addr, repl);
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
