/* ============================================================================
 * pe_vm.c  --  PE 虚拟执行沙盒（用户态解释器，与真实系统零接触）
 * ----------------------------------------------------------------------------
 * 设计依据：火绒《脚本行为沙盒简介》——"把脚本问题转化为 PE 问题"，把代码的
 *          解释与执行完全关在虚拟环境内。本程序把同一条原则用在 PE 上：
 *            * 不 CreateProcess、不映射真文件、不碰真注册表、不联网；
 *            * 所有 x86 指令由本进程内的解释器执行；
 *            * 所有内存访问都经过校验（越界/未映射一律安全停机）；
 *            * 所有 Windows API 都是"假实现"，只记录行为、返回编造的合理值。
 *          因此样本即便再会反沙箱，它面对的是一个真实到可自洽、却完全虚的机器。
 *
 * 阶段一（本文件）：虚拟装载 + 导入表虚拟化 + 全虚拟 API + 内存镜像/落盘还原。
 * 阶段二（后续）：x86-32 解释器（脱壳、行为还原）。
 *
 * 用法：
 *   pe_vm.exe --load <sample.exe>                 只装载：打印 PE 结构/节/导入表（不执行）
 *   pe_vm.exe <sample.exe> [--dump out.bin] [--trace out.log] [--max-insn N]
 *   pe_vm.exe --selftest                          自检
 * 兼容：MinGW-w64 / MSVC，仅 32 位 PE（PE32）。
 * ========================================================================== */
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <math.h>
#include <time.h>
#include <windows.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;

/* MSVC 没有 GCC 的 __builtin_*；用等价实现补齐（任务 4 的 MSVC 构建需要）。 */
#ifdef _MSC_VER
#  include <intrin.h>
static int pevm_parity(unsigned v) {
    v ^= v >> 16;
    v ^= v >> 8;
    v ^= v >> 4;
    v &= 0xF;
    return (0x6996 >> v) & 1;          /* 1 = odd parity，与 __builtin_parity 一致 */
}
#  define __builtin_parity(x)   pevm_parity((unsigned)(x))
#  define __builtin_bswap64(x)  _byteswap_uint64(x)
#  define __builtin_bswap32(x)  _byteswap_ulong(x)
#endif

#define VERSION_STR "pe_vm 0.2 (虚拟执行沙盒 · 阶段一/二：x86-32 + x86-64 用户态解释器)"

/* ---------------------------------------------------------------- 输出 ---- */
static FILE* g_trace = NULL;   /* 行为轨迹（UTF-8） */
static int   g_verbose = 0;
static long  g_insn = 0;
static long  g_insn_print = 0;   /* --insn N：把前 N 条指令的 RIP/字节打印出来（排障用）*/

static void say(const char* fmt, ...);

#include <stdarg.h>
static void vsay(FILE* f, const char* fmt, va_list ap) { vfprintf(f, fmt, ap); }
static void say(const char* fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vsay(stdout, fmt, ap);
    va_end(ap);
    fflush(stdout);
}
static void tr(const char* fmt, ...) {
    va_list ap; va_start(ap, fmt);
    if (g_trace) { vsay(g_trace, fmt, ap); fflush(g_trace); }
    if (g_verbose) { vsay(stdout, fmt, ap); }
    va_end(ap);
}

/* ------------------------------------------------------------ 虚拟内存 ---- */
/* 4GB 地址空间按 1MB 分页惰性分配；prot 位 P_R/P_W/P_X。
 * 任何访问都经 vm_read / vm_write，未映射即安全停机（绝不碰宿主内存）。  */
#define PG_SHIFT 12
#define PG_SIZE  (1u << PG_SHIFT)
#define PG_COUNT (1u << (32 - PG_SHIFT))   /* 1048576（4KB 页，与 PE 节对齐） */

#define P_R 1
#define P_W 2
#define P_X 4

typedef struct { u8* p; u32 prot; u32 written; } pg_t;
static pg_t g_pg[PG_COUNT];
static u32  g_vm_alloced = 0;   /* 已分配页数 */

static u32 pg_default_prot(u32 addr);   /* 后置定义：取所在区域的默认保护位 */

static u8* pg_ensure(u32 addr) {
    u32 i = addr >> PG_SHIFT;
    if (i >= PG_COUNT) return NULL;
    if (!g_pg[i].p) {
        u32 dp = pg_default_prot(addr);
        if (!dp) return NULL;                      /* 不属于任何区域 -> 不分配 */
        g_pg[i].p = (u8*)calloc(1, PG_SIZE);
        if (!g_pg[i].p) return NULL;
        g_pg[i].prot = dp;
        g_vm_alloced++;
    }
    return g_pg[i].p;
}
static u8* pg_get(u32 addr) {
    u32 i = addr >> PG_SHIFT;
    if (i >= PG_COUNT || !g_pg[i].p) return NULL;
    return g_pg[i].p;
}

static int vm_read(u32 a, void* dst, u32 n) {
    u8* d = (u8*)dst;
    u32 done = 0;
    while (done < n) {
        u32 pg = (a + done) >> PG_SHIFT;
        u32 off = (a + done) & (PG_SIZE - 1);
        u32 chunk = PG_SIZE - off; if (chunk > n - done) chunk = n - done;
        if (pg >= PG_COUNT) return 0;
        if (!g_pg[pg].p && !pg_ensure(a + done)) return 0;   /* 区域内的页按需分配（零填充） */
        if (!(g_pg[pg].prot & P_R)) return 0;
        memcpy(d + done, g_pg[pg].p + off, chunk);
        done += chunk;
    }
    return 1;
}
static int vm_write(u32 a, const void* src, u32 n) {
    const u8* s = (const u8*)src;
    u32 done = 0;
    while (done < n) {
        u32 pg = (a + done) >> PG_SHIFT;
        u32 off = (a + done) & (PG_SIZE - 1);
        u32 chunk = PG_SIZE - off; if (chunk > n - done) chunk = n - done;
        if (pg >= PG_COUNT) return 0;
        if (!g_pg[pg].p && !pg_ensure(a + done)) return 0;
        if (!(g_pg[pg].prot & P_W)) return 0;             /* 只读 -> 写失败 */
        memcpy(g_pg[pg].p + off, s + done, chunk);
        g_pg[pg].written = 1;
        done += chunk;
    }
    return 1;
}
/* 内核式写入：忽略保护位（仅用于装载/API 内部模拟） */
static int vm_poke(u32 a, const void* src, u32 n) {
    const u8* s = (const u8*)src;
    u32 done = 0;
    while (done < n) {
        u32 pg = (a + done) >> PG_SHIFT;
        u32 off = (a + done) & (PG_SIZE - 1);
        u32 chunk = PG_SIZE - off; if (chunk > n - done) chunk = n - done;
        if (pg >= PG_COUNT) return 0;
        if (!g_pg[pg].p) { if (!pg_ensure(a + done)) return 0; }
        if (!(g_pg[pg].prot & P_W)) g_pg[pg].prot |= P_W;
        memcpy(g_pg[pg].p + off, s + done, chunk);
        done += chunk;
    }
    return 1;
}
static int vm_read32(u32 a, u32* v) { return vm_read(a, v, 4); }
static int vm_read16(u32 a, u16* v) { return vm_read(a, v, 2); }
static int vm_read8 (u32 a, u8*  v) { return vm_read(a, v, 1); }
static int vm_write32(u32 a, u32 v) { return vm_write(a, &v, 4); }
static int vm_write16(u32 a, u16 v) { return vm_write(a, &v, 2); }
static int vm_write8 (u32 a, u8  v) { return vm_write(a, &v, 1); }

/* ------------------------------------------------- 区域账本（用于报告/还原） -- */
#define RK_IMAGE  1
#define RK_ALLOC  2
#define RK_STACK  3
#define RK_API    4
#define RK_FILE   5

typedef struct { u32 base, size, prot; int written; int kind; char tag[48]; } reg_t;
static reg_t g_reg[1024];
static int   g_regN = 0;

static reg_t* reg_add(u32 base, u32 size, u32 prot, int kind, const char* tag) {
    if (g_regN >= 1024) return NULL;
    reg_t* r = &g_reg[g_regN++];
    r->base = base; r->size = size; r->prot = prot; r->written = 0; r->kind = kind;
    snprintf(r->tag, sizeof(r->tag), "%s", tag ? tag : "");
    return r;
}
static reg_t* reg_find(u32 addr) {
    /* 取"最小的包含区域"：PE 各节登记在整镜像区域之内，最具体的那个优先，
     * 这样每个节都能保留自己的保护位（读/写/执行）。 */
    reg_t* best = NULL;
    for (int i = 0; i < g_regN; i++) {
        reg_t* r = &g_reg[i];
        if (addr >= r->base && addr < r->base + r->size)
            if (!best || r->size < best->size) best = r;
    }
    return best;
}
/* 新页按需分配时，取它所在区域的默认保护位；不在任何区域里就返回 0（不分配） */
static u32 pg_default_prot(u32 addr) {
    reg_t* r = reg_find(addr);
    return r ? r->prot : 0;
}
static void reg_setprot(u32 addr, u32 size, u32 prot) {
    for (int i = 0; i < g_regN; i++) {
        reg_t* r = &g_reg[i];
        if (addr < r->base + r->size && addr + size > r->base) r->prot = prot;
    }
    u32 a = addr & ~(PG_SIZE - 1);
    for (; a < addr + size; a += PG_SIZE) {
        u32 i = a >> PG_SHIFT;
        if (i < PG_COUNT && g_pg[i].p) g_pg[i].prot = prot;
    }
}
static void reg_mark_written(u32 addr, u32 n) {
    for (int i = 0; i < g_regN; i++) {
        reg_t* r = &g_reg[i];
        if (addr < r->base + r->size && addr + n > r->base) r->written = 1;
    }
}

/* --------------------------------------------------------------- PE 解析 -- */
static u8*  g_file = NULL;
static u32  g_filesz = 0;
static u32  g_imagebase = 0, g_entry = 0, g_sizeofimage = 0, g_sizeofheaders = 0;
static u32  g_sectionalign = 0, g_filealign = 0;
static int  g_is64 = 0;
static int  g_load_ok = 0;

typedef struct { char name[9]; u32 va, vsize, raw, rawsize, chars; } sec_t;
static sec_t g_sec[96];
static int   g_secN = 0;

#pragma pack(push,1)
typedef struct { u16 e_magic; u8 _pad[58]; u32 e_lfanew; } dos_t;
typedef struct {
    u16 machine; u16 nsections; u32 timestamp; u32 symtab; u32 nsyms;
    u16 optsize; u16 chars;
} coff_t;
typedef struct {
    u32 rva; u32 size;
} ddir_t;
#pragma pack(pop)

/* 导入表（虚拟化后） */
typedef struct { u32 stub; char dll[56]; char name[64]; int ord; int bound; } imp_t;
#define IMP_MAX 4096
static imp_t g_imp[IMP_MAX];
static int   g_impN = 0;

#define STUB_BASE 0x7F000000u
#define STUB_STRIDE 16
static u32 g_stub_next = 0;
static u32 g_last_error = 0;   /* 假 LastError（供注册表等失败路径使用） */

static u32 rd32(u32 off) { u32 v = 0; if (off + 4 <= g_filesz) memcpy(&v, g_file + off, 4); return v; }
static u16 rd16(u32 off) { u16 v = 0; if (off + 2 <= g_filesz) memcpy(&v, g_file + off, 2); return v; }

/* 在虚拟地址空间分配一段（指定地址时按 4KB 对齐登记，未指定则找空闲） */
static u32 vm_alloc_region(u32 hint, u32 size, u32 prot, int kind, const char* tag) {
    u32 base = hint ? (hint & ~0xFFFu) : 0x10000000u;
    if (base == 0) base = 0x10000000u;
    /* 线性探测空闲（不与既有区域重叠） */
    for (int guard = 0; guard < 200000; guard++) {
        int clash = 0;
        for (int i = 0; i < g_regN; i++) {
            if (base < g_reg[i].base + g_reg[i].size && base + size > g_reg[i].base) { clash = 1; break; }
        }
        if (!clash) break;
        base += (size + 0xFFF) & ~0xFFFu;
        if (base > 0x7F000000u) base = 0x10000000u;
    }
    /* 页面按需分配：这里只登记区域，不预占物理页；新页会继承本区域的保护位 */
    reg_add(base, size, prot, kind, tag);
    return base;
}

/* 运行库的"数据导入"：IAT 槽里应当放变量的地址（可写内存），而不是代码桩。
 * 早期实测里 6ae503b3ee11 / 17e7f0170795 / b007e3f21dc3 都崩在
 *   mov rax,[__imp__fmode] ; mov [rax],0
 * 上——因为 _fmode 是 CRT 的全局变量，不是函数。 */
static const char* const DATA_IMPORTS[] = {
    "_fmode", "_commode", "_acmdln", "_wcmdln", "__initenv", "_environ", "_wenviron",
    "_osplatform", "_osver", "_winver", "_winmajor", "_winminor", "__mb_cur_max",
    "_pctype", "_pwctype", "_days", "_months", "_dowildcard", "_newmode", "_argc", "_argv",
    "__argc", "__argv", "__wargv", "_cpumode", "_fileinfo", "_sys_nerr", "_sys_errlist",
    "_cfltcvt_tab", "_defdll", "_defdir", "_cpunumber", "_setargv", "_setenvp",
    "_pgmptr", "_wpgmptr", NULL
};
static int is_data_import(const char* n) {
    for (int i = 0; DATA_IMPORTS[i]; i++) if (!_stricmp(n, DATA_IMPORTS[i])) return 1;
    return 0;
}
static u32 g_dimp_cur = 0, g_dimp_left = 0;
static u32 data_import_cell(void) {
    if (g_dimp_left < 32) {
        u32 a = vm_alloc_region(0, 0x1000, P_R | P_W, RK_ALLOC, "导入数据");
        if (!a) return 0;
        g_dimp_cur = a; g_dimp_left = 0x1000;
    }
    u32 r = g_dimp_cur; g_dimp_cur += 32; g_dimp_left -= 32; return r;
}
/* 登记一条导入；want=0 时分配"代码桩"，否则用调用者给的地址（数据导入用） */
static u32 stub_alloc_ex(const char* dll, const char* name, u32 want) {
    for (int i = 0; i < g_impN; i++)
        if (!strcmp(g_imp[i].dll, dll) && !strcmp(g_imp[i].name, name)) return g_imp[i].stub;
    if (g_impN >= IMP_MAX) return 0;
    u32 addr = want;
    if (!addr) {
        addr = STUB_BASE + g_stub_next * STUB_STRIDE;
        g_stub_next++;
        /* 桩区登记为一个区域，页面按需分配且只读可执行 */
        static int stub_reg = 0;
        if (!stub_reg) { reg_add(STUB_BASE, 0x10000, P_R | P_X, RK_API, "API桩区"); stub_reg = 1; }
        /* 写入一条 ret，万一被当数据执行也不会跑飞（本沙盒里真调用会被拦截） */
        u8 ret = 0xC3; vm_poke(addr, &ret, 1);
        reg_setprot(addr, STUB_STRIDE, P_R | P_X);
    }
    imp_t* im = &g_imp[g_impN++];
    im->stub = addr; im->ord = 0; im->bound = 0;
    snprintf(im->dll, sizeof(im->dll), "%s", dll);
    snprintf(im->name, sizeof(im->name), "%s", name);
    return addr;
}
static u32 stub_alloc(const char* dll, const char* name) {
    return stub_alloc_ex(dll, name, 0);
}
/* 慢速精确查找（仅用于诊断打印：数据导入单元不在桩区里） */
static imp_t* imp_lookup_slow(u32 a) {
    for (int i = 0; i < g_impN; i++) if (g_imp[i].stub == a) return &g_imp[i];
    return NULL;
}
static u32 stub_alloc_unused_old(const char* dll, const char* name) {
    (void)dll; (void)name; return 0;
}
static imp_t* stub_lookup(u32 addr) {
    if (addr < STUB_BASE || addr >= STUB_BASE + (u32)g_stub_next * STUB_STRIDE) return NULL;
    u32 idx = (addr - STUB_BASE) / STUB_STRIDE;
    if (idx >= (u32)g_impN) return NULL;
    /* 允许落在 stub 内任意偏移（取整条） */
    for (int i = 0; i < g_impN; i++) if ((addr >= g_imp[i].stub) && (addr < g_imp[i].stub + STUB_STRIDE)) return &g_imp[i];
    return NULL;
}

static u64 g_pref_base = 0;   /* 首选镜像基址（64 位；用于基址重定位） */
static int g_is_dll = 0;      /* 文件头带 IMAGE_FILE_DLL：入口按 DllMain(hinst, 1, 0) 调用 */

static int pe_load(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) { say("  [错误] 打不开文件：%s\n", path); return 0; }
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 300 * 1024 * 1024) { say("  [错误] 文件大小异常：%ld\n", sz); fclose(f); return 0; }
    g_file = (u8*)malloc((size_t)sz); g_filesz = (u32)sz;
    if (!g_file || fread(g_file, 1, (size_t)sz, f) != (size_t)sz) { say("  [错误] 读取失败\n"); fclose(f); return 0; }
    fclose(f);

    if (g_filesz < 0x40 || g_file[0] != 'M' || g_file[1] != 'Z') { say("  [错误] 不是 PE（缺 MZ）\n"); return 0; }
    u32 lfanew = rd32(0x3C);
    if (lfanew + 24 > g_filesz) { say("  [错误] e_lfanew 越界\n"); return 0; }
    if (memcmp(g_file + lfanew, "PE\0\0", 4)) { say("  [错误] 缺 PE 签名\n"); return 0; }
    coff_t co; memcpy(&co, g_file + lfanew + 4, sizeof(co));
    g_is_dll = (rd16(lfanew + 22) & 0x2000) ? 1 : 0;
    if (g_is_dll) say("  [说明] 文件头标记为 DLL：入口按 DllMain(hinst, DLL_PROCESS_ATTACH=1, 0) 调用（与 Windows 加载器一致）。\n");
    u32 optoff = lfanew + 24;
    u16 magic = rd16(optoff);
    if (magic == 0x20B) { g_is64 = 1; say("  [说明] 这是 64 位 PE（PE32+）：交给 x86-64 解释器虚拟执行（镜像按 ImageBase 低 32 位装载进沙盒的 4GB 空间）。\n"); }
    else if (magic != 0x10B) { say("  [错误] 未知可选头 magic=0x%X\n", magic); return 0; }

    if (g_is64) {
        g_entry = rd32(optoff + 16);
        u32 imagebase_lo = rd32(optoff + 24);
        u32 imagebase_hi = rd32(optoff + 28);
        g_imagebase = imagebase_lo;
        g_pref_base = ((u64)imagebase_hi << 32) | (u64)imagebase_lo;
        g_sectionalign = rd32(optoff + 32);
        g_filealign = rd32(optoff + 36);
        g_sizeofimage = rd32(optoff + 56);
        g_sizeofheaders = rd32(optoff + 60);
    } else {
        g_entry = rd32(optoff + 16);
        g_imagebase = rd32(optoff + 28);
        g_pref_base = (u64)g_imagebase;
        g_sectionalign = rd32(optoff + 32);
        g_filealign = rd32(optoff + 36);
        g_sizeofimage = rd32(optoff + 56);
        g_sizeofheaders = rd32(optoff + 60);
    }

    /* 映射镜像 */
    u32 img = vm_alloc_region(g_imagebase, g_sizeofimage ? g_sizeofimage : 0x1000, P_R | P_W, RK_IMAGE, "PE镜像");
    if (!img) { say("  [错误] 镜像虚拟分配失败\n"); return 0; }
    g_imagebase = img;
    vm_poke(g_imagebase, g_file, g_sizeofheaders > g_filesz ? g_filesz : g_sizeofheaders);

    /* 节表 */
    u32 secoff = optoff + co.optsize;
    g_secN = 0;
    for (int i = 0; i < co.nsections && i < 96; i++, secoff += 40) {
        sec_t* s = &g_sec[g_secN];
        memcpy(s->name, g_file + secoff, 8); s->name[8] = 0;
        s->vsize = rd32(secoff + 8); s->va = rd32(secoff + 12);
        s->rawsize = rd32(secoff + 16); s->raw = rd32(secoff + 20);
        s->chars = rd32(secoff + 36);
        u32 pr = P_R;
        if (s->chars & 0x80000000u) pr |= P_W;
        if (s->chars & 0x20000000u) pr |= P_X;
        /* 先把本节登记成独立区域（比整镜像区域更小、更具体，优先生效），再写节数据，
         * 这样按需分配的新页会继承"本节自己的"保护位。之前只调用 reg_setprot，
         * 最后一个节的保护位会覆盖整个镜像 —— x64 批量实测里 .bss 写入被判只读、
         * 19 个样本提前停机，根因就在这里。 */
        {
            u32 ssz = s->vsize ? s->vsize : s->rawsize;
            if (s->va < g_sizeofimage) {
                if (ssz > g_sizeofimage - s->va) ssz = g_sizeofimage - s->va;
                if (ssz) reg_add(g_imagebase + s->va, ssz, pr, RK_IMAGE, s->name);
            }
        }
        if (s->raw && s->raw + s->rawsize <= g_filesz && s->rawsize)
            vm_poke(g_imagebase + s->va, g_file + s->raw, s->rawsize < s->vsize || !s->vsize ? s->rawsize : s->vsize);
        g_secN++;
    }

    /* 基址重定位：把镜像里的绝对地址按 (实际基址 - 首选基址) 修正。
     * x64 常见的首选基址 0x140000000 被我们在沙盒里改放到低 32 位；若不修正，
     * 样本读到的静态指针仍指向 0x1400xxxxx，一解引用就"越界"（这是本轮 x64 批量
     * 实测里 19 个样本提前停机的主因）。必须在导入表虚拟化之前做：否则写进 IAT
     * 的桩地址会被一起加 delta 弄坏。 */
    {
        u32 rel_rva = 0, rel_size = 0;
        if (g_is64) { rel_rva = rd32(optoff + 112 + 5 * 8); rel_size = rd32(optoff + 112 + 5 * 8 + 4); }
        else        { rel_rva = rd32(optoff + 96 + 5 * 8);  rel_size = rd32(optoff + 96 + 5 * 8 + 4); }
        u64 d64 = (u64)g_imagebase - g_pref_base;          /* 64 位差值（x64 用）*/
        u32 d32 = (u32)(g_imagebase - (u32)g_pref_base);   /* 32 位差值（x86 用）*/
        int need = g_is64 ? (d64 != 0) : (d32 != 0);
        if (need && rel_rva && rel_size && rel_rva < g_sizeofimage) {
            u32 p = g_imagebase + rel_rva, rend = p + rel_size;
            int nfix = 0, nskip = 0;
            while (p + 8 <= rend) {
                u32 page = 0, blk = 0;
                if (!vm_read32(p, &page) || !vm_read32(p + 4, &blk) || blk < 8) break;
                u32 q = p + 8, qe = p + blk;
                if (qe > rend) qe = rend;
                while (q + 2 <= qe) {
                    u16 e = 0; if (!vm_read16(q, &e)) break; q += 2;
                    int type = e >> 12, off = e & 0xFFF;
                    if (type == 0) continue;                       /* ABSOLUTE：填充，跳过 */
                    u32 a = g_imagebase + page + (u32)off;
                    if (a < g_imagebase || a + 8 > g_imagebase + g_sizeofimage) { nskip++; continue; }
                    if (type == 10) {                              /* DIR64 */
                        u64 v = 0; if (vm_read(a, &v, 8)) { v += d64; vm_poke(a, &v, 8); nfix++; }
                    } else if (type == 3) {                        /* HIGHLOW */
                        u32 v = 0; if (vm_read32(a, &v)) { v += d32; vm_poke(a, &v, 4); nfix++; }
                    } else if (type == 1) {                        /* HIGH */
                        u16 v = 0; if (vm_read16(a, &v)) { v = (u16)(v + (u16)(d32 >> 16)); vm_poke(a, &v, 2); nfix++; }
                    } else if (type == 2) {                        /* LOW */
                        u16 v = 0; if (vm_read16(a, &v)) { v = (u16)(v + (u16)d32); vm_poke(a, &v, 2); nfix++; }
                    } else nskip++;                                /* 少见类型：不动 */
                }
                if (blk == 0) break;
                p += blk;
            }
            say("  [重定位] 首选基址 0x%llX -> 沙盒基址 0x%08X：修正 %d 处%s\n",
                (unsigned long long)g_pref_base, g_imagebase, nfix,
                nskip ? "（另有不支持的条目已跳过）" : "");
        }
    }

    /* 导入表虚拟化 */
    u32 imp_rva = 0, imp_size = 0;
    if (g_is64) { imp_rva = rd32(optoff + 112 + 8); imp_size = rd32(optoff + 112 + 12); }
    else        { imp_rva = rd32(optoff + 96 + 8);  imp_size = rd32(optoff + 96 + 12); }
    if (imp_rva && imp_rva < g_sizeofimage) {
        u32 d = g_imagebase + imp_rva;
        for (int k = 0; k < 512; k++) {
            u32 oft = 0, name_rva = 0, ft = 0;
            vm_read32(d + k * 20, &oft);
            vm_read32(d + k * 20 + 12, &name_rva);
            vm_read32(d + k * 20 + 16, &ft);
            if (!name_rva && !oft && !ft) break;
            char dll[56] = {0};
            vm_read(g_imagebase + name_rva, dll, sizeof(dll) - 1);
            u32 thunk = oft ? oft : ft;
            if (!thunk) continue;
            int tstride = g_is64 ? 8 : 4;   /* PE32+ 的 IAT/OFT 每项 8 字节 */
            for (int t = 0; t < 4096; t++) {
                u32 tv = 0;
                if (g_is64) { u64 tv64 = 0; if (!vm_read(g_imagebase + thunk + t * tstride, &tv64, 8) || !tv64) break; tv = (u32)tv64; }
                else { if (!vm_read32(g_imagebase + thunk + t * tstride, &tv) || !tv) break; }
                char nm[64];
                if (tv & 0x80000000u) snprintf(nm, sizeof(nm), "Ordinal_%u", tv & 0xFFFF);
                else { u16 hint = 0; vm_read16(g_imagebase + tv, &hint); vm_read(g_imagebase + tv + 2, nm, sizeof(nm) - 1); nm[sizeof(nm) - 1] = 0; }
                u32 st = is_data_import(nm) ? stub_alloc_ex(dll, nm, data_import_cell()) : stub_alloc(dll, nm);
                if (g_is64) { u64 st64 = (u64)st; vm_poke(g_imagebase + ft + t * tstride, &st64, 8); }
                else vm_poke(g_imagebase + ft + t * tstride, &st, 4);
            }
        }
    }
    g_load_ok = 1;
    return 1;
}

/* ------------------------------------------------------------- 装载视图 --- */
static void print_load_view(const char* path) {
    say("==================================================================\n");
    say(" PE 虚拟装载视图（只解析，不执行）\n");
    say("==================================================================\n");
    say(" 文件      : %s\n", path);
    say(" 大小      : %u 字节\n", g_filesz);
    say(" 位宽      : %s\n", g_is64 ? "PE32+ (64 位)" : "PE32 (32 位)");
    say(" 镜像基址  : 0x%08X\n", g_imagebase);
    say(" 入口 RVA  : 0x%08X\n", g_entry);
    say(" 镜像大小  : 0x%X (%u 字节)\n", g_sizeofimage, g_sizeofimage);
    say(" 节数量    : %d\n", g_secN);
    say(" 虚拟内存  : 已分配 %u 页 (%u MB)\n", g_vm_alloced, g_vm_alloced >> 10);
    say("\n ---- 节 ----\n");
    say("  %-9s %-10s %-10s %-10s %s\n", "名称", "VA", "虚拟大小", "原始大小", "属性");
    for (int i = 0; i < g_secN; i++) {
        sec_t* s = &g_sec[i];
        char pr[8] = "---";
        pr[0] = (s->chars & 0x40000000u) ? 'R' : '-';
        pr[1] = (s->chars & 0x80000000u) ? 'W' : '-';
        pr[2] = (s->chars & 0x20000000u) ? 'X' : '-';
        say("  %-9s 0x%08X 0x%08X 0x%08X %s\n", s->name, s->va, s->vsize, s->rawsize, pr);
    }
    say("\n ---- 导入表（已虚拟化为假 API 桩）----\n");
    int shown = 0;
    for (int i = 0; i < g_impN; i++) {
        if (g_imp[i].stub) { say("  [0x%08X] %s!%s\n", g_imp[i].stub, g_imp[i].dll, g_imp[i].name); shown++; if (shown >= 60) { say("  ...（共 %d 个导入）\n", g_impN); break; } }
    }
    if (g_impN == 0) say("  （无导入表：可能是加壳/动态解析，正是虚拟执行要对付的）\n");
    say("\n 完成。\n");
}

/* ------------------------------------- 释放体还原（纯静态，仍不执行）-------- */
/* 对应火绒文档图 2-6：外层只负责释放/执行内部 PE 的那类样本。
 * 这里做的是"静态释放体还原"：把 overlay / 内嵌 PE 原样抠出来落盘，
 * 交给现有静态引擎复扫，从而把"只看得见外壳"变成"看得见内核"。        */

static double calc_entropy(const u8* d, u32 n) {
    if (!n) return 0.0;
    u32 cnt[256]; memset(cnt, 0, sizeof(cnt));
    for (u32 i = 0; i < n; i++) cnt[d[i]]++;
    double e = 0.0;
    for (int i = 0; i < 256; i++) if (cnt[i]) {
        double p = (double)cnt[i] / (double)n;
        e -= p * (log(p) / log(2.0));
    }
    return e;
}

/* overlay 起点 = 最后一个节 raw 结束（含 SizeOfHeaders 兜底） */
static u32 pe_overlay_off(void) {
    u32 end = g_sizeofheaders;
    for (int i = 0; i < g_secN; i++) {
        u32 e = g_sec[i].raw + g_sec[i].rawsize;
        if (e > end) end = e;
    }
    return end;
}

/* 若 off 处是一个结构自洽的 PE，返回其"自身文件长度"，否则 0 */
static u32 embedded_pe_len(const u8* d, u32 fsz, u32 off) {
    if (off + 0x40 > fsz) return 0;
    if (d[off] != 'M' || d[off + 1] != 'Z') return 0;
    u32 lf = 0; memcpy(&lf, d + off + 0x3C, 4);
    if (lf < 0x40 || off + lf + 24 > fsz) return 0;
    if (memcmp(d + off + lf, "PE\0\0", 4)) return 0;
    u16 nsec = 0, optsz = 0;
    memcpy(&nsec, d + off + lf + 6, 2);
    memcpy(&optsz, d + off + lf + 20, 2);
    if (nsec == 0 || nsec > 96 || optsz < 0x40) return 0;
    u32 soh = 0;
    memcpy(&soh, d + off + lf + 24 + 60, 4);
    u32 end = soh ? soh : 0x400, secoff = off + lf + 24 + optsz;
    for (int i = 0; i < nsec; i++, secoff += 40) {
        if (secoff + 40 > fsz) break;
        u32 raw = 0, rsz = 0;
        memcpy(&rsz, d + secoff + 16, 4);
        memcpy(&raw, d + secoff + 20, 4);
        if ((u64)raw + rsz > (u64)fsz - off) { end = fsz - off; break; }   /* 节越界 -> 抠到文件尾 */
        u32 e = raw + rsz; if (e > end) end = e;
    }
    if (end < 0x200) end = 0x200;
    if ((u64)off + end > fsz) end = fsz - off;
    return end;
}

static int g_blobN = 0;

static void blob_write(const char* outDir, const char* base, const char* kind,
                       u32 off, const u8* d, u32 n) {
    char dir[MAX_PATH];
    char sub[MAX_PATH];
    snprintf(sub, sizeof(sub), "%s_extracted", base);
    snprintf(dir, sizeof(dir), "%s\\%s", outDir, sub);
    CreateDirectoryA(outDir, NULL);
    CreateDirectoryA(dir, NULL);
    char fn[MAX_PATH];
    g_blobN++;
    snprintf(fn, sizeof(fn), "%s\\%02d_%s_off0x%X.bin", dir, g_blobN, kind, off);
    FILE* f = fopen(fn, "wb");
    if (f) { fwrite(d + off, 1, n, f); fclose(f); }
    double e = calc_entropy(d + off, n);
    say("  [释放体 %d] %-14s 偏移 0x%-8X 长度 %-9u 熵 %.2f  -> %s\n", g_blobN, kind, off, n, e, fn);
    tr("PEDROP\t%s\t0x%X\t%u\t%.2f\t%s\n", kind, off, n, e, fn);
}

static void do_extract(const char* samplePath, const char* outDir) {
    say("\n ---- 释放体还原（静态，不执行）----\n");
    const char* base = samplePath;
    for (const char* p = samplePath; *p; p++) if (*p == '\\' || *p == '/') base = p + 1;
    char baseNoExt[MAX_PATH];
    snprintf(baseNoExt, sizeof(baseNoExt), "%s", base);
    char* dot = strrchr(baseNoExt, '.'); if (dot) *dot = 0;

    /* 1) overlay */
    u32 ov = pe_overlay_off();
    if (ov + 0x200 < g_filesz) {
        u32 n = g_filesz - ov;
        double e = calc_entropy(g_file + ov, n);
        say("  overlay  偏移 0x%X 长度 %u  熵 %.2f%s\n", ov, n, e,
            e > 7.2 ? "  ← 高熵，疑似加密载荷/压缩壳" : "");
        blob_write(outDir, baseNoExt, "overlay", ov, g_file, n);
    } else {
        say("  overlay  无（文件尾即最后节结束）\n");
    }

    /* 2) 内嵌 PE：全文件扫 MZ，要求 PE 头自洽 */
    int found = 0;
    for (u32 i = 0; i + 0x40 < g_filesz; i++) {
        if (g_file[i] != 'M' || g_file[i + 1] != 'Z') continue;
        if (i == 0) { i++; continue; }                    /* 跳过自身 */
        u32 len = embedded_pe_len(g_file, g_filesz, i);
        if (!len) { i++; continue; }
        char kind[32];
        int is64 = 0;
        u32 lf = 0; memcpy(&lf, g_file + i + 0x3C, 4);
        u16 magic = 0; memcpy(&magic, g_file + i + lf + 24, 2);
        is64 = (magic == 0x20B);
        snprintf(kind, sizeof(kind), "PE%s", is64 ? "64" : "32");
        blob_write(outDir, baseNoExt, kind, i, g_file, len);
        found++;
        i += len - 1;                                     /* 跳过已抠出的整段 */
    }
    say("  内嵌 PE  : %d 个\n", found);
    say("  合计释放体: %d 个（已落盘，可直接交给 scan.exe 复扫）\n", g_blobN);

    /* 3) 老三样判定 */
    int isdotnet = 0, isdrv = 0;
    for (int i = 0; i < g_impN; i++) if (!_stricmp(g_imp[i].dll, "mscoree.dll")) isdotnet = 1;
    if (g_secN > 0 && !_stricmp(g_sec[0].name, "INIT")) isdrv = 1;
    say("  形态提示 : %s%s%s\n",
        isdotnet ? ".NET 程序集（x86 解释器不适用，需按 IL 静态/仿真分析） " : "",
        g_is64 ? "64 位（需 x64 解释器）" : "",
        isdrv ? " 驱动(INIT 节，建议配合驱动专用规则)" : "");
}

/* ==================== 阶段二：x86-32 解释器（解壳常用指令集）================
 * 执行模型：fetch-decode-execute，全部在虚拟内存上；EIP 落到"假 API 桩"就转
 * 交给 api_dispatch()。任何一步越界/未实现指令都会安全停机并如实报告。
 * 目标：跑通常见自解壳 stub，检测"写后执行"定位 OEP，dump 出真正的载荷。
 * ========================================================================= */
static u32 R[8];                 /* EAX ECX EDX EBX ESP EBP ESI EDI */
#define EAX R[0]
#define ECX R[1]
#define EDX R[2]
#define EBX R[3]
#define ESP R[4]
#define EBP R[5]
#define ESI R[6]
#define EDI R[7]
static u32 EIP = 0, EFLAGS = 0;
static u32 g_fsbase = 0, g_gsbase = 0;
static int g_halted = 0;
static int g_opsz16 = 0;          /* 0x66 前缀 */
static int g_segovr = -1;         /* 1=FS 2=GS 0=其它段(忽略) */
static int g_rep = 0;             /* 0 无 / 1 rep / 2 repne */
static int g_fault = 0;
static char g_stop_reason[160] = "正常退出";
static int g_backtrace_budget = 0;

#define CF 0x0001u
#define PF 0x0004u
#define AF 0x0010u
#define ZF 0x0040u
#define SF 0x0080u
#define IF 0x0200u
#define DF 0x0400u
#define OF 0x0800u
#define EXIT_MAGIC 0x7FFFFFF0u

static int api_dispatch(void);          /* 前向声明 */
static int g_unk_total;                   /* 定义在 API 表之后：未登记 nargs 的 API 计数 */
static const char* unk_api_hint(void);    /* 前向声明 */
static void blog(const char* kind, const char* fmt, ...);   /* 前向声明 */

static void push32(u32 v) { ESP -= 4; vm_write32(ESP, v); }
static u32  pop32(void)   { u32 v = 0; vm_read32(ESP, &v); ESP += 4; return v; }

static void push_val(u32 v, int size) { if (size == 2) { ESP -= 2; vm_write16(ESP, (u16)v); } else push32(v); }
static u32  pop_val(int size) { if (size == 2) { u16 w = 0; vm_read16(ESP, &w); ESP += 2; return w; } return pop32(); }

/* ---- 取指 ---- */
static u8 next8(void) {
    u8 b = 0;
    if (!vm_read8(EIP, &b)) { g_fault = 1; return 0; }
    EIP++;
    return b;
}
static u32 next32(void) {
    u32 v = 0;
    if (!vm_read32(EIP, &v)) { g_fault = 1; return 0; }
    EIP += 4;
    return v;
}
static u32 peek32(u32 a) { u32 v = 0; vm_read32(a, &v); return v; }
/* 取一小段十六进制字节，用于"未实现指令"的诊断输出 */
static const char* hex_at(u32 addr, int n) {
    static char buf[64];
    int o = 0;
    for (int k = 0; k < n && o < (int)sizeof(buf) - 4; k++) {
        u8 b = 0;
        if (!vm_read8(addr + k, &b)) { o += snprintf(buf + o, sizeof(buf) - o, "?? "); continue; }
        o += snprintf(buf + o, sizeof(buf) - o, "%02X ", b);
    }
    buf[o] = 0;
    return buf;
}

/* ---- ModRM / SIB ---- */
typedef struct { int is_mem; int reg; int rm_reg; u32 addr; int size; int seg; } modrm_t;
static u32 seg_base(int s) { if (s == 1) return g_fsbase; if (s == 2) return g_gsbase; return 0; }

static void dec_modrm(modrm_t* m, int size) {
    u8 b = next8();
    int mod = b >> 6, reg = (b >> 3) & 7, rm = b & 7;
    m->is_mem = 0; m->reg = reg; m->rm_reg = rm; m->size = size; m->seg = g_segovr; m->addr = 0;
    if (mod == 3) return;    /* 寄存器直接寻址：m 代表 r/m 域（rm_reg） */
    m->is_mem = 1;
    u32 addr = 0;
    if (rm == 4) {
        u8 sib = next8();
        int ss = sib >> 6, idx = (sib >> 3) & 7, base = sib & 7;
        u32 index = (idx == 4) ? 0 : R[idx];
        addr = (base == 5 && mod == 0) ? next32() : R[base];
        addr += index << ss;
    } else if (rm == 5 && mod == 0) {
        addr = next32();
    } else {
        addr = R[rm];
    }
    if (mod == 1) addr += (u32)(s32)(s8)next8();
    else if (mod == 2) addr += next32();
    m->addr = seg_base(g_segovr) + addr;
}
static u32 op_read(modrm_t* m) {
    if (!m->is_mem) {
        if (m->size == 1) return R[m->rm_reg] & 0xFF;
        if (m->size == 2) return R[m->rm_reg] & 0xFFFF;
        return R[m->rm_reg];
    }
    if (m->size == 1) { u8 v = 0; if (!vm_read8(m->addr, &v)) { g_fault = 1; return 0; } return v; }
    if (m->size == 2) { u16 v = 0; if (!vm_read16(m->addr, &v)) { g_fault = 1; return 0; } return v; }
    { u32 v = 0; if (!vm_read32(m->addr, &v)) { g_fault = 1; return 0; } return v; }
}
static void op_write(modrm_t* m, u32 v) {
    if (!m->is_mem) {
        if (m->size == 1) R[m->rm_reg] = (R[m->rm_reg] & ~0xFFu) | (v & 0xFF);
        else if (m->size == 2) R[m->rm_reg] = (R[m->rm_reg] & ~0xFFFFu) | (v & 0xFFFF);
        else R[m->rm_reg] = v;
        return;
    }
    if (m->size == 1) { if (!vm_write8(m->addr, (u8)v)) g_fault = 1; }
    else if (m->size == 2) { if (!vm_write16(m->addr, (u16)v)) g_fault = 1; }
    else { if (!vm_write32(m->addr, v)) g_fault = 1; }
    reg_mark_written(m->addr, m->size);
}

/* ---- 标志位 ---- */
static u32 szmask(int sz) { return sz == 1 ? 0xFFu : (sz == 2 ? 0xFFFFu : 0xFFFFFFFFu); }
static u32 msb(int sz) { return sz == 1 ? 0x80u : (sz == 2 ? 0x8000u : 0x80000000u); }
static void set_pzs(u32 r, int sz) {
    u32 mask = szmask(sz);
    r &= mask;
    EFLAGS &= ~(ZF | SF | PF);
    if (r == 0) EFLAGS |= ZF;
    if (r & msb(sz)) EFLAGS |= SF;
    if (__builtin_parity(r & 0xFF) == 0) EFLAGS |= PF;
}
static void flags_add(u32 a, u32 b, u32 r, int sz) {
    u32 mask = szmask(sz);
    a &= mask; b &= mask;
    u64 s = (u64)a + (u64)b;
    EFLAGS &= ~(CF | OF | AF);
    if (s > mask) EFLAGS |= CF;
    if (((a ^ (u32)s) & (b ^ (u32)s)) & msb(sz)) EFLAGS |= OF;
    if (((a ^ b ^ (u32)s) & 0x10)) EFLAGS |= AF;
    set_pzs((u32)s, sz);
}
static void flags_sub(u32 a, u32 b, u32 r, int sz) {
    u32 mask = szmask(sz);
    a &= mask; b &= mask;
    EFLAGS &= ~(CF | OF | AF);
    if (a < b) EFLAGS |= CF;
    if (((a ^ b) & (a ^ r)) & msb(sz)) EFLAGS |= OF;
    if (((a ^ b ^ r) & 0x10)) EFLAGS |= AF;
    set_pzs(r, sz);
}
static void flags_logic(u32 r, int sz) { EFLAGS &= ~(CF | OF | AF); set_pzs(r, sz); }

/* ---- 条件码 ---- */
static int cond(int cc) {
    int cf = (EFLAGS & CF) != 0, zf = (EFLAGS & ZF) != 0, sf = (EFLAGS & SF) != 0, of = (EFLAGS & OF) != 0, pf = (EFLAGS & PF) != 0;
    switch (cc) {
        case 0x0: return of;            case 0x1: return !of;
        case 0x2: return cf;            case 0x3: return !cf;
        case 0x4: return zf;            case 0x5: return !zf;
        case 0x6: return cf || zf;      case 0x7: return !cf && !zf;
        case 0x8: return sf;            case 0x9: return !sf;
        case 0xA: return pf;            case 0xB: return !pf;
        case 0xC: return sf != of;      case 0xD: return sf == of;
        case 0xE: return zf || (sf != of); case 0xF: return !zf && (sf == of);
    }
    return 0;
}

/* 记录"写后执行"可疑点 */
static u32 g_oep_candidate = 0;
static int g_oep_hits = 0;
static void note_exec(u32 addr) {
    u32 pg = addr >> PG_SHIFT;
    if (pg >= PG_COUNT || !g_pg[pg].p) return;
    if (g_pg[pg].written && (g_pg[pg].prot & P_X)) {
        if (g_oep_candidate != (addr & ~(PG_SIZE - 1))) {
            g_oep_candidate = addr & ~(PG_SIZE - 1);
            g_oep_hits++;
            say("  [疑似 OEP] 执行流进入 0x%08X —— 该页先前被写过、现已可执行（写后执行/解壳完成）\n", addr);
            tr("OEP\t0x%X\t0x%X\n", addr, addr & ~(PG_SIZE - 1));
        }
    }
}

/* ---------------- 最简 x87（FPU）：只为让解码/执行不被打断 ----------------
 * 8 层栈 + 常见存取/算术；无法模拟的编码按空操作处理并记日志（不中断执行）。 */
static double g_fpu[8];
static int    g_ftop = 0;
static void   fpu_push(double v) { g_ftop = (g_ftop + 7) & 7; g_fpu[g_ftop] = v; }
static double fpu_pop(void) { double v = g_fpu[g_ftop]; g_ftop = (g_ftop + 1) & 7; return v; }
static double fpu_st(int i) { return g_fpu[(g_ftop + i) & 7]; }
static void   fpu_set(int i, double v) { g_fpu[(g_ftop + i) & 7] = v; }

static double ld_real(u32 a, int sz) {
    if (sz == 4) { u32 b = 0; vm_read32(a, &b); float f; memcpy(&f, &b, 4); return (double)f; }
    if (sz == 8) { u64 b = 0; vm_read(a, &b, 8); double d; memcpy(&d, &b, 8); return d; }
    if (sz == 2) { s16 w = 0; u16 t = 0; if (vm_read16(a, &t)) { memcpy(&w, &t, 2); return (double)w; } return 0; }
    { s32 d = 0; u32 t = 0; if (vm_read32(a, &t)) { memcpy(&d, &t, 4); return (double)d; } return 0; }
}
static void st_real(u32 a, int sz, double v, int as_int) {
    if (sz == 4) { u32 b; if (as_int) { s32 q = (s32)v; b = (u32)q; } else { float f = (float)v; memcpy(&b, &f, 4); } vm_write32(a, b); }
    else if (sz == 8) { u64 b; if (as_int) { s64 q = (s64)v; b = (u64)q; } else { memcpy(&b, &v, 8); } vm_write(a, &b, 8); }
    else if (sz == 2) { u16 b; if (as_int) { s16 q = (s16)v; b = (u16)q; } else b = 0; vm_write16(a, b); }
}

static int do_x87(u8 op, int opsz) {
    u8 mrm = 0;
    if (!vm_read8(EIP, &mrm)) { g_fault = 1; return 0; }
    int mod = mrm >> 6, reg = (mrm >> 3) & 7, rm = mrm & 7;
    (void)opsz;
    if (mod == 3) {
        EIP++;
        switch (op) {
        case 0xD8:
            switch (reg) {
            case 0: fpu_set(0, fpu_st(0) + fpu_st(rm)); break;
            case 1: fpu_set(0, fpu_st(0) * fpu_st(rm)); break;
            case 2: case 3: if (reg == 3) fpu_pop(); break;
            case 4: fpu_set(0, fpu_st(0) - fpu_st(rm)); break;
            case 5: fpu_set(0, fpu_st(rm) - fpu_st(0)); break;
            case 6: fpu_set(0, fpu_st(0) / fpu_st(rm)); break;
            case 7: fpu_set(0, fpu_st(rm) / fpu_st(0)); break;
            }
            return 1;
        case 0xD9:
            if (mrm >= 0xC0 && mrm <= 0xC7) { fpu_push(fpu_st(rm)); return 1; }
            if (mrm >= 0xC8 && mrm <= 0xCF) { double t = fpu_st(0); fpu_set(0, fpu_st(rm)); fpu_set(rm, t); return 1; }
            switch (mrm) {
            case 0xD0: return 1;                                  /* fnop */
            case 0xE0: fpu_set(0, -fpu_st(0)); return 1;           /* fchs */
            case 0xE1: fpu_set(0, fabs(fpu_st(0))); return 1;      /* fabs */
            case 0xE4: case 0xE5: return 1;                       /* ftst/fxam */
            case 0xE8: fpu_push(1.0); return 1;                   /* fld1 */
            case 0xEA: fpu_push(1.4426950408889634); return 1;    /* fldl2e */
            case 0xEB: fpu_push(3.141592653589793); return 1;     /* fldpi */
            case 0xEC: fpu_push(0.3010299956639812); return 1;    /* fldlg2 */
            case 0xED: fpu_push(0.6931471805599453); return 1;    /* fldln2 */
            case 0xEE: fpu_push(0.0); return 1;                   /* fldz */
            case 0xF0: break;                                     /* f2xm1（按空操作） */
            case 0xF1: { double y = fpu_pop(); fpu_set(0, log(fpu_st(0) < 0 ? 0.0000001 : fpu_st(0)) * y); return 1; }  /* fyl2x */
            case 0xFA: fpu_set(0, sqrt(fpu_st(0) < 0 ? 0 : fpu_st(0))); return 1;
            case 0xFE: fpu_set(0, sin(fpu_st(0))); return 1;
            case 0xFF: fpu_set(0, cos(fpu_st(0))); return 1;
            default: blog("x87", "未模拟的 0xD9 %02X（按空操作）", mrm); return 1;
            }
            return 1;
        case 0xDA:
            if (mrm >= 0xC0 && mrm <= 0xDF) {  /* fcmovb/e/be/u */
                int take = (mrm >= 0xC0 && mrm <= 0xC7) || (mrm >= 0xD0 && mrm <= 0xD7);
                if (take) fpu_set(0, fpu_st(rm));
                return 1;
            }
            if (mrm == 0xE9) { fpu_pop(); fpu_pop(); return 1; }   /* fucompp */
            return 1;
        case 0xDB:
            if (mrm >= 0xC0 && mrm <= 0xDF) { /* fcmovnb/e/... */ return 1; }
            if (mrm == 0xE2) return 1;                             /* fnclex */
            if (mrm == 0xE3) { g_ftop = 0; return 1; }              /* fninit */
            return 1;
        case 0xDC:
            switch (reg) {
            case 0: fpu_set(rm, fpu_st(rm) + fpu_st(0)); break;
            case 1: fpu_set(rm, fpu_st(rm) * fpu_st(0)); break;
            case 4: fpu_set(rm, fpu_st(rm) - fpu_st(0)); break;
            case 5: fpu_set(rm, fpu_st(0) - fpu_st(rm)); break;
            case 6: fpu_set(rm, fpu_st(rm) / fpu_st(0)); break;
            case 7: fpu_set(rm, fpu_st(0) / fpu_st(rm)); break;
            default: break;
            }
            return 1;
        case 0xDD:
            if (reg == 0) { fpu_pop(); return 1; }                  /* ffree */
            if (reg == 2) { fpu_set(rm, fpu_st(0)); return 1; }     /* fst sti */
            if (reg == 3) { fpu_set(rm, fpu_st(0)); fpu_pop(); return 1; }
            return 1;
        case 0xDE:
            if (mrm == 0xD9) { fpu_pop(); fpu_pop(); return 1; }    /* fcompp */
            if (reg == 0) { double v = fpu_pop(); fpu_set(0, fpu_st(0) + v); return 1; }
            if (reg == 1) { double v = fpu_pop(); fpu_set(0, fpu_st(0) * v); return 1; }
            if (reg == 4) { double v = fpu_pop(); fpu_set(0, fpu_st(0) - v); return 1; }
            if (reg == 5) { double v = fpu_pop(); fpu_set(0, v - fpu_st(0)); return 1; }
            if (reg == 6) { double v = fpu_pop(); fpu_set(0, fpu_st(0) / v); return 1; }
            if (reg == 7) { double v = fpu_pop(); fpu_set(0, v / fpu_st(0)); return 1; }
            return 1;
        case 0xDF:
            if (mrm == 0xE0) { EAX = (EAX & 0xFFFF0000u) | 0; return 1; }   /* fnstsw ax */
            if (mrm >= 0xE8 && mrm <= 0xEF) { double v = fpu_pop(); (void)v; return 1; }  /* fucomip */
            return 1;
        }
        return 1;
    }
    /* ---- 内存形式 ---- */
    int memsz = 4, as_int = 0;
    if (op == 0xD8 || op == 0xD9 || op == 0xDA) memsz = 4;
    else if (op == 0xDC || op == 0xDD) memsz = 8;
    else if (op == 0xDE) { memsz = 2; as_int = 1; }
    else if (op == 0xDB) { memsz = (reg == 5 || reg == 7) ? 10 : 4; as_int = 1; }
    else if (op == 0xDF) { memsz = (reg == 5 || reg == 7) ? 8 : ((reg == 4 || reg == 6) ? 10 : 2); as_int = 1; }
    modrm_t m; dec_modrm(&m, memsz == 2 ? 2 : (memsz == 8 ? 4 : 4));
    (void)as_int;
    double v = ld_real(m.addr, memsz);
    int pop = 0;
    switch (op) {
    case 0xD8: case 0xDC:                                     /* m32real / m64real 算术 */
        switch (reg) {
        case 0: fpu_set(0, fpu_st(0) + v); break;
        case 1: fpu_set(0, fpu_st(0) * v); break;
        case 2: case 3: if (reg == 3) pop = 1; break;
        case 4: fpu_set(0, fpu_st(0) - v); break;
        case 5: fpu_set(0, v - fpu_st(0)); break;
        case 6: fpu_set(0, fpu_st(0) / v); break;
        case 7: fpu_set(0, v / fpu_st(0)); break;
        }
        break;
    case 0xDA: case 0xDE:                                     /* 整数算术 */
        switch (reg) {
        case 0: fpu_set(0, fpu_st(0) + v); break;
        case 1: fpu_set(0, fpu_st(0) * v); break;
        case 2: case 3: if (reg == 3) pop = 1; break;
        case 4: fpu_set(0, fpu_st(0) - v); break;
        case 5: fpu_set(0, v - fpu_st(0)); break;
        case 6: fpu_set(0, fpu_st(0) / v); break;
        case 7: fpu_set(0, v / fpu_st(0)); break;
        }
        break;
    case 0xD9:
        if (reg == 0) fpu_push(v);
        else if (reg == 2) st_real(m.addr, memsz, fpu_st(0), 0);
        else if (reg == 3) { st_real(m.addr, memsz, fpu_st(0), 0); pop = 1; }
        else if (reg == 5 || reg == 7) { u16 cw = (reg == 7) ? 0x037F : 0; if (reg == 7) vm_write16(m.addr, cw); }
        break;
    case 0xDB:
        if (reg == 0) fpu_push(v);
        else if (reg == 1) { st_real(m.addr, 4, fpu_st(0), 1); pop = 1; }
        else if (reg == 2) st_real(m.addr, 4, fpu_st(0), 1);
        else if (reg == 3) { st_real(m.addr, 4, fpu_st(0), 1); pop = 1; }
        else if (reg == 7) pop = 1;
        break;
    case 0xDD:
        if (reg == 0) fpu_push(v);
        else if (reg == 1) { st_real(m.addr, 8, fpu_st(0), 1); pop = 1; }
        else if (reg == 2) st_real(m.addr, 8, fpu_st(0), 1);
        else if (reg == 3) { st_real(m.addr, 8, fpu_st(0), 1); pop = 1; }
        else if (reg == 7) vm_write16(m.addr, 0);
        break;
    case 0xDF:
        if (reg == 0) fpu_push(v);
        else if (reg == 1) { st_real(m.addr, memsz, fpu_st(0), 1); pop = 1; }
        else if (reg == 2) st_real(m.addr, memsz, fpu_st(0), 1);
        else if (reg == 3) { st_real(m.addr, memsz, fpu_st(0), 1); pop = 1; }
        else if (reg == 5) fpu_push(v);
        else if (reg == 7) { st_real(m.addr, 8, fpu_st(0), 1); pop = 1; }
        break;
    default: break;
    }
    if (pop) fpu_pop();
    return 1;
}

/* ---------------- 最小 SSE（XMM）：覆盖编译器/packer 常用成套指令 ---------------- */
static u8 g_xmm[8][16];
static void xmm_get(modrm_t* m, u8* out, int n, int high8) {
    memset(out, 0, 16);
    if (!m->is_mem) { if (n <= 4 || high8 == 0) memcpy(out, g_xmm[m->rm_reg], n <= 8 ? n : 16); else memcpy(out, g_xmm[m->rm_reg] + 8, 8); return; }
    u32 a = m->addr + (high8 ? 8 : 0);
    if (!vm_read(a, out, n)) vm_read(a, out, 4);
}
static void xmm_put(modrm_t* m, const u8* in, int n, int high8) {
    if (!m->is_mem) { memcpy(g_xmm[m->rm_reg] + (high8 ? 8 : 0), in, n); return; }
    u32 a = m->addr + (high8 ? 8 : 0);
    vm_write(a, in, n);
}
static void ps_arith(int reg, const u8* b, int kind) {
    float x[4], y[4];
    memcpy(x, g_xmm[reg], 16); memcpy(y, b, 16);
    for (int i = 0; i < 4; i++) {
        if (kind == 0) x[i] += y[i];
        else if (kind == 1) x[i] *= y[i];
        else if (kind == 2) x[i] -= y[i];
        else x[i] /= y[i];
    }
    memcpy(g_xmm[reg], x, 16);
}
static int do_sse(u8 op2, int pfx) {   /* pfx: 0 无, 1=66, 2=F2, 3=F3 */
    modrm_t m; dec_modrm(&m, 4);
    u8 t[16];
    switch (op2) {
    case 0x10: case 0x11: {   /* movups / movss / movsd */
        int n = (pfx == 3 || pfx == 2) ? 4 : 16;
        if (op2 == 0x10) { xmm_get(&m, t, n, 0); memcpy(g_xmm[m.reg], t, 16); }
        else { xmm_put(&m, g_xmm[m.reg], n, 0); }
        return 1;
    }
    case 0x28: case 0x29: {   /* movaps / movapd */
        if (op2 == 0x28) { xmm_get(&m, t, 16, 0); memcpy(g_xmm[m.reg], t, 16); }
        else xmm_put(&m, g_xmm[m.reg], 16, 0);
        return 1;
    }
    case 0x6F: case 0x7F: {   /* movdqa / movdqu */
        if (op2 == 0x6F) { xmm_get(&m, t, 16, 0); memcpy(g_xmm[m.reg], t, 16); }
        else xmm_put(&m, g_xmm[m.reg], 16, 0);
        return 1;
    }
    case 0x6E: {              /* movd/movq xmm, r/m */
        int n = (pfx == 1) ? 8 : 4;
        xmm_get(&m, t, n, 0);
        memset(g_xmm[m.reg], 0, 16);
        memcpy(g_xmm[m.reg], t, n);
        return 1;
    }
    case 0x7E: {              /* movd/movq r/m, xmm */
        int n = (pfx == 1) ? 8 : 4;
        xmm_put(&m, g_xmm[m.reg], n, 0);
        return 1;
    }
    case 0xD6: {              /* movq m64, xmm */
        xmm_put(&m, g_xmm[m.reg], 8, 0);
        return 1;
    }
    case 0x12: case 0x13: {   /* movlps */
        if (op2 == 0x12) { xmm_get(&m, t, 8, 0); memset(g_xmm[m.reg], 0, 16); memcpy(g_xmm[m.reg], t, 8); }
        else xmm_put(&m, g_xmm[m.reg], 8, 0);
        return 1;
    }
    case 0x16: case 0x17: {   /* movhps */
        if (op2 == 0x16) { xmm_get(&m, t, 8, 0); memcpy(g_xmm[m.reg] + 8, t, 8); }
        else xmm_put(&m, g_xmm[m.reg], 8, 1);
        return 1;
    }
    case 0x54: case 0x55: case 0x56: case 0x57: {   /* andps/nandps/orps/xorps 或 pd 位运算 */
        xmm_get(&m, t, 16, 0);
        for (int i = 0; i < 16; i++) {
            if (op2 == 0x54) g_xmm[m.reg][i] &= t[i];
            else if (op2 == 0x55) g_xmm[m.reg][i] = (u8)(~(g_xmm[m.reg][i] & t[i]));
            else if (op2 == 0x56) g_xmm[m.reg][i] |= t[i];
            else g_xmm[m.reg][i] ^= t[i];
        }
        return 1;
    }
    case 0xEF: case 0xEE: case 0xFE: case 0xFA: case 0xFC: {   /* pxor/padd/paddd/psub/... 整数按位同样处理 */
        xmm_get(&m, t, 16, 0);
        for (int i = 0; i < 16; i++) {
            if (op2 == 0xEF) g_xmm[m.reg][i] ^= t[i];
            else if (op2 == 0xEE) { int s = g_xmm[m.reg][i] + t[i]; g_xmm[m.reg][i] = (u8)s; }
            else if (op2 == 0xFE) { int s = g_xmm[m.reg][i] + t[i]; g_xmm[m.reg][i] = (u8)s; }
            else if (op2 == 0xFA) { int s = g_xmm[m.reg][i] - t[i]; g_xmm[m.reg][i] = (u8)s; }
            else { int s = g_xmm[m.reg][i] - t[i]; g_xmm[m.reg][i] = (u8)s; }
        }
        return 1;
    }
    case 0x58: case 0x59: case 0x5C: case 0x5E: {   /* addps/mulps/subps/divps 系列 */
        xmm_get(&m, t, 16, 0);
        ps_arith(m.reg, t, op2 == 0x58 ? 0 : (op2 == 0x59 ? 1 : (op2 == 0x5C ? 2 : 3)));
        return 1;
    }
    case 0x51: {   /* sqrtps / sqrtsd */
        xmm_get(&m, t, 16, 0);
        float x[4]; memcpy(x, g_xmm[m.reg], 16);
        for (int i = 0; i < 4; i++) x[i] = (float)sqrt(x[i] < 0 ? 0 : x[i]);
        memcpy(g_xmm[m.reg], x, 16);
        return 1;
    }
    case 0x14: case 0x15: {   /* unpcklps / unpckhps */
        xmm_get(&m, t, 16, 0);
        float a[4], b[4], r[4];
        memcpy(a, g_xmm[m.reg], 16); memcpy(b, t, 16);
        if (op2 == 0x14) { r[0] = a[0]; r[1] = b[0]; r[2] = a[1]; r[3] = b[1]; }
        else { r[0] = a[2]; r[1] = b[2]; r[2] = a[3]; r[3] = b[3]; }
        memcpy(g_xmm[m.reg], r, 16);
        return 1;
    }
    case 0x50: {   /* movmskps */
        xmm_get(&m, t, 16, 0);
        u32 msk = 0; for (int i = 0; i < 4; i++) { float f; memcpy(&f, t + i * 4, 4); if (f < 0) msk |= (1u << i); }
        EAX = msk;
        return 1;
    }
    case 0x2E: case 0x2F: {   /* ucomiss/comiss */
        xmm_get(&m, t, 16, 0);
        float a, b; memcpy(&a, g_xmm[m.reg], 4); memcpy(&b, t, 4);
        EFLAGS &= ~(CF | PF | ZF | OF | SF | AF);
        if (a != a || b != b) EFLAGS |= ZF | PF | CF;
        else if (a > b) { }
        else if (a < b) EFLAGS |= CF;
        else EFLAGS |= ZF;
        return 1;
    }
    case 0x2A: {   /* cvtsi2ss / cvtsi2sd */
        u32 iv = 0; int sz = (pfx == 3) ? 4 : 4;
        if (!m.is_mem) iv = R[m.rm_reg];
        else if (!vm_read(m.addr, &iv, sz)) iv = 0;
        if (pfx == 2) { double d = (double)(s32)iv; memcpy(g_xmm[m.reg], &d, 8); memset(g_xmm[m.reg] + 8, 0, 8); }
        else { float f = (float)(s32)iv; memcpy(g_xmm[m.reg], &f, 4); memset(g_xmm[m.reg] + 4, 0, 12); }
        return 1;
    }
    case 0x2C: case 0x2D: {   /* cvttss2si / cvtss2si */
        xmm_get(&m, t, 16, 0);
        if (pfx == 3) { float f; memcpy(&f, t, 4); EAX = (u32)(s32)f; }
        else { double d; memcpy(&d, t, 8); EAX = (u32)(s32)d; }
        return 1;
    }
    case 0x5B: {   /* cvtdq2ps / cvttps2dq */
        xmm_get(&m, t, 16, 0);
        if (pfx == 1) { float x[4]; memcpy(x, g_xmm[m.reg], 16); s32 r[4]; for (int i = 0; i < 4; i++) r[i] = (s32)x[i]; memcpy(g_xmm[m.reg], r, 16); }
        else { s32 iv[4]; memcpy(iv, g_xmm[m.reg], 16); float x[4]; for (int i = 0; i < 4; i++) x[i] = (float)iv[i]; memcpy(g_xmm[m.reg], x, 16); }
        return 1;
    }
    case 0xC6: {   /* shufps / shufpd */
        u8 imm = next8();
        xmm_get(&m, t, 16, 0);
        float a[4], b[4], r[4];
        memcpy(a, g_xmm[m.reg], 16); memcpy(b, t, 16);
        int i0 = imm & 3, i1 = (imm >> 2) & 3, i2 = (imm >> 4) & 3, i3 = (imm >> 6) & 3;
        r[0] = a[i0]; r[1] = a[i1]; r[2] = b[i2]; r[3] = b[i3];
        memcpy(g_xmm[m.reg], r, 16);
        return 1;
    }
    case 0x70: {   /* pshufd / pshuflw / pshufhw */
        u8 imm = next8();
        u32 v[4]; memcpy(v, g_xmm[m.reg], 16);
        u32 r[4] = { v[imm & 3], v[(imm >> 2) & 3], v[(imm >> 4) & 3], v[(imm >> 6) & 3] };
        memcpy(g_xmm[m.reg], r, 16);
        return 1;
    }
    case 0x5A: {   /* cvtps2pd / cvtpd2ps */
        xmm_get(&m, t, 16, 0);
        if (pfx == 1) { double d[2]; memcpy(d, g_xmm[m.reg], 16); float f[2] = { (float)d[0], (float)d[1] }; memset(g_xmm[m.reg], 0, 16); memcpy(g_xmm[m.reg], f, 8); }
        else { float f[2]; memcpy(f, g_xmm[m.reg], 8); double d[2] = { (double)f[0], (double)f[1] }; memcpy(g_xmm[m.reg], d, 16); }
        return 1;
    }
    default:
        blog("SSE", "未模拟的 0F %02X（前缀 %d，按空操作）", op2, pfx);
        return 1;
    }
    return 1;
}

/* ---- 一个指令周期 ---- */
 /* 提前声明 step 和支撑函数，解决调用顺序问题 */
static int step(void);

/* ==================== 新增的支撑函数（黑匣子 + TLS） ==================== */

#define XLAST32 64
static struct { u32 eip; u8 b[10]; } g_last32[XLAST32];
static long g_lastn32 = 0;

static void x32_last_rec(u32 eip) {
    int i = (int)(g_lastn32 % XLAST32);
    g_last32[i].eip = eip;
    for (int k = 0; k < 10; k++) { u8 v = 0; g_last32[i].b[k] = vm_read8(eip + (u32)k, &v) ? v : 0; }
    g_lastn32++;
}

static void x32_dump_last(int cnt) {
    if (cnt > XLAST32) cnt = XLAST32;
    if (g_lastn32 < cnt) cnt = (int)g_lastn32;
    if (cnt <= 0) return;
    say("  最近 %d 条指令（由旧到新）：\n", cnt);
    for (int i = 0; i < cnt; i++) {
        long idx = (g_lastn32 - cnt + i) % XLAST32;
        char hex[40]; int k = 0;
        for (int j = 0; j < 10; j++) k += snprintf(hex + k, sizeof(hex) - (size_t)k, "%02X ", g_last32[idx].b[j]);
        say("    [%06ld] %08X  %s\n", g_lastn32 - cnt + i, g_last32[idx].eip, hex);
    }
    say("  EAX=%08X ECX=%08X EDX=%08X EBX=%08X ESP=%08X EBP=%08X ESI=%08X EDI=%08X\n",
        EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI);
    say("  EFLAGS=%08X  栈顶 8 项：", EFLAGS);
    for (int i = 0; i < 8; i++) {
        u32 v = 0;
        if (vm_read32(ESP + i * 4, &v)) say(" %08X", v); else { say(" ??"); break; }
    }
    say("\n");
}

static int run_tls_callbacks(void) {
    u32 tls_rva = 0;
    u32 lfanew = rd32(0x3C);
    u32 optoff = lfanew + 24;
    
    if (g_is64) { tls_rva = rd32(optoff + 112 + 9 * 8); }
    else        { tls_rva = rd32(optoff + 96 + 9 * 8); }
    
    if (!tls_rva || tls_rva >= g_sizeofimage) return 0;

    u32 tls_dir = g_imagebase + tls_rva;
    u32 cb_array = 0;
    if (g_is64) vm_read32(tls_dir + 24, &cb_array);
    else        vm_read32(tls_dir + 12, &cb_array);
    
    if (!cb_array) return 0;

    say("  [TLS] ★发现并执行 TLS 回调链 @0x%08X\n", cb_array);
    int n = 0;
    for (int i = 0; i < 64; i++) {
        u32 cb = 0;
        if (!vm_read32(cb_array + i * 4, &cb) || !cb) break;
        say("    [TLS] 回调 #%d = 0x%08X\n", i, cb);

        push32(EXIT_MAGIC);           
        push32(0);                    
        push32(1);                    
        push32(g_imagebase);          

        EIP = cb;
        g_halted = 0;
        long base = g_insn;
        while (!g_halted && g_insn - base < 1000000L) {
            if (!step()) break;
            g_insn++;
        }
        say("    [TLS] 回调 #%d 结束：%s（%ld 条指令）\n", i, g_stop_reason, g_insn - base);
        n++;
        g_halted = 0;
    }
    return n;
}

/* ==================== 支撑函数结束 ==================== */
static int step(void) {
    // --- 1. 拦截绝对的 0 地址 ---
    if (EIP == 0) {
        say("  [防崩溃] ★拦截执行 0x00 空指针！\n");
        snprintf(g_stop_reason, sizeof(g_stop_reason), "执行到 0x00 空指针（多为假 API 返回空/样本自身空指针，无法定论）");
        g_halted = 1;
        return 0;
    }

    /* --- 删除了 0x00406B35 的硬编码拦截 --- */

    if (g_halted) return 0;
            
    x32_last_rec(EIP);  /* ★ 加上黑匣子记录 */

    /* 落到假 API 桩 -> 交给虚拟 API */
    if (g_insn < g_insn_print) say("    [%06ld] %08X  %s\n", g_insn, EIP, hex_at(EIP, 10));

    g_fault = 0;   /* 每步复位：一次越界访问不污染后续判定 */

    /* 落到假 API 桩 -> 交给虚拟 API（必须在解码之前拦，否则会被当成 C3=ret 直接跑掉，栈也跟着错位）*/
    if (stub_lookup(EIP)) { if (!api_dispatch()) return 0; return 1; }

    note_exec(EIP);

    g_opsz16 = 0; g_segovr = -1; g_rep = 0;
    /* 前缀 */
    for (;;) {
        u8 p = peek32(EIP) & 0xFF;
        if (p == 0x66) { g_opsz16 = 1; EIP++; }
        else if (p == 0x67) { EIP++; }                   /* 地址尺寸前缀：忽略（极少见） */
        else if (p == 0xF0) { EIP++; }                   /* lock */
        else if (p == 0xF2) { g_rep = 2; EIP++; }
        else if (p == 0xF3) { g_rep = 1; EIP++; }
        else if (p == 0x64) { g_segovr = 1; EIP++; }
        else if (p == 0x65) { g_segovr = 2; EIP++; }
        else if (p == 0x2E || p == 0x36 || p == 0x3E || p == 0x26) { g_segovr = 0; EIP++; }
        else break;
    }
    int opsz = g_opsz16 ? 2 : 4;

    u8 op = next8();
    if (g_fault) {
        if (g_unk_total) snprintf(g_stop_reason, sizeof(g_stop_reason),
            "取指越界 @0x%08X（★ 本次已有 %d 次未登记参数个数的 API 调用：%s —— 栈错位极可能由此而来）", EIP, g_unk_total, unk_api_hint());
        else snprintf(g_stop_reason, sizeof(g_stop_reason), "取指越界 @0x%08X", EIP);
        return 0;
    }

    switch (op) {
    /* ---- mov ---- */
    case 0x88: case 0x89: { modrm_t m; int sz = (op == 0x88) ? 1 : opsz; dec_modrm(&m, sz); op_write(&m, (sz == 1) ? (R[m.reg] & 0xFF) : (sz == 2 ? R[m.reg] & 0xFFFF : R[m.reg])); return 1; }
    case 0x8A: case 0x8B: { modrm_t m; int sz = (op == 0x8A) ? 1 : opsz; dec_modrm(&m, sz); u32 v = op_read(&m); if (sz == 1) R[m.reg] = (R[m.reg] & ~0xFFu) | (v & 0xFF); else if (sz == 2) R[m.reg] = (R[m.reg] & ~0xFFFFu) | (v & 0xFFFF); else R[m.reg] = v; return 1; }
    case 0x8C: { modrm_t m; dec_modrm(&m, opsz); op_write(&m, g_segovr == 1 ? 0x3B : 0x23); return 1; }
    case 0x8E: { modrm_t m; dec_modrm(&m, opsz); (void)op_read(&m); return 1; }
    case 0x8D: { modrm_t m; dec_modrm(&m, opsz); R[m.reg] = m.is_mem ? m.addr : op_read(&m); return 1; }
    case 0xC6: case 0xC7: { modrm_t m; int sz = (op == 0xC6) ? 1 : opsz; dec_modrm(&m, sz); if (m.reg != 0) { snprintf(g_stop_reason, sizeof(g_stop_reason), "C6/C7 非法 reg 域"); return 0; } u32 imm = (sz == 1) ? next8() : (sz == 2 ? (next8() | (next8() << 8)) : next32()); op_write(&m, imm); return 1; }
    case 0xB0: case 0xB1: case 0xB2: case 0xB3: case 0xB4: case 0xB5: case 0xB6: case 0xB7: { int r = op - 0xB0; R[r] = (R[r] & ~0xFFu) | next8(); return 1; }
    case 0xB8: case 0xB9: case 0xBA: case 0xBB: case 0xBC: case 0xBD: case 0xBE: case 0xBF: { int r = op - 0xB8; if (opsz == 2) R[r] = (R[r] & 0xFFFF0000u) | (next8() | (next8() << 8)); else R[r] = next32(); return 1; }
    case 0xA0: case 0xA1: { u32 a = next32(); if (op == 0xA0) { u8 v = 0; if (!vm_read8(seg_base(g_segovr) + a, &v)) g_fault = 1; EAX = (EAX & ~0xFFu) | v; } else { EAX = peek32(seg_base(g_segovr) + a); } return 1; }
    case 0xA2: case 0xA3: { u32 a = next32(); if (op == 0xA2) vm_write8(seg_base(g_segovr) + a, (u8)EAX); else vm_write32(seg_base(g_segovr) + a, EAX); return 1; }
    case 0x86: case 0x87: { modrm_t m; int sz = (op == 0x86) ? 1 : opsz; dec_modrm(&m, sz); u32 v = op_read(&m); op_write(&m, (sz == 1) ? (R[m.reg] & 0xFF) : R[m.reg]); if (sz == 1) R[m.reg] = (R[m.reg] & ~0xFFu) | (v & 0xFF); else R[m.reg] = v; return 1; }

    /* ---- lea 已处理；push/pop ---- */
    case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57: push_val(R[op - 0x50], opsz); return 1;
    case 0x58: case 0x59: case 0x5A: case 0x5B: case 0x5C: case 0x5D: case 0x5E: case 0x5F: { int r = op - 0x58; u32 v = pop_val(opsz); if (opsz == 2) R[r] = (R[r] & 0xFFFF0000u) | (v & 0xFFFF); else R[r] = v; return 1; }
    case 0x68: push_val(g_opsz16 ? (next8() | (next8() << 8)) : next32(), opsz); return 1;
    case 0x6A: { u8 imm = next8(); push_val((u32)(s32)(s8)imm, opsz); return 1; }
    case 0x8F: { modrm_t m; dec_modrm(&m, opsz); if (m.reg != 0) { snprintf(g_stop_reason, sizeof(g_stop_reason), "8F 非法 reg 域"); return 0; } op_write(&m, pop_val(opsz)); return 1; }
    case 0x60: { u32 esp0 = ESP; push32(EAX); push32(ECX); push32(EDX); push32(EBX); push32(esp0); push32(EBP); push32(ESI); push32(EDI); return 1; }
    case 0x61: { EDI = pop32(); ESI = pop32(); EBP = pop32(); (void)pop32(); EBX = pop32(); EDX = pop32(); ECX = pop32(); EAX = pop32(); return 1; }
    case 0x9C: push_val(EFLAGS, opsz); return 1;
    case 0x9D: EFLAGS = pop_val(opsz) | 0x02; return 1;
    case 0x9E: { /* sahf */ EFLAGS = (EFLAGS & ~0xFFu) | (EAX >> 8) | 0x02; return 1; }
    case 0x9F: { /* lahf */ EAX = (EAX & 0xFFFF00FFu) | ((EFLAGS & 0xFF) << 8); return 1; }
    case 0x98: { if (opsz == 2) EAX = (EAX & 0xFFFF0000u) | (u32)(s32)(s16)(EAX & 0xFFFF); else EAX = (u32)(s32)(s16)(EAX & 0xFFFF); return 1; }
    case 0x99: { if (opsz == 2) EDX = (EAX & 0x8000) ? 0xFFFF : 0; else EDX = (EAX & 0x80000000u) ? 0xFFFFFFFF : 0; return 1; }
    case 0x90: return 1;
    case 0x91: case 0x92: case 0x93: case 0x94: case 0x95: case 0x96: case 0x97: { int r = op - 0x90 + 1; u32 t = EAX; EAX = R[r]; R[r] = t; return 1; }

    /* ---- inc/dec 短编码 ---- */
    case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: case 0x45: case 0x46: case 0x47: { int r = op - 0x40; u32 a = R[r], res; int cf = (EFLAGS & CF); flags_add(a, 1, a + 1, 4); res = a + 1; R[r] = res; EFLAGS = (EFLAGS & ~CF) | cf; return 1; }
    case 0x48: case 0x49: case 0x4A: case 0x4B: case 0x4C: case 0x4D: case 0x4E: case 0x4F: { int r = op - 0x48; u32 a = R[r]; int cf = (EFLAGS & CF); flags_sub(a, 1, a - 1, 4); R[r] = a - 1; EFLAGS = (EFLAGS & ~CF) | cf; return 1; }

    /* ---- 跳转/调用/返回 ---- */
    case 0xE8: { s32 rel = (s32)next32(); push_val(EIP, opsz); EIP += rel; return 1; }
    case 0xE9: { s32 rel = (g_opsz16 ? (s16)(next8() | (next8() << 8)) : (s32)next32()); EIP += rel; return 1; }
    case 0xEB: { s8 rel = (s8)next8(); EIP += rel; return 1; }
    case 0xC3: { u32 ra = pop_val(opsz); if (ra == EXIT_MAGIC) { g_halted = 1; snprintf(g_stop_reason, sizeof(g_stop_reason), "样本从入口正常返回"); return 0; } EIP = ra; return 1; }
    case 0xC2: { u32 imm = next8() | (next8() << 8); u32 ra = pop_val(opsz); if (ra == EXIT_MAGIC) { g_halted = 1; snprintf(g_stop_reason, sizeof(g_stop_reason), "样本正常返回"); return 0; } EIP = ra; ESP += imm; return 1; }
    case 0xC9: { ESP = EBP; EBP = pop32(); return 1; }
    case 0xCC: { snprintf(g_stop_reason, sizeof(g_stop_reason), "命中 int3（可能是反调试/异常处理）"); g_halted = 1; return 0; }
    case 0xCD: {
        u8 n = next8(); g_halted = 1;
        if (n == 0x29) {
            /* int 0x29 = __fastfail：x86 侧同样留 ★ 证据（与 x64 对齐） */
            blog("反调试", "★样本命中 int 0x29（__fastfail，ecx=0x%08X）：反调试/完整性校验触发的自毁", (u32)R[1]);
            tr("反调试\tint 0x29\t__fastfail ecx=0x%08X\n", (u32)R[1]);
            snprintf(g_stop_reason, sizeof(g_stop_reason), "命中 int 0x29（__fastfail，ecx=0x%08X）：样本主动自毁，通常为反调试/反篡改", (u32)R[1]);
        } else {
            snprintf(g_stop_reason, sizeof(g_stop_reason), "命中 int 0x%02X（未模拟中断/异常）", n);
        }
        return 0;
    }
    case 0xF4: { snprintf(g_stop_reason, sizeof(g_stop_reason), "命中 hlt"); g_halted = 1; return 0; }
    /* ---- 标志位控制（解壳/混淆代码起手常用；虚拟环境里改标志即可）---- */
    case 0xF8: EFLAGS &= ~CF; return 1;                     /* clc */
    case 0xF9: EFLAGS |=  CF; return 1;                     /* stc */
    case 0xF5: EFLAGS ^=  CF; return 1;                     /* cmc */
    case 0xFC: EFLAGS &= ~DF; return 1;                     /* cld —— 串操作方向，必须真实现 */
    case 0xFD: EFLAGS |=  DF; return 1;                     /* std */
    case 0xFA: EFLAGS &= ~IF; return 1;                     /* cli（无中断，等价空操作）*/
    case 0xFB: EFLAGS |=  IF; return 1;                     /* sti */
    /* ---- BCD 调整（AAM/AAD）：混淆壳喜欢拿它们藏字节 ---- */
    case 0xD4: {                                            /* aam */
        u8 b = next8();
        if (b == 0) { snprintf(g_stop_reason, sizeof(g_stop_reason), "AAM 立即数为 0（真机会触发除零）"); return 0; }
        u8 al = (u8)EAX;
        EAX = (EAX & 0xFFFF0000u) | ((u32)(al / b) << 8) | (u32)(al % b);
        set_pzs(EAX & 0xFFu, 1);
        return 1;
    }
    case 0xD5: {                                            /* aad */
        u8 b = next8();
        u8 al = (u8)((u8)(EAX >> 8) * b + (u8)EAX);
        EAX = (EAX & 0xFFFF0000u) | al;
        set_pzs(al, 1);
        return 1;
    }
    case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75: case 0x76: case 0x77:
    case 0x78: case 0x79: case 0x7A: case 0x7B: case 0x7C: case 0x7D: case 0x7E: case 0x7F: { s8 rel = (s8)next8(); if (cond(op - 0x70)) EIP += rel; return 1; }
    case 0xE0: case 0xE1: case 0xE2: { s8 rel = (s8)next8(); ECX--; int z = (ECX == 0); if (op == 0xE2 ? !z : (op == 0xE1 ? !z : z)) EIP += rel; return 1; }
    case 0xE3: { s8 rel = (s8)next8(); if (ECX == 0) EIP += rel; return 1; }

    /* ---- ALU（寄存器/内存形式）---- */
    case 0x00: case 0x01: case 0x02: case 0x03: case 0x08: case 0x09: case 0x0A: case 0x0B:
    case 0x10: case 0x11: case 0x12: case 0x13: case 0x18: case 0x19: case 0x1A: case 0x1B:
    case 0x20: case 0x21: case 0x22: case 0x23: case 0x28: case 0x29: case 0x2A: case 0x2B:
    case 0x30: case 0x31: case 0x32: case 0x33: case 0x38: case 0x39: case 0x3A: case 0x3B: {
        int fam = (op >> 3) & 7;
        int form = op & 3;
        int sz = (op & 1) ? opsz : 1;
        modrm_t m; dec_modrm(&m, sz);
        u32 a, b, r;
        int dst_mem;
        u32 regval = (sz == 1) ? (R[m.reg] & 0xFF) : (sz == 2 ? (R[m.reg] & 0xFFFF) : R[m.reg]);
        if (form == 0 || form == 1) { a = op_read(&m); b = regval; dst_mem = 1; }
        else { a = regval; b = op_read(&m); dst_mem = 0; }
        switch (fam) {
            case 0: r = a + b; flags_add(a, b, r, sz); break;
            case 1: r = a | b; flags_logic(r, sz); break;
            case 2: { u32 c = (EFLAGS & CF) ? 1 : 0; r = a + b + c; flags_add(a, b, r, sz); if ((u64)a + b + c > szmask(sz)) EFLAGS |= CF; else EFLAGS &= ~CF; break; }
            case 3: { u32 c = (EFLAGS & CF) ? 1 : 0; u32 bb = b + c; r = a - bb; flags_sub(a, bb, r, sz); break; }
            case 4: r = a & b; flags_logic(r, sz); break;
            case 5: r = a - b; flags_sub(a, b, r, sz); break;
            case 6: r = a ^ b; flags_logic(r, sz); break;
            default: r = a - b; flags_sub(a, b, r, sz); break;   /* cmp */
        }
        if (fam != 7) {
            if (dst_mem) op_write(&m, r);
            else { if (sz == 1) R[m.reg] = (R[m.reg] & ~0xFFu) | (r & 0xFF); else if (sz == 2) R[m.reg] = (R[m.reg] & 0xFFFF0000u) | (r & 0xFFFF); else R[m.reg] = r; }
        }
        return 1;
    }
    /* ---- ALU 累加器 + imm ---- */
    case 0x04: case 0x05: case 0x0C: case 0x0D: case 0x14: case 0x15: case 0x1C: case 0x1D:
    case 0x24: case 0x25: case 0x2C: case 0x2D: case 0x34: case 0x35: case 0x3C: case 0x3D: {
        int fam = (op >> 3) & 7;
        int sz = (op & 1) ? opsz : 1;
        u32 a = (sz == 1) ? (EAX & 0xFF) : (sz == 2 ? EAX & 0xFFFF : EAX);
        u32 b = (sz == 1) ? next8() : (sz == 2 ? (next8() | (next8() << 8)) : next32());
        u32 r;
        switch (fam) {
            case 0: r = a + b; flags_add(a, b, r, sz); break;
            case 1: r = a | b; flags_logic(r, sz); break;
            case 2: { u32 c = (EFLAGS & CF) ? 1 : 0; r = a + b + c; flags_add(a, b, r, sz); if ((u64)a + b + c > szmask(sz)) EFLAGS |= CF; break; }
            case 3: { u32 c = (EFLAGS & CF) ? 1 : 0; r = a - b - c; flags_sub(a, b + c, r, sz); break; }
            case 4: r = a & b; flags_logic(r, sz); break;
            case 5: r = a - b; flags_sub(a, b, r, sz); break;
            case 6: r = a ^ b; flags_logic(r, sz); break;
            default: r = a - b; flags_sub(a, b, r, sz); break;
        }
        if (fam != 7) { if (sz == 1) EAX = (EAX & ~0xFFu) | (r & 0xFF); else if (sz == 2) EAX = (EAX & 0xFFFF0000u) | (r & 0xFFFF); else EAX = r; }
        return 1;
    }
    /* ---- group1: 80/81/83 ---- */
    case 0x80: case 0x81: case 0x83: {
        int sz = (op == 0x80) ? 1 : opsz;
        modrm_t m; dec_modrm(&m, sz);
        int sub = m.reg;
        u32 a = op_read(&m);
        u32 b;
        if (op == 0x83) b = (u32)(s32)(s8)next8();
        else if (sz == 1) b = next8();
        else if (sz == 2) b = next8() | (next8() << 8);
        else b = next32();
        u32 r;
        switch (sub) {
            case 0: r = a + b; flags_add(a, b, r, sz); break;
            case 1: r = a | b; flags_logic(r, sz); break;
            case 2: { u32 c = (EFLAGS & CF) ? 1 : 0; r = a + b + c; flags_add(a, b, r, sz); if ((u64)a + b + c > szmask(sz)) EFLAGS |= CF; break; }
            case 3: { u32 c = (EFLAGS & CF) ? 1 : 0; r = a - b - c; flags_sub(a, b + c, r, sz); break; }
            case 4: r = a & b; flags_logic(r, sz); break;
            case 5: r = a - b; flags_sub(a, b, r, sz); break;
            case 6: r = a ^ b; flags_logic(r, sz); break;
            default: r = a - b; flags_sub(a, b, r, sz); break;
        }
        if (sub != 7) op_write(&m, r);
        return 1;
    }
    case 0x84: case 0x85: { modrm_t m; int sz = (op == 0x84) ? 1 : opsz; dec_modrm(&m, sz); u32 a = op_read(&m); u32 b = (sz == 1) ? (R[m.reg] & 0xFF) : R[m.reg]; flags_logic(a & b, sz); return 1; }
    case 0xA8: case 0xA9: { int sz = (op == 0xA8) ? 1 : opsz; u32 a = (sz == 1) ? (EAX & 0xFF) : EAX; u32 b = (sz == 1) ? next8() : (sz == 2 ? (next8() | (next8() << 8)) : next32()); flags_logic(a & b, sz); return 1; }

    /* ---- group3/4/5 ---- */
    case 0xF6: case 0xF7: {
        int sz = (op == 0xF6) ? 1 : opsz;
        modrm_t m; dec_modrm(&m, sz);
        int sub = m.reg;
        u32 a = op_read(&m);
        if (sub == 0 || sub == 1) { u32 b = (sz == 1) ? next8() : (sz == 2 ? (next8() | (next8() << 8)) : next32()); flags_logic(a & b, sz); return 1; }
        if (sub == 2) { op_write(&m, ~a & szmask(sz)); return 1; }
        if (sub == 3) { u32 r = (u32)(0 - (s64)(s32)a); if (sz == 1) r &= 0xFF; if (sz == 2) r &= 0xFFFF; flags_sub(0, a, r, sz); op_write(&m, r); return 1; }
        if (sub == 4) { /* mul */ u64 p; if (sz == 1) { p = (u64)(EAX & 0xFF) * (a & 0xFF); EAX = (EAX & 0xFFFF0000u) | ((u32)(p & 0xFFFF)); EFLAGS &= ~(CF | OF); if (p > 0xFF) EFLAGS |= CF | OF; }
                        else if (sz == 2) { p = (u64)(EAX & 0xFFFF) * (a & 0xFFFF); EAX = (EAX & 0xFFFF0000u) | (u32)(p & 0xFFFF); EDX = (EDX & 0xFFFF0000u) | (u32)((p >> 16) & 0xFFFF); EFLAGS &= ~(CF | OF); if (p > 0xFFFF) EFLAGS |= CF | OF; }
                        else { p = (u64)EAX * a; EAX = (u32)p; EDX = (u32)(p >> 32); EFLAGS &= ~(CF | OF); if (p >> 32) EFLAGS |= CF | OF; } return 1; }
        if (sub == 5) { /* imul 单操作数 */ s64 p; if (sz == 1) { p = (s64)(s8)(EAX & 0xFF) * (s64)(s8)(a & 0xFF); EAX = (EAX & 0xFFFF0000u) | ((u32)p & 0xFFFF); EFLAGS &= ~(CF | OF); if (p != (s64)(s8)(p & 0xFF)) EFLAGS |= CF | OF; }
                        else if (sz == 2) { p = (s64)(s16)(EAX & 0xFFFF) * (s64)(s16)(a & 0xFFFF); EAX = (EAX & 0xFFFF0000u) | ((u32)p & 0xFFFF); EDX = (EDX & 0xFFFF0000u) | (((u32)p >> 16) & 0xFFFF); EFLAGS &= ~(CF | OF); if (p != (s64)(s16)(p & 0xFFFF)) EFLAGS |= CF | OF; }
                        else { p = (s64)(s32)EAX * (s64)(s32)a; EAX = (u32)p; EDX = (u32)((u64)p >> 32); EFLAGS &= ~(CF | OF); if (p != (s64)(s32)(u32)p) EFLAGS |= CF | OF; } return 1; }
        if (sub == 6 || sub == 7) { /* div/idiv */
            if (a == 0) { snprintf(g_stop_reason, sizeof(g_stop_reason), "除零（0x%08X）", EIP); g_halted = 1; return 0; }
            if (sz == 4) {
                if (sub == 6) { u64 dv = ((u64)EDX << 32) | EAX; if (dv / a > 0xFFFFFFFFu) { snprintf(g_stop_reason, sizeof(g_stop_reason), "div 溢出"); g_halted = 1; return 0; } EAX = (u32)(dv / a); EDX = (u32)(dv % a); }
                else { s64 dv = (s64)((((u64)EDX << 32) | EAX)); s64 q = dv / (s64)(s32)a; s64 rm = dv % (s64)(s32)a; EAX = (u32)q; EDX = (u32)rm; }
            } else { u32 dv = (sz == 1) ? (EAX & 0xFFFF) : (((EDX & 0xFFFF) << 16) | (EAX & 0xFFFF)); if (sub == 6) { EAX = (EAX & ~0xFFFFu) | ((dv / a) & 0xFFFF); EDX = (EDX & ~0xFFFFu) | ((dv % a) & 0xFFFF); } else { EAX = (EAX & ~0xFFFFu) | (((u32)((s32)dv / (s32)(s16)a)) & 0xFFFF); EDX = (EDX & ~0xFFFFu) | (((u32)((s32)dv % (s32)(s16)a)) & 0xFFFF); } }
            return 1;
        }
        snprintf(g_stop_reason, sizeof(g_stop_reason), "F6/F7 未支持 sub=%d", sub); return 0;
    }
    case 0xFE: {
        modrm_t m; dec_modrm(&m, 1);
        u32 a = op_read(&m);
        if (m.reg == 0) { int cf = (EFLAGS & CF); flags_add(a, 1, a + 1, 1); op_write(&m, a + 1); EFLAGS = (EFLAGS & ~CF) | cf; }
        else if (m.reg == 1) { int cf = (EFLAGS & CF); flags_sub(a, 1, a - 1, 1); op_write(&m, a - 1); EFLAGS = (EFLAGS & ~CF) | cf; }
        else { snprintf(g_stop_reason, sizeof(g_stop_reason), "FE 未支持 reg=%d", m.reg); return 0; }
        return 1;
    }
    case 0xFF: {
        modrm_t m; int sz = opsz; dec_modrm(&m, sz);
        switch (m.reg) {
            case 7: { push_val(op_read(&m), sz); return 1; }
            case 0: { u32 a = op_read(&m); int cf = (EFLAGS & CF); flags_add(a, 1, a + 1, sz); op_write(&m, a + 1); EFLAGS = (EFLAGS & ~CF) | cf; return 1; }
            case 1: { u32 a = op_read(&m); int cf = (EFLAGS & CF); flags_sub(a, 1, a - 1, sz); op_write(&m, a - 1); EFLAGS = (EFLAGS & ~CF) | cf; return 1; }
            case 2: { u32 t = op_read(&m); push_val(EIP, sz); EIP = t; return 1; }
            case 3: { u32 t = m.is_mem ? peek32(m.addr) : op_read(&m); push_val(EIP, sz); EIP = t; return 1; }
            case 4: { u32 t = op_read(&m); EIP = t; return 1; }
            case 5: { u32 t = m.is_mem ? peek32(m.addr) : op_read(&m); EIP = t; return 1; }
            case 6: { push_val(op_read(&m), sz); return 1; }
            default: snprintf(g_stop_reason, sizeof(g_stop_reason), "FF 组未支持 reg=%d  字节[%s] @0x%08X", m.reg, hex_at(EIP - 2, 6), EIP - 2); return 0;
        }
    }
    case 0x69: case 0x6B: {
        modrm_t m; dec_modrm(&m, opsz);
        u32 src = op_read(&m);
        u32 imm = (op == 0x6B) ? (u32)(s32)(s8)next8() : (opsz == 2 ? (next8() | (next8() << 8)) : next32());
        s64 p = (s64)(s32)src * (s64)(s32)(op == 0x6B ? (u32)(s32)(s8)imm : imm);
        R[m.reg] = (u32)p;
        EFLAGS &= ~(CF | OF); if (p != (s64)(s32)(u32)p) EFLAGS |= CF | OF;
        return 1;
    }
    /* ---- 移位/循环移位 ---- */
    case 0xC0: case 0xC1: case 0xD0: case 0xD1: case 0xD2: case 0xD3: {
        int sz = (op == 0xC0 || op == 0xD0 || op == 0xD2) ? 1 : opsz;
        modrm_t m; dec_modrm(&m, sz);
        int sub = m.reg;
        u32 a = op_read(&m);
        u32 cnt;
        if (op == 0xC0 || op == 0xC1) cnt = next8();
        else if (op == 0xD0 || op == 0xD1) cnt = 1;
        else cnt = ECX & 0xFF;
        if (cnt == 0) return 1;
        u32 mask = szmask(sz), res = a & mask;
        cnt &= 0x1F;
        switch (sub) {
            case 4: case 6: { /* shl/sal */
                u64 v = (u64)res << cnt;
                EFLAGS &= ~(CF | OF);
                if (v & (1ULL << (sz * 8))) EFLAGS |= CF;
                res = (u32)v & mask;
                if (cnt == 1) { if ((res & msb(sz)) != 0) EFLAGS |= OF; }
                set_pzs(res, sz);
                break;
            }
            case 5: { /* shr */
                u32 cf = (cnt <= sz * 8) ? ((res >> (cnt - 1)) & 1) : 0;
                res >>= cnt; EFLAGS &= ~(CF | OF); if (cf) EFLAGS |= CF; set_pzs(res, sz);
                if (cnt == 1 && (a & msb(sz))) EFLAGS |= OF;
                break;
            }
            case 7: { /* sar */
                s32 v = (sz == 1) ? (s32)(s8)(res & 0xFF) : (sz == 2 ? (s32)(s16)(res & 0xFFFF) : (s32)res);
                u32 cf = (res >> (cnt - 1)) & 1;
                v >>= (cnt > 31 ? 31 : cnt);
                res = (u32)v & mask; EFLAGS &= ~(CF | OF); if (cf) EFLAGS |= CF; set_pzs(res, sz);
                break;
            }
            case 0: case 1: { /* rol/ror */
                cnt %= (sz * 8);
                if (cnt) { if (sub == 0) res = ((res << cnt) | (res >> (sz * 8 - cnt))) & mask; else res = ((res >> cnt) | (res << (sz * 8 - cnt))) & mask; }
                EFLAGS &= ~(CF | OF);
                if (sub == 0) { if (res & 1) EFLAGS |= CF; if (cnt == 1 && ((res & msb(sz)) != 0)) EFLAGS |= OF; }
                else { if (res & msb(sz)) EFLAGS |= CF; if (cnt == 1 && ((res ^ (res >> 1)) & msb(sz))) EFLAGS |= OF; }
                break;
            }
            case 2: case 3: { /* rcl/rcr */
                int bits = sz * 8;
                cnt %= (bits + 1);
                u32 cf = (EFLAGS & CF) ? 1 : 0;
                u64 val = res;
                for (u32 i = 0; i < cnt; i++) {
                    if (sub == 2) { u32 nb = (val >> (bits - 1)) & 1; val = ((val << 1) | cf) & mask; cf = nb; }
                    else { u32 nb = val & 1; val = (val >> 1) | ((u64)cf << (bits - 1)); cf = nb; }
                }
                res = (u32)val & mask;
                EFLAGS &= ~CF; if (cf) EFLAGS |= CF;
                break;
            }
            default: snprintf(g_stop_reason, sizeof(g_stop_reason), "移位 sub=%d 未支持", sub); return 0;
        }
        op_write(&m, res);
        return 1;
    }
    /* ---- 串操作 ---- */
    case 0xA4: case 0xA5: case 0xAA: case 0xAB: case 0xAC: case 0xAD: case 0xAE: case 0xAF: {
        int sz = (op & 1) ? opsz : 1;
        int df = (EFLAGS & DF) ? -1 : 1;
        u32 count = g_rep ? ECX : 1;
        for (u32 i = 0; i < count; i++) {
            if (op == 0xA4 || op == 0xA5) { u32 v; if (sz == 1) { u8 b = 0; vm_read8(ESI, &b); v = b; vm_write8(EDI, (u8)v); } else if (sz == 2) { u16 w = 0; vm_read16(ESI, &w); v = w; vm_write16(EDI, (u16)v); } else { vm_read32(ESI, &v); vm_write32(EDI, v); } reg_mark_written(EDI, sz); ESI += df * sz; EDI += df * sz; }
            else if (op == 0xAA || op == 0xAB) { if (sz == 1) vm_write8(EDI, (u8)EAX); else if (sz == 2) vm_write16(EDI, (u16)EAX); else vm_write32(EDI, EAX); reg_mark_written(EDI, sz); EDI += df * sz; }
            else if (op == 0xAC || op == 0xAD) { if (sz == 1) { u8 b = 0; vm_read8(ESI, &b); EAX = (EAX & ~0xFFu) | b; } else if (sz == 2) { u16 w = 0; vm_read16(ESI, &w); EAX = (EAX & 0xFFFF0000u) | w; } else vm_read32(ESI, &EAX); ESI += df * sz; }
            else if (op == 0xAE || op == 0xAF) { u32 a = (sz == 1) ? (EAX & 0xFF) : (sz == 2 ? EAX & 0xFFFF : EAX), b; if (sz == 1) { u8 t = 0; vm_read8(EDI, &t); b = t; } else if (sz == 2) { u16 t = 0; vm_read16(EDI, &t); b = t; } else vm_read32(EDI, &b); flags_sub(a, b, a - b, sz); EDI += df * sz; }
            if (g_rep && (op == 0xAE || op == 0xAF)) { if (g_rep == 1 && !(EFLAGS & ZF)) break; if (g_rep == 2 && (EFLAGS & ZF)) break; }
        }
        if (g_rep) ECX = 0;
        return 1;
    }
    /* ---- 段寄存器 push/pop（老式/混淆代码）：按空操作处理，保持栈平衡 ---- */
    case 0x06: case 0x0E: case 0x16: case 0x1E: push_val(0x23, opsz); return 1;
    case 0x07: case 0x17: case 0x1F: (void)pop_val(opsz); return 1;
    /* ---- x87 浮点（最简模拟）---- */
    case 0xD8: case 0xD9: case 0xDA: case 0xDB: case 0xDC: case 0xDD: case 0xDE: case 0xDF:
        return do_x87(op, opsz);
    /* ---- BCD/ASCII 调整（老旧/混淆代码里会出现）---- */
    case 0x27: { /* DAA */
        u32 al = EAX & 0xFF;
        if ((al & 0x0F) > 9 || (EFLAGS & AF)) { al += 6; EFLAGS |= AF; } else EFLAGS &= ~AF;
        if (al > 0x9F || (EFLAGS & CF)) { al += 0x60; EFLAGS |= CF; } else EFLAGS &= ~CF;
        EAX = (EAX & ~0xFFu) | (al & 0xFF);
        return 1;
    }
    case 0x2F: { /* DAS */
        u32 al = EAX & 0xFF;
        if ((al & 0x0F) > 9 || (EFLAGS & AF)) { al -= 6; EFLAGS |= AF; } else EFLAGS &= ~AF;
        if (al > 0x9F || (EFLAGS & CF)) { al -= 0x60; EFLAGS |= CF; } else EFLAGS &= ~CF;
        EAX = (EAX & ~0xFFu) | (al & 0xFF);
        return 1;
    }
    case 0x37: { /* AAA */
        u32 al = EAX & 0xFF;
        if ((al & 0x0F) > 9 || (EFLAGS & AF)) { al += 6; EAX = (EAX & 0xFFFF00FFu) | ((EAX + 0x100) & 0xFF00u); EFLAGS |= AF | CF; }
        else EFLAGS &= ~(AF | CF);
        EAX = (EAX & ~0xFFu) | (al & 0x0F);
        return 1;
    }
    case 0x3F: { /* AAS */
        u32 al = EAX & 0xFF;
        if ((al & 0x0F) > 9 || (EFLAGS & AF)) { al -= 6; EAX = (EAX & 0xFFFF00FFu) | ((EAX - 0x100) & 0xFF00u); EFLAGS |= AF | CF; }
        else EFLAGS &= ~(AF | CF);
        EAX = (EAX & ~0xFFu) | (al & 0x0F);
        return 1;
    }
    /* ---- 端口 I/O（反虚拟机常用）：按"非虚拟机"假返回，避免误判 ---- */
    case 0xEC: case 0xED: { EAX = (EAX & 0xFFFF0000u) | 0xFFFFu; blog("反虚拟机", "IN 指令（端口 I/O）@0x%08X，已按非虚拟机返回值 0xFFFF 处理", EIP - 1); return 1; }
    case 0xE4: case 0xE5: { next8(); EAX = (EAX & 0xFFFF0000u) | 0xFFFFu; return 1; }
    case 0xEE: case 0xEF: { return 1; }
    case 0xE6: case 0xE7: { next8(); return 1; }
    /* INS/OUTS 字符串端口 I/O（0x6C..0x6F）：32 位模式下是真指令，不是"未定义字节"。
     * 与上面的 IN/OUT 一致，按"非虚拟机/空操作"处理，免得壳靠它直接把解释器顶停。 */
       case 0x6C: case 0x6D: case 0x6E: case 0x6F: {
        blog("反虚拟机", "INS/OUTS 字符串 I/O（0x%02X）@0x%08X 已按空操作处理", op, EIP - 1);
        return 1;
    }
    case 0x9B: { return 1; }  /* FWAIT：浮点等待，模拟器里直接跳过 */
    case 0xF1: { blog("反调试", "ICEBP（0xF1）@0x%08X 已跳过", EIP - 1); return 1; }
    case 0xD6: { blog("异常", "命中保留指令 0xD6(SALC) @0x%08X，按空操作跳过", EIP - 1); return 1; }
    default: break;
    }
   
    /* ---------- 双字节 0F ---------- */
    if (op == 0x0F) {
        u8 op2 = next8();
        if (g_fault) return 0;
        switch (op2) {
        case 0x80: case 0x81: case 0x82: case 0x83: case 0x84: case 0x85: case 0x86: case 0x87:
        case 0x88: case 0x89: case 0x8A: case 0x8B: case 0x8C: case 0x8D: case 0x8E: case 0x8F: { s32 rel = (s32)next32(); if (cond(op2 - 0x80)) EIP += rel; return 1; }
        case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: case 0x45: case 0x46: case 0x47:
        case 0x48: case 0x49: case 0x4A: case 0x4B: case 0x4C: case 0x4D: case 0x4E: case 0x4F: {   /* CMOVcc */
            modrm_t m; dec_modrm(&m, opsz);
            u32 v = op_read(&m);
            if (cond(op2 - 0x40)) { if (opsz == 2) R[m.reg] = (R[m.reg] & 0xFFFF0000u) | (v & 0xFFFF); else R[m.reg] = v; }
            return 1;
        }
        case 0x90: case 0x91: case 0x92: case 0x93: case 0x94: case 0x95: case 0x96: case 0x97:
        case 0x98: case 0x99: case 0x9A: case 0x9B: case 0x9C: case 0x9D: case 0x9E: case 0x9F: {   /* SETcc */
            modrm_t m; dec_modrm(&m, 1);
            op_write(&m, cond(op2 - 0x90) ? 1 : 0);
            return 1;
        }
        case 0xA3: case 0xAB: case 0xB3: case 0xBB: {   /* BT/BTS/BTR/BTC r/m, r */
            modrm_t m; int sz = (op2 == 0xA3) ? opsz : opsz; dec_modrm(&m, sz);
            u32 v = op_read(&m), bit = R[m.reg] % (u32)(sz * 8);
            EFLAGS = (EFLAGS & ~CF) | ((v >> bit) & 1);
            if (op2 == 0xAB) op_write(&m, v | (1u << bit));
            else if (op2 == 0xB3) op_write(&m, v & ~(1u << bit));
            else if (op2 == 0xBB) op_write(&m, v ^ (1u << bit));
            return 1;
        }
        case 0xBA: {   /* BT/BTS/BTR/BTC r/m, imm8 */
            modrm_t m; dec_modrm(&m, opsz);
            u8 bit8 = next8();
            int sub = m.reg;
            u32 v = op_read(&m), bit = bit8 % (u32)(opsz * 8);
            EFLAGS = (EFLAGS & ~CF) | ((v >> bit) & 1);
            if (sub == 5) op_write(&m, v | (1u << bit));
            else if (sub == 6) op_write(&m, v & ~(1u << bit));
            else if (sub == 7) op_write(&m, v ^ (1u << bit));
            else if (sub != 4) { snprintf(g_stop_reason, sizeof(g_stop_reason), "0F BA 未支持 sub=%d", sub); g_halted = 1; return 0; }
            return 1;
        }
        case 0xBC: case 0xBD: {   /* BSF / BSR */
            modrm_t m; dec_modrm(&m, opsz);
            u32 v = op_read(&m);
            EFLAGS &= ~ZF;
            if (op2 == 0xBC) { R[m.reg] = 0; for (int i = 0; i < opsz * 8; i++) if ((v >> i) & 1) { R[m.reg] = (u32)i; break; } }
            else { R[m.reg] = 0; for (int i = opsz * 8 - 1; i >= 0; i--) if ((v >> i) & 1) { R[m.reg] = (u32)i; break; } }
            if (!v) EFLAGS |= ZF;
            return 1;
        }
        case 0xB0: case 0xB1: {   /* CMPXCHG */
            int sz = (op2 == 0xB0) ? 1 : opsz;
            modrm_t m; dec_modrm(&m, sz);
            u32 a = op_read(&m);
            u32 acc = (sz == 1) ? (EAX & 0xFF) : (sz == 2 ? EAX & 0xFFFF : EAX);
            u32 rv = (sz == 1) ? (R[m.reg] & 0xFF) : (sz == 2 ? R[m.reg] & 0xFFFF : R[m.reg]);
            flags_sub(acc, a, acc - a, sz);
            if (acc == a) op_write(&m, rv);
            else { if (sz == 1) EAX = (EAX & ~0xFFu) | a; else if (sz == 2) EAX = (EAX & 0xFFFF0000u) | a; else EAX = a; }
            return 1;
        }
        case 0xC0: case 0xC1: {   /* XADD */
            int sz = (op2 == 0xC0) ? 1 : opsz;
            modrm_t m; dec_modrm(&m, sz);
            u32 a = op_read(&m);
            u32 rv = (sz == 1) ? (R[m.reg] & 0xFF) : (sz == 2 ? R[m.reg] & 0xFFFF : R[m.reg]);
            op_write(&m, a + rv);
            if (sz == 1) R[m.reg] = (R[m.reg] & ~0xFFu) | (a & 0xFF);
            else if (sz == 2) R[m.reg] = (R[m.reg] & 0xFFFF0000u) | (a & 0xFFFF);
            else R[m.reg] = a;
            flags_add(a, rv, a + rv, sz);
            return 1;
        }
        case 0xA4: case 0xA5: {   /* SHLD r/m, r, imm8 */
            int sz = (op2 == 0xA4) ? 1 : opsz;
            modrm_t m; dec_modrm(&m, sz);
            u8 cnt = next8() & 0x1F;
            u32 v = op_read(&m);
            u32 rv = (sz == 1) ? (R[m.reg] & 0xFF) : (sz == 2 ? R[m.reg] & 0xFFFF : R[m.reg]);
            u32 bits = (u32)(sz * 8);
            u32 res = v;
            for (u32 i = 0; i < cnt; i++) res = (res << 1) | ((bits <= 32 ? (rv >> (bits - 1)) : 0) & 1);
            op_write(&m, res);
            return 1;
        }
        case 0xAC: case 0xAD: {   /* SHRD r/m, r, imm8 */
            int sz = (op2 == 0xAC) ? 1 : opsz;
            modrm_t m; dec_modrm(&m, sz);
            u8 cnt = next8() & 0x1F;
            u32 v = op_read(&m);
            u32 rv = (sz == 1) ? (R[m.reg] & 0xFF) : (sz == 2 ? R[m.reg] & 0xFFFF : R[m.reg]);
            u32 res = v;
            for (u32 i = 0; i < cnt; i++) res = (res >> 1) | ((rv & 1) << ((u32)(sz * 8) - 1));
            op_write(&m, res);
            return 1;
        }
        case 0x10: case 0x11: case 0x12: case 0x13: case 0x14: case 0x15: case 0x16: case 0x17:
        case 0x28: case 0x29: case 0x2A: case 0x2C: case 0x2D: case 0x2E: case 0x2F:
        case 0x50: case 0x51: case 0x54: case 0x55: case 0x56: case 0x57: case 0x58: case 0x59:
        case 0x5A: case 0x5B: case 0x5C: case 0x5E:
        case 0x6E: case 0x6F: case 0x70: case 0x7E: case 0x7F:
        case 0xEE: case 0xEF: case 0xFA: case 0xFC: case 0xFE:
        case 0xC6: case 0xD6:
            return do_sse(op2, g_opsz16 ? 1 : (g_rep == 2 ? 2 : (g_rep == 1 ? 3 : 0)));
        case 0xAF: { modrm_t m; dec_modrm(&m, opsz); u32 src = op_read(&m); s64 p = (s64)(s32)R[m.reg] * (s64)(s32)src; R[m.reg] = (u32)p; EFLAGS &= ~(CF | OF); if (p != (s64)(s32)(u32)p) EFLAGS |= CF | OF; return 1; }
        case 0xB6: case 0xB7: { modrm_t m; int sz = (op2 == 0xB6) ? 1 : 2; dec_modrm(&m, sz); u32 v = op_read(&m); R[m.reg] = (sz == 1) ? (v & 0xFF) : (v & 0xFFFF); return 1; }
        case 0xBE: case 0xBF: { modrm_t m; int sz = (op2 == 0xBE) ? 1 : 2; dec_modrm(&m, sz); u32 v = op_read(&m); R[m.reg] = (sz == 1) ? (u32)(s32)(s8)(v & 0xFF) : (u32)(s32)(s16)(v & 0xFFFF); return 1; }
        case 0x31: { EDX = (u32)(clock()); EAX = (u32)(clock() >> 8); return 1; }   /* rdtsc */
        case 0xA2: { EAX = 0x000106A5; EBX = 0x00000000; ECX = 0x00000000; EDX = 0x0F8BFBFF; return 1; }  /* cpuid */
        case 0xC8: case 0xC9: case 0xCA: case 0xCB: case 0xCC: case 0xCD: case 0xCE: case 0xCF: { R[op2 - 0xC8] = __builtin_bswap32(R[op2 - 0xC8]); return 1; }
        case 0x1F: { modrm_t m; dec_modrm(&m, opsz); return 1; }   /* nop r/m */
        case 0x0D: case 0x18: { modrm_t m; dec_modrm(&m, 1); return 1; }   /* prefetch 提示，不影响语义 */
        case 0xAE: { modrm_t m; dec_modrm(&m, 1); return 1; }   /* fxsave/fxrstor/ldmxcsr/stmxcsr/clflush：按无副作用处理 */
        case 0x0B: { snprintf(g_stop_reason, sizeof(g_stop_reason), "命中 ud2（反调试/异常）"); g_halted = 1; return 0; }
        case 0x05: { return 1; }   /* syscall（不模拟） */
        default:
            snprintf(g_stop_reason, sizeof(g_stop_reason), "未实现的 0F 指令 0x0F 0x%02X @0x%08X", op2, EIP - 2);
            g_halted = 1;
            return 0;
        }
    }

    snprintf(g_stop_reason, sizeof(g_stop_reason), "未实现的指令 0x%02X  字节[%s] @0x%08X", op, hex_at(EIP - 1, 6), EIP - 1);
    g_halted = 1;
    return 0;
}

/* ==================== 阶段二：全虚拟 API（假实现，只记录行为）================ */
static char g_sample_path[260] = "C:\\Samples\\sample.exe";

static void vm_cstr(u32 addr, char* out, int n) {
    out[0] = 0; int i = 0;
    for (; i < n - 1; i++) { u8 b = 0; if (!vm_read8(addr + i, &b) || b == 0) break; out[i] = (char)b; }
    out[i] = 0;
}
static void vm_wstr(u32 addr, char* out, int n) {
    out[0] = 0; int i = 0;
    for (; i < n - 1; i++) { u16 w = 0; if (!vm_read16(addr + i * 2, &w) || w == 0 || w > 0x7F) break; out[i] = (char)w; }
    out[i] = 0;
}
/* 往客户机内存写宽字符串 / UNICODE_STRING（x64 的 PEB 伪造用） */
static void vm_wstr_put(u32 addr, const char* s) {
    u32 k = 0; for (; s[k]; k++) { u16 w = (u16)(u8)s[k]; vm_poke(addr + k * 2, &w, 2); }
    u16 z = 0; vm_poke(addr + k * 2, &z, 2);
}
static void vm_ustr(u32 base, u32 bufaddr, const char* s) {
    u16 len = (u16)(strlen(s) * 2), max = (u16)(len + 2);
    vm_poke(base, &len, 2); vm_poke(base + 2, &max, 2);
    u64 b = bufaddr; vm_poke(base + 8, &b, 8);
    vm_wstr_put(bufaddr, s);
}
static u32 A(int i) { u32 v = 0; vm_read32(ESP + 4 + 4 * i, &v); return v; }

/* 虚拟文件系统（永远不落真盘） */
typedef struct { u32 handle; char path[260]; u8* data; u32 len, cap; FILE* rd; u32 pos; } vfile_t;
static vfile_t g_vf[64]; static int g_vfN = 0;
static u32 g_next_handle = 0x00001000;

/* 只允许读“样本自身”这个宿主文件；其它路径一律不碰宿主磁盘。 */
static int vf_is_self(const char* path) {
    char a[260], b[260]; int i;
    for (i = 0; path[i] && i < 259; i++) a[i] = (path[i] == '/') ? '\\' : path[i];
    a[i] = 0;
    for (i = 0; g_sample_path[i] && i < 259; i++) b[i] = (g_sample_path[i] == '/') ? '\\' : g_sample_path[i];
    b[i] = 0;
    return a[0] && !_stricmp(a, b);
}
static vfile_t* vf_get(const char* path) {
    vfile_t* f = NULL;
    for (int i = 0; i < g_vfN; i++) if (!_stricmp(g_vf[i].path, path)) { f = &g_vf[i]; break; }
    if (!f && g_vfN < 64) {
        f = &g_vf[g_vfN++];
        memset(f, 0, sizeof(*f));
        f->handle = g_next_handle++;
        snprintf(f->path, 260, "%s", path);
    }
    if (f) {
        f->pos = 0;
        if (!f->rd && vf_is_self(f->path)) f->rd = fopen(g_sample_path, "rb");
        if (f->rd) _fseeki64(f->rd, 0, SEEK_SET);
    }
    return f;
}
static u32 vf_size(vfile_t* f) {
    if (!f) return 0;
    if (f->rd) {
        long long cur = _ftelli64(f->rd);
        _fseeki64(f->rd, 0, SEEK_END);
        long long sz = _ftelli64(f->rd);
        _fseeki64(f->rd, cur < 0 ? 0 : cur, SEEK_SET);
        return sz > 0 ? (u32)sz : 0;
    }
    return f->len;
}

/* 虚拟模块表 */
typedef struct { u32 base; char name[64]; } vmod_t;
static vmod_t g_vmod[32]; static int g_vmodN = 0;

/* 行为记录 */
#define LOG_MAX 512
static char g_log_kind[LOG_MAX][16];
static char g_log_text[LOG_MAX][280];
static int  g_logN = 0;
static void blog(const char* kind, const char* fmt, ...) {
    if (g_logN >= LOG_MAX) return;
    snprintf(g_log_kind[g_logN], 16, "%s", kind);
    va_list ap; va_start(ap, fmt);
    vsnprintf(g_log_text[g_logN], 280, fmt, ap);
    va_end(ap);
    tr("%s\t%s\n", kind, g_log_text[g_logN]);
    g_logN++;
}

static u32 g_tick = 0x00040000;
static u32 g_qpc_lo = 0x12345678, g_qpc_hi = 0x00000123;

/* ---------------- 各 API 的假实现 ---------------- */
// 对抗 FindWindow 查找调试器窗口（如 OllyDbg, x64dbg, ProcessHacker）
static void h_FindWindowA(void) { EAX = 0; } // 永远返回找不到
static void h_FindWindowW(void) { EAX = 0; }

// 对抗 EnumWindows 枚举窗口
static void h_EnumWindows(void) { EAX = 0; } // 返回失败，假装没有窗口

// 对抗 GetForegroundWindow 获取当前活动窗口
static void h_GetForegroundWindow(void) { EAX = 0; } 

// 获取模块句柄（恶意软件常查是否加载了杀软、沙盒的 DLL，如 SbieDll.dll）
static void h_GetModuleHandleA(void) {
    u32 name_ptr = A(0);
    char name[256] = {0};
    
    // 如果传入 NULL，通常是为了获取自身模块句柄
    if (name_ptr == 0) {
        EAX = g_imagebase;
        return;
    }
    
    vm_cstr(name_ptr, name, sizeof(name));

    // 如果查的是特定沙盒、杀软或调试器 DLL，假装找不到
    if (_stricmp(name, "SbieDll.dll") == 0 || 
        _stricmp(name, "dbghelp.dll") == 0 || 
        _stricmp(name, "sbiedll.dll") == 0 ||
        _stricmp(name, "api_log.dll") == 0 ||
        _stricmp(name, "dir_watch.dll") == 0 ||
        _stricmp(name, "pstorec.dll") == 0 ||
        _stricmp(name, "vmcheck.dll") == 0) {
        blog("反沙盒", "GetModuleHandleA(\"%s\") -> 伪造未加载", name);
        EAX = 0; 
    } 
    // 如果查的是 kernel32 或 ntdll，返回一个伪造的合法句柄
    else if (_stricmp(name, "kernel32.dll") == 0 || _stricmp(name, "ntdll.dll") == 0) {
        EAX = 0x7FF00000; // 返回一个高位地址，假装系统 DLL 已加载
        if (g_vmodN < 32) { g_vmod[g_vmodN].base = EAX; snprintf(g_vmod[g_vmodN].name, 64, "%s", name); g_vmodN++; }
    } 
    // 其他所有 DLL，为了保证逻辑通过，我们全给它返回一个假句柄
    else {
        EAX = 0x10000000; 
        if (g_vmodN < 32) { g_vmod[g_vmodN].base = EAX; snprintf(g_vmod[g_vmodN].name, 64, "%s", name); g_vmodN++; }
    }
}
static void h_ret0(void) { EAX = 0; }
// 伪造网卡 MAC 地址（避开 VMware 的 00:0C:29 和 VirtualBox 的 08:00:27）
static void h_GetAdaptersInfo(void) { 
    // 实际中会去填充 IP_ADAPTER_INFO 结构，这里简单返回一个非虚拟机的物理网卡特征
    blog("反沙盒", "GetAdaptersInfo -> 伪造返回物理网卡特征"); 
    EAX = 0; // 假装成功
}

// 伪造 CPUID 指令信息（有些病毒会直接内联汇编执行 cpuid，如果是虚拟机，Hypervisor 位会被置 1）
// 注：如果你代码里有内联 asm 处理 0x0F 0xA2，可以在这里拦截并伪造 ECX=0（隐藏 Hypervisor 位）

// 伪造硬盘序列号（避开 VMware 的 "VMware Virtual IDE Hard Drive"）
static void h_GetVolumeInformation(void) {
    u32 root = A(0);
    u32 vol_name = A(1);
    u32 vol_name_size = A(2);
    u32 serial = A(3);
    if (serial) {
        u32 fake_serial = 0x12345678; // 伪造一个随机的物理硬盘序列号
        vm_write32(serial, fake_serial);
    }
    if (vol_name && vol_name_size > 0) {
        const char* name = "OS";
        vm_poke(vol_name, name, 3);
    }
    blog("反沙盒", "GetVolumeInformation -> 伪造物理硬盘序列号");
    EAX = 1;
}
static void h_GetKeyboardType(void) {
    u32 type = A(0);
    if (type == 0) {
        EAX = 4;        // 返回增强型键盘（典型物理机特征）
    } else if (type == 1) {
        EAX = 0x0000;   // 子类型返回 0（非虚拟机特征）
    } else {
        EAX = 0;
    }
    blog("反沙盒", "GetKeyboardType(%u) -> 伪造返回物理机特征", type);
} 
static void h_ret1(void) { EAX = 1; }

// 很多沙盒运行几秒钟就分析完了，所以 Uptime（运行时间）极短。病毒会检测如果时间太短，就认为是沙盒。
static void h_GetTickCount(void) {
    // 伪造开机了 3 个小时（3 * 60 * 60 * 1000 毫秒）
    EAX = 10800000 + (u32)(g_insn / 100); 
}

// 沙盒通常分配很少的内存，或者 CPU 核心数为 1。
static void h_GetSystemInfo(void) {
    u32 lpSystemInfo = A(0);
    if (lpSystemInfo) {
        u8 sysinfo[36] = {0};
        u32 num_procs = 4; // 伪造 4 核 CPU
        memcpy(sysinfo + 20, &num_procs, 4);
        vm_poke(lpSystemInfo, sysinfo, 36);
    }
}

/* STARTUPINFOA（x86 为 0x44 字节）：不能再用 SYSTEM_INFO 顶替，
 * 否则 CRT 读到的 cb/dwFlags/hStd* 全是别的字段。 */
static void h_GetStartupInfo(void) {
    u32 p = A(0);
    if (p) {
        u8 si[0x44] = {0};
        u32 cb = 0x44;
        memcpy(si, &cb, 4);
        vm_poke(p, si, sizeof(si));
    }
}

// 获取用户名（沙盒常用 "WDAGUtilityAccount", "sandbox", "malware" 等）
static void h_GetUserNameA(void) {
    u32 buf = A(0);
    u32 size_ptr = A(1);
    const char* fake_name = "admin"; // 伪装成普通用户
    if (buf) vm_poke(buf, fake_name, strlen(fake_name) + 1);
    if (size_ptr) vm_write32(size_ptr, strlen(fake_name) + 1);
    EAX = 1;
}

// 检查 CPU 核心数
static void h_GetSystemDirectoryA(void) {
    u32 buf = A(0), n = A(1);
    const char* s = "C:\\Windows\\System32";
    u32 len = (u32)strlen(s);
    if (buf && n > len) { vm_poke(buf, s, len + 1); EAX = len; }
    else EAX = len + 1;   // 缓冲区不够时返回所需长度
}
static void h_ret_LCID(void) { EAX = 0x0409; } /* 伪造返回英语美国的 LCID */

static void h_VirtualAlloc(void) {
    u32 hint = A(0), size = A(1), type = A(2), prot = A(3);
    u32 p = P_R | P_W;
    if (prot & (0x10 | 0x20 | 0x40 | 0x80)) p |= P_X;
    if ((prot & 0xFF) == 1) p = 0;
    if (!size) size = 0x1000;
    u32 asize = (size + 0xFFF) & ~0xFFFu;
    reg_t* r = hint ? reg_find(hint) : NULL;
    u32 a;
    if (hint && r) {
        /* 地址落在已有区域内 -> 按"提交/改保护"处理（MEM_RESERVE → MEM_COMMIT 的典型用法） */
        if (p) reg_setprot(hint, asize, r->prot | p);
        a = hint;
    } else {
        a = vm_alloc_region(hint, asize, p, RK_ALLOC, "VirtualAlloc");
    }
    blog("分配", "VirtualAlloc(0x%X, %u, 0x%X, 0x%X) -> 0x%08X%s", hint, size, type, prot, a,
         (prot & 0x40) ? "  [可读写+可执行]" : "");
    EAX = a;
}
static void h_VirtualProtect(void) {
    u32 addr = A(0), size = A(1), np = A(2), oldp = A(3);
    u32 p = P_R | P_W;
    if (np & (0x10 | 0x20 | 0x40 | 0x80)) p |= P_X;
    if ((np & 0xFF) == 1) p = 0;
    reg_t* r = reg_find(addr);
    u32 old = r ? r->prot : (P_R | P_W);
    if (oldp) vm_write32(oldp, old);
    reg_setprot(addr, size, p);
    int was_written = 0;
    for (u32 a = addr; a < addr + size; a += PG_SIZE) { u32 i = a >> PG_SHIFT; if (i < PG_COUNT && g_pg[i].written) was_written = 1; }
    blog("保护", "VirtualProtect(0x%X, %u, 0x%X, ...) -> %s写后改成%s", addr, size, np,
         was_written ? "【先前被写过】" : "", (p & P_X) ? "可执行" : "不可执行");
    if (was_written && (p & P_X)) {
        g_oep_candidate = addr & ~(PG_SIZE - 1); g_oep_hits++;
        say("  [疑似 OEP] VirtualProtect 把【被写过】的 0x%08X（%u 字节）改成可执行 —— 典型解壳收尾\n", addr, size);
        tr("OEP\tVirtualProtect\t0x%X\t0x%X\n", addr, size);
    }
    EAX = 1;
}
static void h_VirtualFree(void) { blog("释放", "VirtualFree(0x%X, %u, 0x%X)", A(0), A(1), A(2)); EAX = 1; }
static void h_VirtualQuery(void) {
    u32 addr = A(0), buf = A(1), len = A(2);
    if (buf && len >= 28) {
        u8 mbi[28]; memset(mbi, 0, sizeof(mbi));
        reg_t* r = reg_find(addr);
        u32 base = r ? r->base : (addr & ~0xFFFu), size = r ? r->size : 0x1000;
        memcpy(mbi + 0, &base, 4); memcpy(mbi + 4, &base, 4); memcpy(mbi + 8, &size, 4);
        u32 p = r ? r->prot : (P_R | P_W); u32 wprot = 0x04; if (p & P_X) wprot = 0x40;
        memcpy(mbi + 12, &wprot, 4); u32 st = 0x1000; memcpy(mbi + 16, &st, 4);
        vm_poke(buf, mbi, 28);
    }
    EAX = 28;
}
static void h_GetProcAddress(void) {
    u32 mod = A(0), nm = A(1);
    char name[128];
    if (nm < 0x10000) snprintf(name, sizeof(name), "Ordinal_%u", nm);
    else vm_cstr(nm, name, sizeof(name));
    char dll[64]; snprintf(dll, sizeof(dll), "dyn");
    for (int i = 0; i < g_vmodN; i++) if (g_vmod[i].base == mod) { snprintf(dll, sizeof(dll), "%s", g_vmod[i].name); break; }
    /* 反沙盒：绝不能暴露 Wine 特征（wine_get_version 等）——样本一旦查到就会直接收摊不干活 */
    {
        char low[128]; snprintf(low, sizeof(low), "%s", name);
        for (char* q = low; *q; q++) if (*q >= 'A' && *q <= 'Z') *q = (char)(*q - 'A' + 'a');
        if (strstr(low, "wine")) {
            blog("反沙盒", "★GetProcAddress(0x%X, \"%s\") -> NULL（不暴露 Wine 特征）", mod, name);
            EAX = 0;
            return;
        }
    }
    u32 st = stub_alloc(dll, name);
    blog("动态API", "GetProcAddress(0x%X, \"%s\") -> 0x%08X", mod, name, st);
    EAX = st;
}
static void h_GetModuleFileName(void) {
    u32 buf = A(1), n = A(2);
    u32 len = (u32)strlen(g_sample_path);
    if (n && n <= len) len = n - 1;
    vm_poke(buf, g_sample_path, len); vm_write8(buf + len, 0);
    EAX = len;
}
static vfile_t* vf_find(u32 h) { for (int i = 0; i < g_vfN; i++) if (g_vf[i].handle == h) return &g_vf[i]; return NULL; }
static void h_CreateFile(void) {
    u32 p = A(0); char path[260];
    vm_cstr(p, path, sizeof(path));
    if (!path[0]) vm_wstr(p, path, sizeof(path));
    vfile_t* f = vf_get(path);
    blog("文件", "CreateFile(\"%s\") -> 句柄 0x%X%s", path, f ? f->handle : 0, (f && f->rd) ? "（样本自身，只读）" : "");
    EAX = f ? f->handle : 0xFFFFFFFFu;
}
static void h_WriteFile(void) {
    u32 h = A(0), buf = A(1), n = A(2), pwritten = A(3);
    vfile_t* f = vf_find(h);
    if (f) {
        if (f->len + n > f->cap) { u32 nc = f->len + n + 0x1000; f->data = (u8*)realloc(f->data, nc); f->cap = nc; }
        vm_read(buf, f->data + f->len, n); f->len += n;
    }
    if (pwritten) vm_write32(pwritten, n);
    blog("文件", "WriteFile(句柄 0x%X, %u 字节)%s", h, n, f ? "" : "  [未知句柄]");
    if (f) blog("落盘", "写入 \"%s\" 共 %u 字节", f->path, f->len);
    EAX = 1;
}
static void h_ReadFile(void) {
    u32 h = A(0), buf = A(1), n = A(2), pb = A(3);
    vfile_t* f = vf_find(h);
    u32 got = 0;
    if (f && n) {
        if (f->rd) {
            u8 tmp[4096];
            while (got < n) {
                u32 want = n - got; if (want > sizeof(tmp)) want = sizeof(tmp);
                size_t rd = fread(tmp, 1, want, f->rd);
                if (!rd) break;
                vm_poke(buf + got, tmp, (u32)rd); got += (u32)rd;
            }
        } else if (f->data && f->pos < f->len) {
            got = f->len - f->pos; if (got > n) got = n;
            vm_poke(buf, f->data + f->pos, got); f->pos += got;
        }
    }
    if (pb) vm_write32(pb, got);
    blog("文件", "ReadFile(句柄 0x%X, 请求 %u) -> %u 字节", h, n, got);
    EAX = 1;
}
static void h_GetFileSize(void) { vfile_t* f = vf_find(A(0)); u32 sz = vf_size(f); u32 ph = A(1); if (ph) vm_write32(ph, sz); EAX = sz; }
static void h_CloseHandle(void) { EAX = 1; }

static void h_CreateProcess(void) {
    u32 cmd = A(1); if (!cmd) cmd = A(0);
    char s[256]; vm_cstr(cmd, s, sizeof(s));
    if (!s[0]) vm_wstr(cmd, s, sizeof(s));
    blog("执行", "★企图启动进程：%s", s);
    say("  [执行] ★样本企图启动进程：%s\n", s);
    EAX = 1;
}
static void h_WinExec(void) { char s[256]; vm_cstr(A(0), s, sizeof(s)); blog("执行", "★WinExec(\"%s\", %u)", s, A(1)); say("  [执行] ★WinExec：%s\n", s); EAX = 33; }
static void h_ShellExecute(void) {
    char op[64], file[256]; vm_cstr(A(1), op, sizeof(op)); vm_cstr(A(2), file, sizeof(file));
    blog("执行", "★ShellExecute(\"%s\", \"%s\")", op, file); say("  [执行] ★ShellExecute：%s %s\n", op, file);
    EAX = 42;
}
static void h_URLDownloadToFile(void) {
    char url[512], file[260]; vm_cstr(A(1), url, sizeof(url)); vm_cstr(A(2), file, sizeof(file));
    blog("网络", "★URLDownloadToFile(\"%s\" -> \"%s\")", url, file);
    say("  [网络] ★下载：%s  ->  %s\n", url, file);
    EAX = 0;
}
static void h_InternetOpenUrl(void) { char url[512]; vm_cstr(A(1), url, sizeof(url)); blog("网络", "★InternetOpenUrl(\"%s\")", url); say("  [网络] ★访问：%s\n", url); EAX = 0x00000001; }
static void h_WinHttpConnect(void) { char h[256]; u16 port = (u16)A(2); vm_cstr(A(1), h, sizeof(h)); blog("网络", "★WinHttpConnect(\"%s\", %u)", h, port); say("  [网络] ★连接：%s:%u\n", h, port); EAX = 0x00000002; }
static void h_InternetConnect(void) { char h[256]; vm_cstr(A(1), h, sizeof(h)); blog("网络", "★InternetConnect(\"%s\", %u)", h, (u16)A(2)); say("  [网络] ★连接：%s:%u\n", h, (u16)A(2)); EAX = 0x00000003; }
static void h_connect(void) {
    u32 name = A(1), namelen = A(2);
    u32 ip = 0; u16 port = 0;
    if (namelen >= 8) { u8 b[8]; vm_read(name, b, 8); port = (u16)((b[2] << 8) | b[3]); ip = b[4] | (b[5] << 8) | (b[6] << 16) | ((u32)b[7] << 24); }
    blog("网络", "★socket connect -> %u.%u.%u.%u:%u", ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF, port);
    say("  [网络] ★socket 连接：%u.%u.%u.%u:%u\n", ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF, port);
    EAX = 0;
}
static void h_RegSetValue(void) {
    u32 namep = A(1), type = A(3), datap = A(4), datalen = A(5);
    char nm[256] = "(默认)"; if (namep) vm_cstr(namep, nm, sizeof(nm));
    char val[200] = "";
    if (datap && datalen) {
        if (type == 1 || type == 2) vm_cstr(datap, val, sizeof(val));
        else {
            int o = snprintf(val, sizeof(val), "<%u 字节> ", datalen);
            for (u32 i = 0; i < datalen && i < 24 && o < (int)sizeof(val) - 4; i++) {
                u8 b = 0; if (!vm_read8(datap + i, &b)) break;
                o += snprintf(val + o, sizeof(val) - o, "%02X ", b);
            }
        }
    }
    blog("注册表", "★RegSetValueEx(\"%s\", 类型 %u) = \"%s\"", nm, type, val);
    say("  [注册表] ★写入 %s = %s\n", nm, val);
    EAX = 0;
}
static void h_RegCreateKey(void) { char k[256]; vm_cstr(A(1), k, sizeof(k)); u32 ph = A(6); u32 h = 0x80000001u; if (ph) vm_write32(ph, h); blog("注册表", "RegCreateKeyEx(\"%s\")", k); EAX = 0; }
static void h_IsDebuggerPresent(void) { EAX = 0; }
static void h_CheckRemoteDebugger(void) { u32 p = A(1); if (p) vm_write32(p, 0); EAX = 1; }
static void h_NtQueryInformationProcess(void) {
    u32 cls = A(1), buf = A(2), len = A(3), pret = A(4);
    if (buf && len) { u32 z = 0; vm_write32(buf, z); }
    if (pret) vm_write32(pret, 0);
    blog("反调试", "NtQueryInformationProcess(class=%u) -> 已伪装为 0", cls);
    EAX = 0;
}
static void h_SetUnhandledExceptionFilter(void) { EAX = 0; }
static void h_GetTickCount64(void) { g_tick += 0x137; u64 v = (u64)g_tick; vm_write32(A(0), (u32)v); vm_write32(A(0) + 4, (u32)(v >> 32)); EAX = (u32)v; }
static void h_QueryPerformanceCounter(void) { g_qpc_lo += 0x2710; if (g_qpc_lo < 0x2710) g_qpc_hi++; u32 p = A(0); if (p) { vm_write32(p, g_qpc_lo); vm_write32(p + 4, g_qpc_hi); } EAX = 1; }
static void h_GetSystemTime(void) { u32 p = A(0); if (p) { WORD w[8] = {2026, 10, 3, 17, 12, 34, 5, 300}; vm_poke(p, w, 16); } }
static void h_GetLocalTime(void) { h_GetSystemTime(); }
static void h_GetVersion(void) { EAX = 0x00000A00; }
static void h_GlobalMemoryStatus(void) { u32 p = A(0); if (p) { u8 m[32]; memset(m, 0, sizeof(m)); u32 tot = 0x80000000u, avail = 0x40000000u; memcpy(m + 0, &tot, 4); memcpy(m + 4, &tot, 4); memcpy(m + 8, &avail, 4); vm_poke(p, m, 32); } }
static void h_GetComputerName(void) { u32 b = A(0), n = A(1); const char* s = "DESKTOP-SVM"; u32 l = (u32)strlen(s); vm_poke(b, s, l + 1); if (n) vm_write32(n, l); EAX = 1; }
static void h_GetUserName(void) { u32 b = A(0), n = A(1); const char* s = "admin"; u32 l = (u32)strlen(s); vm_poke(b, s, l + 1); if (n) vm_write32(n, l + 1); EAX = 1; }
static void h_ExitProcess(void) { snprintf(g_stop_reason, sizeof(g_stop_reason), "样本调用 ExitProcess(%u)", A(0)); g_halted = 1; }
static void h_CreateThread(void) { EAX = 0x00001234; blog("线程", "CreateThread（未真起线程，仅记录）"); }
static void h_CreateMutex(void) { EAX = 0x00002000; }
static void h_GetCommandLine(void) {
    static u32 cached = 0;
    if (!cached) { u32 a = vm_alloc_region(0, 0x1000, P_R | P_W, RK_ALLOC, "cmdline"); char s[300]; snprintf(s, sizeof(s), "\"%s\"", g_sample_path); vm_poke(a, s, (u32)strlen(s) + 1); cached = a; }
    EAX = cached;
}
/* 真正的内存/字符串工具（在虚拟内存上实现，避免解释大循环） */
static void h_lstrlen(void) { u32 a = A(0), n = 0; while (n < 0x100000) { u8 b; if (!vm_read8(a + n, &b) || !b) break; n++; } EAX = n; }
static void h_lstrcpy(void) { u32 d = A(0), s = A(1), i = 0; for (; i < 0x100000; i++) { u8 b; if (!vm_read8(s + i, &b)) break; vm_write8(d + i, b); if (!b) break; } EAX = d; }
static void h_lstrcat(void) { u32 d = A(0), s = A(1); u32 n = 0; while (n < 0x100000) { u8 b; if (!vm_read8(d + n, &b) || !b) break; n++; } u32 i = 0; for (; i < 0x100000; i++) { u8 b; if (!vm_read8(s + i, &b)) break; vm_write8(d + n + i, b); if (!b) break; } EAX = d; }
static void h_memcpy(void) { u32 d = A(0), s = A(1), n = A(2); for (u32 i = 0; i < n; i++) { u8 b; if (!vm_read8(s + i, &b)) break; vm_write8(d + i, b); } EAX = d; }
static void h_memset(void) { u32 d = A(0), v = A(1), n = A(2); for (u32 i = 0; i < n; i++) vm_write8(d + i, (u8)v); EAX = d; }
static void h_strlen(void) { h_lstrlen(); }
static void h_Alloc(void) { u32 sz = A(0); if (sz < 0x1000) sz = 0x1000; u32 a = vm_alloc_region(0, (sz + 0xFFF) & ~0xFFFu, P_R | P_W, RK_ALLOC, "HeapAlloc"); EAX = a; }
static void h_GetProcessHeap(void) { EAX = 0x00A00000; }   /* 堆句柄必须非 0，CRT 会检查 */
static void h_GetACP(void) { EAX = 936; }   /* GBK，返回 0 会被当成无效代码页 */
static void h_GetEnvStringsW(void) { u32 p = vm_alloc_region(0, 64, P_R | P_W, RK_ALLOC, "envW"); vm_write16(p, 0); vm_write16(p + 2, 0); EAX = p; }
static void h_GetEnvStringsA(void) { u32 p = vm_alloc_region(0, 64, P_R | P_W, RK_ALLOC, "envA"); vm_write8(p, 0); vm_write8(p + 1, 0); EAX = p; }
static void h_CLRCreateInstance(void) { EAX = 0x80004005; }   /* E_FAIL：让宿主走降级路径，不假装 CLR 可用 */
static void h_CorBindToRuntimeEx(void) { EAX = 0x80004005; } /* 旧版 CLR 绑定：E_FAIL */

/* h_LoadLibrary 的假实现：返回一个稳定的假模块句柄（不能返回 0，否则样本认为加载失败） */
static void h_LoadLibrary(void) {
    u32 name_ptr = A(0);
    char name[256] = {0};
    vm_cstr(name_ptr, name, sizeof(name));
    blog("加载", "LoadLibrary(\"%s\") -> 伪造句柄", name);
    EAX = 0x10000000;
}

typedef void (*api_fn)(void);
typedef struct { const char* name; int nargs; api_fn fn; } api_ent_t;
/* ---- 语义修正的小实现 ---- */
static void h_identity(void) { EAX = A(0); }   /* EncodePointer/DecodePointer：本沙盒不加密，原样返回（返回 1 会让样本跳飞）*/
static void h_GetModuleHandleEx(void) {         /* (dwFlags, lpModuleName, phModule) */
    u32 ph = A(2);
    if (ph) vm_write32(ph, g_imagebase);
    EAX = 1;                                    /* 成功 */
}
static void h_RtlLookupFunctionEntry(void) {    /* (controlPc, &imageBase, &historyTable) */
    u32 pib = A(1), pht = A(2);
    if (pib) vm_write32(pib, g_imagebase);
    if (pht) vm_write32(pht, 0);
    EAX = 0;                                    /* 动态代码没有函数表项：与真机一致 */
}

/* ---- 抽测补充（2026-10-18）：点名缺参数个数的 API + 漏登记的 W 版字符串函数 ---- */
static void h_HttpOpenRequest(void) {           /* (h, verb, object, ver, ref, accept, flags, ctx) */
    char verb[64] = "", obj[600] = "";
    vm_cstr(A(1), verb, sizeof(verb));
    vm_cstr(A(2), obj, sizeof(obj));
    blog("网络", "★HttpOpenRequest(\"%s\", \"%s\")", verb, obj);
    say("  [网络] ★HTTP 请求：%s %s\n", verb[0] ? verb : "GET", obj);
    EAX = 0x00000004;
}
static void h_HttpOpenRequestW(void) {
    char verb[64] = "", obj[600] = "";
    vm_wstr(A(1), verb, sizeof(verb));
    vm_wstr(A(2), obj, sizeof(obj));
    blog("网络", "★HttpOpenRequest(\"%s\", \"%s\")", verb, obj);
    say("  [网络] ★HTTP 请求：%s %s\n", verb[0] ? verb : "GET", obj);
    EAX = 0x00000004;
}
static void h_InternetCloseHandle(void) { EAX = 1; }
static void h_InternetReadFile(void) {          /* (h, buf, toRead, &read)：TRUE + 已读 0 = 数据到底 */
    u32 pr = A(3);
    if (pr) vm_write32(pr, 0);
    EAX = 1;
}
static void h_InternetSetOption(void) { EAX = 1; }
static void h_InternetQueryOption(void) { EAX = 0; }
static void h_lstrlenW(void) { u32 a = A(0), n = 0; while (n < 0x10000) { u16 w = 0; if (!vm_read(a + n * 2, &w, 2) || !w) break; n++; } EAX = n; }
static void h_lstrcpyW(void) { u32 d = A(0), s = A(1); for (u32 i = 0; i < 0x10000; i++) { u16 w = 0; if (!vm_read(s + i * 2, &w, 2)) break; vm_poke(d + i * 2, &w, 2); if (!w) break; } EAX = d; }
static void h_lstrcatW(void) { u32 d = A(0), s = A(1), n = 0; while (n < 0x10000) { u16 w = 0; if (!vm_read(d + n * 2, &w, 2) || !w) break; n++; } for (u32 i = 0; i < 0x10000; i++) { u16 w = 0; if (!vm_read(s + i * 2, &w, 2)) break; vm_poke(d + (n + i) * 2, &w, 2); if (!w) break; } EAX = d; }
static void h_lstrcmpA(void) { u32 a = A(0), b = A(1); for (u32 i = 0; i < 0x10000; i++) { u8 x = 0, y = 0; if (!vm_read8(a + i, &x) || !vm_read8(b + i, &y)) break; if (x != y) { EAX = (x < y) ? (u32)-1 : 1; return; } if (!x) break; } EAX = 0; }
static void h_lstrcmpW(void) { u32 a = A(0), b = A(1); for (u32 i = 0; i < 0x10000; i++) { u16 x = 0, y = 0; if (!vm_read(a + i * 2, &x, 2) || !vm_read(b + i * 2, &y, 2)) break; if (x != y) { EAX = (x < y) ? (u32)-1 : 1; return; } if (!x) break; } EAX = 0; }
static void h_lstrcmpiA(void) { u32 a = A(0), b = A(1); for (u32 i = 0; i < 0x10000; i++) { u8 x = 0, y = 0; if (!vm_read8(a + i, &x) || !vm_read8(b + i, &y)) break; u8 X = (x >= 'a' && x <= 'z') ? (u8)(x - 32) : x, Y = (y >= 'a' && y <= 'z') ? (u8)(y - 32) : y; if (X != Y) { EAX = (X < Y) ? (u32)-1 : 1; return; } if (!x) break; } EAX = 0; }
static void h_lstrcmpiW(void) { u32 a = A(0), b = A(1); for (u32 i = 0; i < 0x10000; i++) { u16 x = 0, y = 0; if (!vm_read(a + i * 2, &x, 2) || !vm_read(b + i * 2, &y, 2)) break; u16 X = (x >= 'a' && x <= 'z') ? (u16)(x - 32) : x, Y = (y >= 'a' && y <= 'z') ? (u16)(y - 32) : y; if (X != Y) { EAX = (X < Y) ? (u32)-1 : 1; return; } if (!x) break; } EAX = 0; }
static void h_ChrCmpIW(void) { EAX = 0; }       /* 返回 0 = 两字符相同 */
static void h_CopyAccelTable(void) { EAX = 0; }
static void h_getmainargs(void) {               /* cdecl：(int* argc, char*** argv, char*** envp, int, void*) */
    static u32 argv_arr = 0, env_arr = 0;
    h_GetCommandLine();
    if (!argv_arr) {
        argv_arr = vm_alloc_region(0, 0x1000, P_R | P_W, RK_ALLOC, "argv");
        if (argv_arr) { vm_write32(argv_arr, EAX); vm_write32(argv_arr + 4, 0); }
        env_arr = vm_alloc_region(0, 0x1000, P_R | P_W, RK_ALLOC, "envp");
        if (env_arr) vm_write32(env_arr, 0);
    }
    {
        u32 pargc = A(0), pargv = A(1), penvp = A(2);
        if (pargc) vm_write32(pargc, 1);
        if (pargv) vm_write32(pargv, argv_arr);
        if (penvp) vm_write32(penvp, env_arr);
    }
    EAX = 0;
}
static void h_p_acmdln(void) {                  /* char** __p__acmdln(void) */
    static u32 cell = 0;
    if (!cell) { cell = vm_alloc_region(0, 0x1000, P_R | P_W, RK_ALLOC, "acmdln"); if (cell) { h_GetCommandLine(); vm_write32(cell, EAX); } }
    EAX = cell;
}
static void h_p_fmode(void) {                   /* int* __p__fmode(void) */
    static u32 cell = 0;
    if (!cell) { cell = vm_alloc_region(0, 0x1000, P_R | P_W, RK_ALLOC, "fmode"); if (cell) vm_write32(cell, 0); }
    EAX = cell;
}
static void h_p_commode(void) {                 /* int* __p__commode(void) */
    static u32 cell = 0;
    if (!cell) { cell = vm_alloc_region(0, 0x1000, P_R | P_W, RK_ALLOC, "commode"); if (cell) vm_write32(cell, 0); }
    EAX = cell;
}
static void h_GetLastInputInfo(void) {          /* (LASTINPUTINFO*)：写 0，返回 TRUE */
    u32 p = A(0);
    if (p) { vm_write32(p, 8); vm_write32(p + 4, 0); }
    EAX = 1;
}
static void h_DuplicateHandle(void) {           /* (..., lpTargetHandle, ...)：给个假句柄，返回 TRUE */
    u32 pt = A(3);
    if (pt) vm_write32(pt, 0x00000500);
    EAX = 1;
}
static void h_CoCreateGuid(void) {              /* (GUID*)：写 0，返回 S_OK */
    u32 p = A(0);
    if (p) { u8 z[16]; memset(z, 0, sizeof(z)); vm_poke(p, z, 16); }
    EAX = 0;
}
static void h_UuidToString(void) {              /* (UUID*, RPC_CSTR* out)：给个假字符串 */
    static u32 cell = 0;
    if (!cell) {
        u32 r = vm_alloc_region(0, 0x1000, P_R | P_W, RK_ALLOC, "uuidstr");
        const char* s = "11111111-2222-3333-4444-555555555555";
        if (r) { vm_poke(r, s, (u32)strlen(s) + 1); cell = r; }
    }
    u32 po = A(1);
    if (po) vm_write32(po, cell);
    EAX = 0;
}

static const api_ent_t g_api[] = {
    { "VirtualAlloc", 4, h_VirtualAlloc }, { "VirtualProtect", 4, h_VirtualProtect },
    { "VirtualFree", 3, h_VirtualFree }, { "VirtualQuery", 3, h_VirtualQuery },
    { "VirtualAllocEx", 5, h_VirtualAlloc }, { "VirtualProtectEx", 5, h_VirtualProtect },
    { "GetProcAddress", 2, h_GetProcAddress },
    { "LoadLibraryA", 1, h_LoadLibrary }, { "LoadLibraryW", 1, h_LoadLibrary },
    { "LoadLibraryExA", 3, h_LoadLibrary }, { "LoadLibraryExW", 3, h_LoadLibrary },
    
    // --- 核心：模块与文件 (指向最新伪装版) ---
    { "GetModuleHandleA", 1, h_GetModuleHandleA }, { "GetModuleHandleW", 1, h_GetModuleHandleA },
    { "GetModuleFileNameA", 3, h_GetModuleFileName }, { "GetModuleFileNameW", 3, h_GetModuleFileName },
    { "CreateFileA", 7, h_CreateFile }, { "CreateFileW", 7, h_CreateFile },
    { "WriteFile", 5, h_WriteFile }, { "ReadFile", 5, h_ReadFile },
    { "GetFileSize", 2, h_GetFileSize }, { "CloseHandle", 1, h_CloseHandle },
    { "CreateDirectoryA", 2, h_ret1 }, { "CreateDirectoryW", 2, h_ret1 },
    { "DeleteFileA", 1, h_ret1 }, { "DeleteFileW", 1, h_ret1 },
    { "CopyFileA", 3, h_ret1 }, { "MoveFileA", 2, h_ret1 }, { "MoveFileW", 2, h_ret1 },
    { "SetFileAttributesA", 2, h_ret1 }, { "SetFileAttributesW", 2, h_ret1 },
    { "FindFirstFileA", 2, h_ret0 }, { "FindFirstFileW", 2, h_ret0 },
    
    // --- 高危行为 (执行与网络) ---
    { "CreateProcessA", 10, h_CreateProcess }, { "CreateProcessW", 10, h_CreateProcess },
    { "WinExec", 2, h_WinExec }, { "ShellExecuteA", 6, h_ShellExecute }, { "ShellExecuteW", 6, h_ShellExecute },
    { "ShellExecuteExA", 1, h_ret1 }, { "ShellExecuteExW", 1, h_ret1 },
    { "URLDownloadToFileA", 5, h_URLDownloadToFile }, { "URLDownloadToFileW", 5, h_URLDownloadToFile },
    { "InternetOpenUrlA", 6, h_InternetOpenUrl }, { "InternetOpenUrlW", 6, h_InternetOpenUrl },
    
    // --- 沙盒伪装与反沙盒 API ---
    { "GetKeyboardType", 1, h_GetKeyboardType },
    { "GetTickCount", 0, h_GetTickCount },
    { "GetTickCount64", 1, h_GetTickCount64 },
    { "GetSystemInfo", 1, h_GetSystemInfo },
    { "GetNativeSystemInfo", 1, h_GetSystemInfo },
    { "GetSystemDirectoryA", 2, h_GetSystemDirectoryA },
    { "GetSystemDirectoryW", 2, h_GetSystemDirectoryA },
    { "GetVolumeInformationA", 8, h_GetVolumeInformation },
    { "GetVolumeInformationW", 8, h_GetVolumeInformation },
    { "GetUserNameA", 2, h_GetUserNameA },
    { "GetUserNameW", 2, h_GetUserNameA },
    { "GetForegroundWindow", 0, h_GetForegroundWindow },
    { "FindWindowA", 2, h_FindWindowA },
    { "FindWindowW", 2, h_FindWindowW },
    { "EnumWindows", 2, h_EnumWindows },
    { "GetAdaptersInfo", 2, h_GetAdaptersInfo },
    { "NtQueryInformationProcess", 5, h_NtQueryInformationProcess },
    { "GetThreadLocale", 0, h_ret_LCID }, { "GetSystemDefaultLCID", 0, h_ret_LCID },

    /* ---- 恢复：只要登记了名字就必须给对参数个数，否则 stdcall 栈会错位 ---- */
    { "system", -1, h_ret1 }, { "InternetConnectA", 8, h_InternetConnect },
    { "InternetConnectW", 8, h_InternetConnect }, { "WinHttpConnect", 4, h_WinHttpConnect },
    { "InternetOpenA", 5, h_ret1 }, { "InternetOpenW", 5, h_ret1 },
    { "InternetCloseHandle", 1, h_InternetCloseHandle }, { "HttpOpenRequestA", 8, h_HttpOpenRequest },
    { "HttpOpenRequestW", 8, h_HttpOpenRequestW }, { "InternetSetOptionA", 4, h_InternetSetOption },
    { "InternetSetOptionW", 4, h_InternetSetOption }, { "InternetQueryOptionA", 4, h_InternetQueryOption },
    { "InternetGetCookieA", 4, h_ret0 }, { "InternetGetCookieW", 4, h_ret0 },
    { "InternetSetCookieA", 3, h_ret1 }, { "InternetSetCookieW", 3, h_ret1 },
    { "ObtainUserAgentString", 3, h_ret0 },
    { "InternetReadFile", 4, h_InternetReadFile }, { "HttpSendRequestA", 5, h_ret1 },
    { "HttpSendRequestW", 5, h_ret1 }, { "WinHttpOpenRequest", 7, h_ret1 },
    { "WinHttpSendRequest", 7, h_ret1 }, { "WSAStartup", 2, h_ret0 },
    { "socket", 3, h_ret0 }, { "connect", 3, h_connect },
    { "send", 4, h_ret1 }, { "recv", 4, h_ret0 },
    { "closesocket", 1, h_ret0 }, { "gethostbyname", 1, h_ret0 },
    { "inet_addr", 1, h_ret0 }, { "RegCreateKeyExA", 9, h_RegCreateKey },
    { "RegCreateKeyExW", 9, h_RegCreateKey }, { "RegOpenKeyExA", 5, h_RegCreateKey },
    { "RegOpenKeyExW", 5, h_RegCreateKey }, { "RegSetValueExA", 6, h_RegSetValue },
    { "RegSetValueExW", 6, h_RegSetValue }, { "RegCloseKey", 1, h_ret0 },
    { "RegDeleteValueA", 2, h_ret0 }, { "IsDebuggerPresent", 0, h_IsDebuggerPresent },
    { "CheckRemoteDebuggerPresent", 2, h_CheckRemoteDebugger }, { "SetUnhandledExceptionFilter", 1, h_SetUnhandledExceptionFilter },
    { "UnhandledExceptionFilter", 1, h_ret0 }, { "QueryPerformanceCounter", 1, h_QueryPerformanceCounter },
    { "GetSystemTime", 1, h_GetSystemTime }, { "GetLocalTime", 1, h_GetLocalTime },
    { "GetVersion", 0, h_GetVersion }, { "GlobalMemoryStatus", 1, h_GlobalMemoryStatus },
    { "GetComputerNameA", 2, h_GetComputerName }, { "GetComputerNameW", 2, h_GetComputerName },
    { "ExitProcess", 1, h_ExitProcess }, { "TerminateProcess", 2, h_ExitProcess },
    { "CreateThread", 6, h_CreateThread }, { "CreateRemoteThread", 7, h_CreateThread },
    { "CreateMutexA", 3, h_CreateMutex }, { "CreateMutexW", 3, h_CreateMutex },
    { "GetCommandLineA", 0, h_GetCommandLine }, { "GetCommandLineW", 0, h_GetCommandLine },
    { "Sleep", 1, h_ret0 }, { "SleepEx", 2, h_ret0 },
    { "GetLastError", 0, h_ret0 }, { "SetLastError", 1, h_ret0 },
    { "GetCurrentProcess", 0, h_ret0 }, { "GetCurrentProcessId", 0, h_ret0 },
    { "GetCurrentThread", 0, h_ret0 }, { "GetCurrentThreadId", 0, h_ret0 },
    { "WaitForSingleObject", 2, h_ret0 }, { "GetProcessHeap", 0, h_GetProcessHeap },
    { "HeapCreate", 3, h_GetProcessHeap }, { "HeapAlloc", 3, h_Alloc },
    { "HeapFree", 3, h_ret1 }, { "HeapReAlloc", 4, h_Alloc },
    { "GlobalAlloc", 2, h_Alloc }, { "LocalAlloc", 2, h_Alloc },
    { "LocalFree", 1, h_ret0 }, { "GlobalFree", 1, h_ret0 },
    { "lstrlenA", 1, h_lstrlen }, { "lstrlenW", 1, h_lstrlenW },
    { "lstrcpyA", 2, h_lstrcpy }, { "lstrcatA", 2, h_lstrcat },
    { "lstrcpyW", 2, h_lstrcpyW }, { "lstrcatW", 2, h_lstrcatW },
    { "lstrcmpA", 2, h_lstrcmpA }, { "lstrcmpW", 2, h_lstrcmpW },
    { "lstrcmpiA", 2, h_lstrcmpiA }, { "lstrcmpiW", 2, h_lstrcmpiW },
    { "memcpy", -1, h_memcpy }, { "memmove", -1, h_memcpy },
    { "memset", -1, h_memset }, { "strlen", -1, h_strlen },
    { "RtlZeroMemory", 2, h_memset }, { "RtlMoveMemory", 3, h_memcpy },
    { "OutputDebugStringA", 1, h_ret0 }, { "OutputDebugStringW", 1, h_ret0 },
    { "GetEnvironmentVariableA", 3, h_ret0 }, { "GetEnvironmentStrings", 0, h_ret0 },
    { "FreeLibrary", 1, h_ret1 }, { "GetExitCodeProcess", 2, h_ret0 },
    { "SetPriorityClass", 2, h_ret1 }, { "SetThreadPriority", 2, h_ret1 },
    { "AdjustTokenPrivileges", 6, h_ret1 }, { "OpenProcessToken", 3, h_ret1 },
    { "LookupPrivilegeValueA", 3, h_ret1 }, { "LoadLibraryEx", 3, h_LoadLibrary },
    { "GetSystemMetrics", 1, h_ret0 }, { "GetACP", 0, h_GetACP },
    { "GetOEMCP", 0, h_GetACP }, { "GetCPInfo", 2, h_ret0 },
    { "GetLocaleInfoA", 4, h_ret0 }, { "GetLocaleInfoW", 4, h_ret0 },
    { "GetTimeZoneInformation", 1, h_ret0 }, { "SetErrorMode", 1, h_ret0 },
    { "SetConsoleCtrlHandler", 2, h_ret1 }, { "GetStdHandle", 1, h_ret0 },
    { "WriteConsoleA", 5, h_ret1 }, { "WriteConsoleW", 5, h_ret1 },
    { "SetHandleCount", 1, h_ret0 }, { "GetStartupInfoA", 1, h_GetStartupInfo },
    { "GetStartupInfoW", 1, h_GetStartupInfo },
    { "TlsAlloc", 0, h_ret0 }, { "TlsSetValue", 2, h_ret1 },
    { "TlsGetValue", 1, h_ret0 }, { "InterlockedIncrement", 1, h_ret1 },
    { "InterlockedDecrement", 1, h_ret1 }, { "InterlockedCompareExchange", 3, h_ret1 },
    { "InterlockedExchange", 2, h_ret1 }, { "GetProcessAffinityMask", 3, h_ret1 },
    { "SetThreadAffinityMask", 2, h_ret1 }, { "IsProcessorFeaturePresent", 1, h_ret1 },
    { "CreateEventA", 4, h_ret0 }, { "CreateEventW", 4, h_ret0 },
    { "SetEvent", 1, h_ret1 }, { "ResetEvent", 1, h_ret1 },
    { "OpenEventA", 3, h_ret0 }, { "GetFileAttributesA", 1, h_ret0 },
    { "GetFileAttributesW", 1, h_ret0 }, { "SetCurrentDirectoryA", 1, h_ret1 },
    { "SetCurrentDirectoryW", 1, h_ret1 }, { "GetCurrentDirectoryA", 2, h_ret0 },
    { "GetFullPathNameA", 4, h_ret0 }, { "GetShortPathNameA", 3, h_ret0 },
    { "GetTempPathA", 2, h_ret0 }, { "GetTempPathW", 2, h_ret0 },
    { "GetTempFileNameA", 4, h_ret0 }, { "GetWindowsDirectoryA", 2, h_ret0 },
    { "MultiByteToWideChar", 6, h_ret0 }, { "WideCharToMultiByte", 8, h_ret0 },
    { "CharUpperA", 1, h_ret0 }, { "CharLowerA", 1, h_ret0 },
    { "GetUserDefaultLCID", 0, h_ret0 }, { "GlobalLock", 1, h_ret0 },
    { "GlobalUnlock", 1, h_ret1 }, { "LocalLock", 1, h_ret0 },
    { "LocalUnlock", 1, h_ret1 }, { "InitializeCriticalSection", 1, h_ret0 },
    { "InitializeSListHead", 1, h_ret0 }, { "InitializeCriticalSectionAndSpinCount", 2, h_ret1 }, { "EnterCriticalSection", 1, h_ret0 },
    { "GetEnvironmentStringsA", 0, h_GetEnvStringsA }, { "GetEnvironmentStringsW", 0, h_GetEnvStringsW },
    { "CLRCreateInstance", 3, h_CLRCreateInstance }, { "CorBindToRuntimeEx", 6, h_CorBindToRuntimeEx },
    { "FreeEnvironmentStringsA", 1, h_ret1 }, { "FreeEnvironmentStringsW", 1, h_ret1 },
    { "LeaveCriticalSection", 1, h_ret0 }, { "DeleteCriticalSection", 1, h_ret0 },
    { "ReleaseMutex", 1, h_ret1 }, { "CreateSemaphoreA", 4, h_ret0 },
    { "ReleaseSemaphore", 3, h_ret1 }, { "CreateFileMappingA", 6, h_ret0 },
    { "CreateFileMappingW", 6, h_ret0 }, { "MapViewOfFile", 5, h_ret0 },
    { "UnmapViewOfFile", 1, h_ret1 }, { "FlushFileBuffers", 1, h_ret1 },
    { "GetFileSizeEx", 2, h_ret0 }, { "SetFilePointer", 4, h_ret0 },
    { "SetFilePointerEx", 5, h_ret0 }, { "AppendFile", 0, h_ret0 },
    { "CreateFileMapping", 6, h_ret0 }, { "FindNextFileA", 2, h_ret0 },
    { "FindClose", 1, h_ret1 }, { "GetWindowsDirectoryW", 2, h_ret0 },
    { "ExpandEnvironmentStringsA", 3, h_ret0 }, { "ExpandEnvironmentStringsW", 3, h_ret0 },
    { "GetFileVersionInfoSizeA", 2, h_ret0 }, { "GetFileVersionInfoA", 4, h_ret0 },
    { "VerQueryValueA", 4, h_ret0 }, { "RegQueryValueExA", 6, h_ret0 },
    { "RegQueryValueExW", 6, h_ret0 }, { "RegEnumKeyExA", 8, h_ret0 },
    { "RegDeleteKeyA", 2, h_ret0 }, { "RegDeleteValueW", 2, h_ret0 },
    { "RegOpenKeyA", 3, h_ret0 }, { "RegOpenKeyW", 3, h_ret0 },
    { "RegCreateKeyA", 3, h_ret0 }, { "CopyFileW", 3, h_ret1 },
    { "MoveFileExA", 3, h_ret1 }, { "CreateToolhelp32Snapshot", 2, h_ret0 },
    { "Process32First", 2, h_ret0 }, { "Process32Next", 2, h_ret0 },
    { "Process32FirstW", 2, h_ret0 }, { "Process32NextW", 2, h_ret0 },
    { "Module32First", 2, h_ret0 }, { "Module32Next", 2, h_ret0 },
    { "Thread32First", 2, h_ret0 }, { "Thread32Next", 2, h_ret0 },
    { "OpenProcess", 3, h_ret0 }, { "ReadProcessMemory", 5, h_ret0 },
    { "WriteProcessMemory", 5, h_ret0 }, { "GetThreadContext", 2, h_ret0 },
    { "SetThreadContext", 2, h_ret0 }, { "ResumeThread", 1, h_ret0 },
    { "SuspendThread", 1, h_ret0 }, { "LookupPrivilegeValueW", 3, h_ret1 },
    { "GetTokenInformation", 5, h_ret0 }, { "IsWow64Process", 2, h_ret1 },
    { "GetModuleHandleExA", 3, h_GetModuleHandleEx }, { "EnumProcessModules", 4, h_ret0 },
    { "GetModuleBaseNameA", 4, h_ret0 }, { "GetModuleBaseNameW", 4, h_ret0 },
    { "LoadStringA", 4, h_ret0 }, { "GetKeyState", 1, h_ret0 },
    { "GetAsyncKeyState", 1, h_ret0 }, { "GetCursorPos", 1, h_ret0 },
    { "SetWindowsHookExA", 4, h_ret0 }, { "CallNextHookEx", 4, h_ret0 },
    { "UnhookWindowsHookEx", 1, h_ret1 }, { "GetWindowTextA", 3, h_ret0 },
    { "MessageBoxA", 4, h_ret1 }, { "MessageBoxW", 4, h_ret1 },
    { "GetPrivateProfileStringA", 6, h_ret0 }, { "WritePrivateProfileStringA", 4, h_ret1 },
    { "GetTempFileNameW", 4, h_ret0 }, { "GetShortPathNameW", 3, h_ret0 },
    { "QueryPerformanceFrequency", 1, h_ret0 }, { "FreeEnvironmentStringsA", 1, h_ret1 },
    { "GetConsoleMode", 2, h_ret1 }, { "GetConsoleWindow", 0, h_ret0 },
    { "GetConsoleOutputCP", 0, h_GetACP }, { "GetSystemTimeAsFileTime", 1, h_GetSystemTime },
    { "GetSystemTimes", 3, h_ret0 }, { "CryptAcquireContextA", 5, h_ret0 },
    { "CryptGenRandom", 3, h_ret1 }, { "CryptReleaseContext", 2, h_ret1 },
    { "CryptEncrypt", 7, h_ret0 }, { "CryptDecrypt", 7, h_ret0 },
    { "CryptCreateHash", 5, h_ret0 }, { "CryptHashData", 4, h_ret0 },
    { "CryptDeriveKey", 5, h_ret0 }, { "CryptDestroyHash", 1, h_ret1 },
    { "CryptDestroyKey", 1, h_ret1 }, { "CryptImportKey", 6, h_ret0 },
    { "CryptExportKey", 6, h_ret0 }, { "CryptGetHashParam", 5, h_ret0 },
    { "BCryptGenRandom", 3, h_ret0 }, { "WSACleanup", 0, h_ret0 },
    { "getaddrinfo", 4, h_ret0 }, { "freeaddrinfo", 1, h_ret0 },
    { "htons", 1, h_ret0 }, { "inet_ntoa", 1, h_ret0 },
    { "WSAIoctl", 7, h_ret0 }, { "CreatePipe", 4, h_ret0 },
    { "PeekNamedPipe", 5, h_ret0 }, { "GetLogicalDrives", 0, h_ret0 },
    { "GetDriveTypeA", 1, h_ret0 }, { "GetDiskFreeSpaceExA", 4, h_ret1 },
    { "ReadConsoleA", 5, h_ret1 }, { "QueryFullProcessImageNameA", 4, h_ret0 },
    { "CreateEnvironmentBlock", 3, h_ret0 }, { "DestroyEnvironmentBlock", 1, h_ret1 },
    { "SetProcessAffinityMask", 2, h_ret1 }, { "Wow64DisableWow64FsRedirection", 1, h_ret0 },

    /* ---- 补充（回归实测出现过的未知项；stdcall 正数，cdecl 用 -1）---- */
    { "SetDllDirectoryW", 1, h_ret1 }, { "SetDefaultDllDirectories", 1, h_ret1 },
    { "SetSearchPathMode", 1, h_ret1 }, { "SetProcessDEPPolicy", 1, h_ret1 },
    { "InitCommonControls", 0, h_ret0 }, { "CharNextW", 1, h_ret0 },
    { "CharNextA", 1, h_ret0 }, { "GetLongPathNameW", 3, h_ret0 },
    { "GetLongPathNameA", 3, h_ret0 }, { "lstrcpynW", 3, h_lstrcpy },
    { "lstrcpynA", 3, h_lstrcpy },
    { "VerifyVersionInfoW", 3, h_ret0 }, { "VerifyVersionInfoA", 3, h_ret0 },
    { "VerSetConditionMask", 3, h_ret0 },
    { "GetVersionExW", 1, h_ret0 }, { "GetVersionExA", 1, h_ret0 },
    { "InitializeCriticalSectionEx", 3, h_ret1 },
    { "OleInitialize", 1, h_ret0 }, { "OleUninitialize", 0, h_ret0 },
    { "SHGetFileInfoW", 5, h_ret0 }, { "SHGetFileInfoA", 5, h_ret0 },
    { "_initterm", -1, h_ret0 }, { "_initterm_e", -1, h_ret0 },
    { "_crt_atexit", -1, h_ret0 }, { "atexit", -1, h_ret0 }, { "_onexit", -1, h_ret0 },
    { "malloc", -1, h_Alloc }, { "calloc", -1, h_Alloc }, { "realloc", -1, h_Alloc },
    { "free", -1, h_ret0 }, { "srand", -1, h_ret0 }, { "rand", -1, h_ret0 },
    { "wsprintfA", -1, h_ret0 }, { "wsprintfW", -1, h_ret0 },
    { "_set_invalid_parameter_handler", -1, h_ret0 },

    /* ---- 补充二：解壳器/加载器/异常与 TLS-FLS 常见项（stdcall）---- */
    { "CharPrevW", 1, h_ret0 }, { "CharPrevA", 1, h_ret0 },
    { "FlsAlloc", 1, h_ret0 }, { "FlsFree", 1, h_ret1 },
    { "FlsGetValue", 1, h_ret0 }, { "FlsSetValue", 2, h_ret1 },
    { "TlsFree", 1, h_ret1 },
    { "AddVectoredExceptionHandler", 2, h_ret1 }, { "RemoveVectoredExceptionHandler", 1, h_ret1 },
    { "SetThreadStackGuarantee", 1, h_ret1 },
    { "RtlCaptureContext", 1, h_ret0 }, { "RtlLookupFunctionEntry", 3, h_RtlLookupFunctionEntry },
    { "RtlVirtualUnwind", 6, h_ret0 }, { "RtlUnwind", 4, h_ret0 }, { "RtlUnwindEx", 6, h_ret0 },
    { "RtlAddFunctionTable", 3, h_ret1 }, { "RtlDeleteFunctionTable", 1, h_ret1 },
    { "_except_handler4_common", 5, h_ret0 }, { "__C_specific_handler", 5, h_ret0 },
    { "__security_check_cookie", 1, h_ret0 }, { "_guard_dispatch_icall", 0, h_ret0 },
    { "_guard_check_icall", 1, h_ret0 },
    { "EncodePointer", 1, h_identity }, { "DecodePointer", 1, h_identity },
    { "SetProcessMitigationPolicy", 2, h_ret1 }, { "GetProcessMitigationPolicy", 3, h_ret0 },
    { "SetThreadErrorMode", 2, h_ret1 }, { "GetErrorMode", 0, h_ret0 },
    { "GetSystemTimePreciseAsFileTime", 1, h_GetSystemTime },
    { "SystemTimeToFileTime", 2, h_ret1 },
    { "GetCurrentProcessorNumber", 0, h_ret0 },
    { "SetConsoleOutputCP", 1, h_ret1 }, { "SetConsoleCP", 1, h_ret1 },
    { "GetUserDefaultUILanguage", 0, h_ret0 }, { "GetSystemDefaultUILanguage", 0, h_ret0 },
    { "SetThreadUILanguage", 1, h_ret0 },
    { "LCMapStringW", 6, h_ret0 }, { "CompareStringW", 6, h_ret0 },
    { "GetModuleHandleExW", 3, h_GetModuleHandleEx },
    { "Wow64RevertWow64FsRedirection", 1, h_ret0 },
    { "GetFileAttributesExW", 3, h_ret0 }, { "GetFileAttributesExA", 3, h_ret0 },
    { "FindFirstFileExA", 6, h_ret0 }, { "FindFirstFileExW", 6, h_ret0 },
    { "MoveFileExW", 3, h_ret1 }, { "GetFullPathNameW", 4, h_ret0 },
    { "GetDiskFreeSpaceExW", 4, h_ret1 }, { "GetLogicalDriveStringsA", 2, h_ret0 },
    { "PathFileExistsW", 1, h_ret0 }, { "PathCombineW", 3, h_ret0 },
    { "PathRemoveFileSpecW", 1, h_ret1 }, { "PathIsDirectoryW", 1, h_ret0 },
    { "SHGetFolderPathW", 5, h_ret0 }, { "SHGetSpecialFolderPathW", 4, h_ret1 },
    { "StrCmpIW", 2, h_ret0 }, { "StrStrIW", 2, h_ret0 }, { "StrStrW", 2, h_ret0 },
    { "RegQueryInfoKeyA", 12, h_ret0 }, { "RegEnumValueA", 8, h_ret0 },
    { "RegGetValueA", 6, h_ret0 }, { "RegGetValueW", 6, h_ret0 },
    { "GetProcessTimes", 5, h_ret1 }, { "GetThreadTimes", 5, h_ret1 },
    { "WaitForMultipleObjects", 3, h_ret0 },
    { "CreateJobObjectA", 2, h_ret0 }, { "SetInformationJobObject", 4, h_ret1 },
    { "AssignProcessToJobObject", 2, h_ret1 },
    { "CreateProcessAsUserW", 11, h_CreateProcess },
    { "OpenMutexA", 3, h_ret0 }, { "OpenMutexW", 3, h_ret0 }, { "OpenSemaphoreA", 3, h_ret0 },
    { "SetInformationThread", 4, h_ret0 },
    { "GetOverlappedResult", 4, h_ret1 }, { "DeviceIoControl", 8, h_ret1 },
    { "CreateNamedPipeA", 8, h_ret0 }, { "ConnectNamedPipe", 2, h_ret0 },
    { "DisconnectNamedPipe", 1, h_ret1 }, { "SetEndOfFile", 1, h_ret1 },
    { "HeapSetInformation", 2, h_ret1 }, { "HeapValidate", 3, h_ret1 },
    { "GetFileInformationByHandle", 2, h_ret1 },
    { "FindResourceA", 3, h_ret0 }, { "FindResourceW", 3, h_ret0 },
    { "LoadResource", 2, h_ret0 }, { "LockResource", 1, h_ret0 }, { "SizeofResource", 2, h_ret0 },
    { "GetLastInputInfo", 1, h_GetLastInputInfo },
    { "VirtualFreeEx", 4, h_ret1 }, { "IsBadReadPtr", 2, h_ret0 }, { "DuplicateHandle", 7, h_DuplicateHandle },
    { "CoCreateGuid", 1, h_CoCreateGuid }, { "UuidToStringA", 2, h_UuidToString }, { "StrStrA", 2, h_ret0 },
    { "CopyAcceleratorTableA", 3, h_CopyAccelTable }, { "AllowSetForegroundWindow", 1, h_ret1 },
    { "ChrCmpIW", 2, h_ChrCmpIW },
    { "__getmainargs", -1, h_getmainargs }, { "_getmainargs", -1, h_getmainargs },
    { "_wgetmainargs", -1, h_getmainargs }, { "__p__acmdln", 0, h_p_acmdln },
    { "__p__fmode", 0, h_p_fmode }, { "__p__commode", 0, h_p_commode },
    { "__set_app_type", -1, h_ret0 }, { "_controlfp", -1, h_ret0 },
    { "RtlDecompressBuffer", 6, h_ret0 },
    { "GetConsoleAliasExesLengthW", 0, h_ret0 }, { "GetConsoleAliasExesLengthA", 0, h_ret0 },
    { "GetSysColor", 1, h_ret0 },

    { NULL, 0, NULL }
};
static int g_api_calls = 0;
/* 未登记参数个数的 API：栈无法平衡。这是"取指越界 @很小的值"最常见的原因，必须留下线索 */
static char g_unk_last[4][64];
static int  g_unk_n = 0, g_unk_total = 0;
static void unk_api_note(const char* name) {
    memmove(g_unk_last[1], g_unk_last[0], sizeof(g_unk_last[0]) * 3);
    snprintf(g_unk_last[0], sizeof(g_unk_last[0]), "%s", name);
    if (g_unk_n < 4) g_unk_n++;
    g_unk_total++;
}
static const char* unk_api_hint(void) {
    static char b[320];
    b[0] = 0; int o = 0;
    for (int i = 0; i < g_unk_n; i++) o += snprintf(b + o, sizeof(b) - (size_t)o, "%s%s", i ? ", " : "", g_unk_last[i]);
    return b;
}
/* 判断“样本跳到假 API 桩”的那条指令是 CALL 还是 JMP。
 *
 * 不能只看栈顶：CALL 会压返回地址，JMP [IAT] 尾调用不会。
 * x32_last_rec() 在每条指令执行前记录 EIP + 前 10 字节；当 EIP 落到桩上时，
 * 上一条记录就是真正把控制流送进桩的指令。这里只解码它的 opcode/ModRM：
 *   E8 / 9A / FF /2 /3  -> CALL
 *   E9 / EB / FF /4 /5 / C3 / C2 / Jcc / loop -> JMP/RET（不压返回地址）
 */
static int stub_entry_was_call(void) {
    long n = g_lastn32;
    long idx;
    const u8 *b;
    int i = 0;

    if (n < 2) return 0;                       /* 入口直接落在桩上：按 JMP 处理 */
    idx = (n - 2) % XLAST32;
    if (idx < 0) idx += XLAST32;
    b = g_last32[idx].b;

    /* 跳过 legacy 前缀（66/67/F0/F2/F3/段前缀），最多到第 8 字节。 */
    while (i < 8) {
        u8 p = b[i];
        if (p == 0x66 || p == 0x67 || p == 0xF0 || p == 0xF2 || p == 0xF3 ||
            p == 0x2E || p == 0x36 || p == 0x3E || p == 0x26 || p == 0x64 || p == 0x65) {
            i++;
        } else {
            break;
        }
    }
    if (b[i] == 0xE8 || b[i] == 0x9A) return 1; /* call rel32 / call far */
    if (b[i] == 0xFF) {
        int reg = (b[i + 1] >> 3) & 7;
        if (reg == 2 || reg == 3) return 1;     /* call r/m, call far */
    }
    return 0;                                   /* jmp / ret / jcc / loop ... */
}

/* 判断一个地址能否作为 API 返回后的续跑点：必须是可执行页，或者是退栈哨兵。 */
static int api_resume_ok(u32 addr) {
    u32 pg;
    if (addr == EXIT_MAGIC) return 1;
    if (addr == 0) return 0;
    pg = addr >> PG_SHIFT;
    if (pg >= PG_COUNT || !g_pg[pg].p) return 0;
    return (g_pg[pg].prot & P_X) != 0;
}

/* api_dispatch —— 假 API 桩的统一调度。
 *
 * 进入本函数时 EIP 指向桩地址，ESP 的布局分两种：
 *   CALL [IAT]  ：call 指令已经压入返回地址 -> [ESP] = 返回地址，参数在 [ESP+4 ...]
 *   JMP  [IAT]  ：尾调用，本函数（被 jmp 掉的那个）的返回地址就是调用方压的
 *                 -> 对 API 而言 [ESP] 同样是返回地址，参数在 [ESP+4 ...]
 * 两种情况下被调 API 的 "ret n" 都会弹掉 1 个返回地址和 n 个 stdcall 参数，
 * 所以栈回卷量完全一致：ESP += 4 + 4*nargs。
 * 之前 JMP 分支只把 EIP 设成 [ESP] 而不回卷栈，返回地址会永久留在栈上，
 * 后续某条 ret 就会把参数（典型是 0x00000002）弹进 EIP —— 即 0x2 越界。
 * nargs < 0（表里写 -1）表示 cdecl：参数由调用方清理，这里只弹返回地址。
 */
static int api_dispatch(void) {
    imp_t* im = stub_lookup(EIP);
    if (!im) return 0;
    const char* name = im->name;
    int from_call = stub_entry_was_call();
    u32 ret = peek32(ESP);              /* 栈顶：返回地址（CALL/JMP 语义相同） */
    u32 esp_in = ESP;                   /* 进入桩时的栈指针，回卷以它为基准 */

    if (!_stricmp(name, "_CorExeMain") || !_stricmp(name, "_CorDllMain")) {
        blog("托管", "★.NET 程序集入口 %s：x86 解释器不适用，需按 IL 分析", name);
        say("  [托管] ★.NET 程序集（入口 %s）：x86 解释器到此为止，需 IL 静态/仿真分析\n", name);
        snprintf(g_stop_reason, sizeof(g_stop_reason), "托管程序集（.NET），x86 解释器不适用");
        g_halted = 1;
        return 0;
    }

    api_fn fn = NULL; int nargs = 0;
    for (int i = 0; g_api[i].name; i++) if (!_stricmp(g_api[i].name, name)) { fn = g_api[i].fn; nargs = g_api[i].nargs; break; }
    g_api_calls++;
    if (fn) fn();
    else { blog("API未实现", "%s!%s -> 返回 0（参数个数未知，按 0 处理；此调用之后栈可能错位）", im->dll, name); EAX = 0; nargs = 0; unk_api_note(name); }
    if (getenv("PEVM_API_LOG"))
        fprintf(stderr, "[API] %s via %s -> EAX=0x%X ret=0x%X ESP=0x%X nargs=%d\n",
                name, from_call ? "CALL" : "JMP", (unsigned)EAX, (unsigned)ret, (unsigned)esp_in, nargs);

    /* 续跑地址：正常就是栈顶那个返回地址。 */
    u32 next = ret;

    /* 防御：JMP 形态里偶尔会由调用方自己 push 参数后再 jmp（无返回地址压栈），
     * 此时 [ESP] 是普通参数（例如 2），直接当 EIP 用就会跳到 0x00000002。
     * 只有在主路径明显不可执行、且参数个数已知时才做一次保守修正：
     * 参数上方那一格才是真正的返回地址；栈回卷量不变（同样吃掉返回地址 + nargs 个参数）。 */
    if (!api_resume_ok(next) && nargs > 0) {
        u32 alt = peek32(esp_in + 4u * (u32)nargs);
        if (api_resume_ok(alt)) {
            blog("栈修正", "%s!%s 的 [ESP]=0x%08X 不是可执行返回地址，改用参数上方的 0x%08X 续跑",
                 im->dll, name, (unsigned)next, (unsigned)alt);
            next = alt;
        }
    }

    if (next == EXIT_MAGIC) {
        snprintf(g_stop_reason, sizeof(g_stop_reason), "样本在 API 调用后结束（回到返回哨兵）");
        g_halted = 1;
        return 0;
    }
    if (!api_resume_ok(next)) {
        snprintf(g_stop_reason, sizeof(g_stop_reason), "API 返回地址 0x%08X 不是可执行内存（样本实现可能在被调用的系统 DLL 内）", next);
        g_halted = 1;
        return 0;
    }

    /* 统一栈回卷：弹返回地址（4）；stdcall 再按 nargs 清参数；cdecl（nargs<0）不动参数。 */
    EIP = next;
    ESP = esp_in + 4;
    if (nargs > 0) ESP += 4u * (u32)nargs;
    return 1;
}

static void setup_thread_env(const char* samplePath) {
    snprintf(g_sample_path, sizeof(g_sample_path), "%s", samplePath);
    u32 stk = vm_alloc_region(0x00100000, 0x00100000, P_R | P_W, RK_STACK, "线程栈");
    ESP = stk + 0x000F0000;
    u32 teb = vm_alloc_region(0x7FFD0000, 0x2000, P_R | P_W, RK_ALLOC, "TEB");
    u32 peb = vm_alloc_region(0x7FFD2000, 0x2000, P_R | P_W, RK_ALLOC, "PEB");
    u32 ldr = vm_alloc_region(0x7FFD4000, 0x2000, P_R | P_W, RK_ALLOC, "Ldr");
    g_fsbase = teb;
    vm_write32(teb + 0x00, 0xFFFFFFFFu);
    vm_write32(teb + 0x04, stk + 0x00100000);
    vm_write32(teb + 0x08, stk);
    vm_write32(teb + 0x18, teb);
    vm_write32(teb + 0x30, peb);
    vm_write8(peb + 0x02, 0);
    vm_write32(peb + 0x08, g_imagebase);
    vm_write32(peb + 0x0C, ldr);
    vm_write32(peb + 0x68, 0);
    vm_write32(ldr + 0x14, ldr + 0x14);
    vm_write32(ldr + 0x18, ldr + 0x14);
    if (g_is_dll) { push32(0); push32(1); push32(g_imagebase); }   /* stdcall：DllMain(hinst, DLL_PROCESS_ATTACH=1, 0) */
    else { push32(0); push32(0); push32(0); }
    push32(EXIT_MAGIC);
    push32(EXIT_MAGIC);
    
    /* 注意：原来这里的打补丁代码（0x00401B19）已经被删除 */
}

static u32 g_dumpN = 0;
static void dump_bytes(const char* outDir, const char* tag, u32 base, u32 size) {
    if (!outDir || !size) return;
    if (size > 0x4000000u) { say("  [说明] %s 0x%08X 大小 0x%X 超过 64MB，只落盘前 64MB（避免占满磁盘）。\n", tag, base, size); size = 0x4000000u; }
    CreateDirectoryA(outDir, NULL);
    char fn[MAX_PATH];
    g_dumpN++;
    snprintf(fn, sizeof(fn), "%s\\%02u_%s_0x%X.bin", outDir, g_dumpN, tag, base);
    FILE* f = fopen(fn, "wb");
    if (!f) return;
    u32 left = size;
    for (u32 a = base; left;) {
        u32 pg = a >> PG_SHIFT, off = a & (PG_SIZE - 1);
        u32 chunk = PG_SIZE - off; if (chunk > left) chunk = left;
        if (pg < PG_COUNT && g_pg[pg].p) { fwrite(g_pg[pg].p + off, 1, chunk, f); a += chunk; left -= chunk; }
        else { for (u32 k = 0; k < chunk; k++) fputc(0, f); a += chunk; left -= chunk; }
    }
    fclose(f);
    say("  [落盘] %s  0x%08X (%u 字节) -> %s\n", tag, base, size, fn);
    tr("DUMP\t%s\t0x%X\t%u\t%s\n", tag, base, size, fn);
}

/* 在已写过的可执行区域里找内嵌 PE 并 dump */
/* ---- 映射 KUSER_SHARED_DATA（0x7FFE0000，只读页）----
 * 样本和保护壳经常直接读这块：系统版本、TickCount、共享 Cookie、ActiveConsoleId，
 * 也用作反虚拟机/反调试探针（典型如 0x7FFE0320）。不映射的话这些样本会直接"取数越界"死在启动阶段。 */
static void setup_kuser_shared(void) {
    u32 k = vm_alloc_region(0x7FFE0000, 0x1000, P_R, RK_ALLOC, "KUSER_SHARED_DATA");
    if (!k) return;
    u8 p[0x1000]; memset(p, 0, sizeof(p));
    u32 tick = (u32)(g_tick + 0x10000);        memcpy(p + 0x000, &tick, 4);
    u32 mul = 0x0FA00000;                      memcpy(p + 0x004, &mul, 4);
    u64 it = 0x01D0000000000000ull;            memcpy(p + 0x008, &it, 8);    /* InterruptTime */
    u64 st = 0x01DC000000000000ull;            memcpy(p + 0x010, &st, 8);    /* SystemTime */
    u16 img = 0x8664, imh = 0x8664;            memcpy(p + 0x020, &img, 2); memcpy(p + 0x022, &imh, 2);
    const char* root = "C:\\Windows";                                            /* NtSystemRoot（UTF-16）*/
    for (int i = 0; root[i]; i++) p[0x024 + i * 2] = (u8)root[i];
    u32 lpm = 0x200000;                        memcpy(p + 0x238, &lpm, 4);   /* LargePageMinimum */
    u64 seed = 0x1122334455667788ull;          memcpy(p + 0x244, &seed, 8);  /* RNGSeedVersion */
    u32 build = 19045;                         memcpy(p + 0x254, &build, 4); /* NtBuildNumber（Win10 22H2）*/
    u32 maj = 10, min = 0;                     memcpy(p + 0x264, &maj, 4); memcpy(p + 0x268, &min, 4);
    p[0x2CC] = 0;                                                              /* KdDebuggerEnabled=0 */
    u32 aci = 1, dmi = 0;                      memcpy(p + 0x2D0, &aci, 4); memcpy(p + 0x2D4, &dmi, 4);
    u32 probe = 1;                             memcpy(p + 0x320, &probe, 4); /* 常见探针位：给平凡非零值 */
    u64 cookie = 0x1122334455667788ull;        memcpy(p + 0x330, &cookie, 8);/* SharedUserData->Cookie */
    vm_poke(k, p, 0x1000);
    reg_setprot(k, 0x1000, P_R);
}

/* ---- 判断沙盒里 0x40000000 处的镜像是否与磁盘文件一致？
 * 一致 => 外壳没做"原地解壳"，那不算释放体；不一致 => 很可能就是脱壳后的原镜像。 */
static int image_matches_file(void) {
    if (!g_file || g_filesz < 0x40) return 0;
    u32 lf = rd32(0x3C);
    if (lf + 24 > g_filesz) return 0;
    u16 nsec = 0; memcpy(&nsec, g_file + lf + 6, 2);
    u16 optsz = 0; memcpy(&optsz, g_file + lf + 20, 2);
    if (!nsec || nsec > 96) return 0;
    u32 sect = lf + 24 + optsz, checked = 0, diff = 0;
    for (u32 k = 0; k < nsec && !diff && checked < 0x400000; k++, sect += 40) {
        if (sect + 40 > g_filesz) break;
        u32 vsz = 0, rva = 0, rawsz = 0, rawoff = 0;
        memcpy(&vsz, g_file + sect + 8, 4);
        memcpy(&rva, g_file + sect + 12, 4);
        memcpy(&rawsz, g_file + sect + 16, 4);
        memcpy(&rawoff, g_file + sect + 20, 4);
        u32 n = rawsz ? rawsz : vsz;
        if (!rva || !rawoff || !n) continue;
        if (rawoff + n > g_filesz || rva + n > g_sizeofimage) continue;
        if (n > 0x200000) n = 0x200000;
        for (u32 i = 0; i + 64 <= n; i += 64) {
            u8 a[64] = {0};
            if (!vm_read(g_imagebase + rva + i, a, 64)) { break; }
            if (memcmp(a, g_file + rawoff + i, 64)) { diff = 1; break; }
            checked += 64;
        }
    }
    if (!checked) return 0;
    return !diff;
}

/* ---- 装载完成后的镜像快照 + "样本是否改过自己的镜像"判定 ----
 * 为什么要快照：装载期的重定位、导入表虚拟化（IAT 会被写成一串 API 桩地址）都会改动
 * 镜像，如果拿"内存 vs 磁盘文件"来判是否解壳，任何带导入表的样本都会被误判成"解壳"。
 * 快照必须取在"重定位 + 导入虚拟化"之后，并把装载期的 written 标记清掉，
 * 这样 written / 变化 都只代表"样本自己写过的"。 */
static u8* g_img_snap = NULL;
static u32 g_img_snap_sz = 0;

static void img_take_snapshot(void) {
    if (!g_imagebase || !g_sizeofimage || g_img_snap) return;
    g_img_snap = (u8*)malloc(g_sizeofimage);
    if (!g_img_snap) { g_img_snap_sz = 0; return; }
    memset(g_img_snap, 0, g_sizeofimage);
    /* 逐页直接拷贝（不走 vm_read：vm_read 受保护位限制，遇到只写/不可读的节会中途返回，
     * 结果把后半幅镜像当成 0，后面比出满屏"变化"，误判成解壳）。 */
    u32 b0 = g_imagebase, b1 = g_imagebase + g_sizeofimage;
    for (u32 a = b0; a < b1; a += PG_SIZE) {
        u32 pg = a >> PG_SHIFT;
        if (pg >= PG_COUNT || !g_pg[pg].p) continue;
        u32 n = (a + PG_SIZE <= b1) ? PG_SIZE : (b1 - a);
        memcpy(g_img_snap + (a - b0), g_pg[pg].p, n);
    }
    g_img_snap_sz = g_sizeofimage;
    for (int i = 0; i < g_regN; i++) g_reg[i].written = 0;   /* 装载期的写不算样本行为 */
    for (u32 pg = 0; pg < PG_COUNT; pg++) if (g_pg[pg].p) g_pg[pg].written = 0;
}

static u32 image_diff_bytes(void) {
    if (!g_img_snap || !g_img_snap_sz) return 0;
    u32 b0 = g_imagebase, b1 = g_imagebase + g_img_snap_sz, n = 0;
    for (u32 a = b0 & ~(PG_SIZE - 1); a < b1; a += PG_SIZE) {
        u32 pg = a >> PG_SHIFT;
        if (pg >= PG_COUNT || !g_pg[pg].p) continue;
        u32 s = (a > b0) ? a : b0;
        u32 e = ((a + PG_SIZE) < b1) ? (a + PG_SIZE) : b1;
        if (e <= s) continue;
        const u8* cur = g_pg[pg].p + (s - a);
        const u8* old = g_img_snap + (s - b0);
        for (u32 i = 0; i < e - s; i++) if (cur[i] != old[i]) { if (++n >= 0x40000u) return n; }
    }
    return n;
}

static void dump_oep_and_scan(const char* outDir) {
    say("\n ---- 运行结束后的释放体扫描（虚拟内存里找 PE）----\n");
    int n = 0;
    for (int i = 0; i < g_regN; i++) {
        reg_t* r = &g_reg[i];
        if (!(r->prot & P_X) || !r->written) continue;
        u32 end = r->base + r->size;
        for (u32 a = r->base; a + 0x40 < end; a += 0x10) {
            u8 mz[2];
            if (!vm_read8(a, &mz[0]) || !vm_read8(a + 1, &mz[1])) break;
            if (mz[0] != 'M' || mz[1] != 'Z') continue;
            u32 lf = peek32(a + 0x3C);
            if (lf < 0x40 || lf > 0x1000) continue;
            u8 sig[4];
            if (!vm_read(a + lf, sig, 4)) continue;
            if (memcmp(sig, "PE\0\0", 4)) continue;
            u16 nsec = 0; vm_read16(a + lf + 6, &nsec);
            u32 soh = 0; vm_read32(a + lf + 24 + 60, &soh);
            u32 est = soh ? soh : 0x400;
            if (nsec > 0 && nsec < 96) {
                u16 optsz = 0; vm_read16(a + lf + 20, &optsz);
                for (u32 s = a + lf + 24 + optsz, k = 0; k < nsec; k++, s += 40) {
                    u32 rsz = 0, raw = 0; vm_read32(s + 16, &rsz); vm_read32(s + 20, &raw);
                    if (raw + rsz > est) est = raw + rsz;
                }
            }
            if (est > 0x10000000) est = 0x10000000;
            if (a == g_imagebase) {
                if (image_matches_file()) {
                    say("  [说明] 0x%08X 处是原始镜像，且与磁盘文件逐节一致（未发生原地解壳），不计为释放体。\n", a);
                    break;
                }
                say("  [说明] 0x%08X 处镜像与磁盘文件不同：疑似原地解壳后的原镜像。\n", a);
            }
            dump_bytes(outDir, "内存PE", a, est);
            n++;
            break;   /* 每个区域只取第一个，避免重复 */
        }
    }
    say("  内存中找到内嵌 PE：%d 个\n", n);
}

/* =====================================================================
 * x86-64（long mode）解释器 —— 与上面的 x86-32 通路完全隔离、互不影响
 * ---------------------------------------------------------------------
 * 沙盒地址空间是 32 位的：PE32+ 镜像按 PE 头 ImageBase 的低 32 位装载
 * （x64 常见 0x140000000 -> 0x40000000），凡超过 4GB 的地址一律按"未映射"
 * 安全停机。真实解壳/外壳代码绝大多数用 RIP 相对寻址，重定位到低 4GB 后
 * 仍能正确执行。覆盖整数/解壳常用指令；遇到未实现的编码如实停机并打印字节
 * （不猜、不硬走），与 x86-32 通路完全一样的口径。
 * ===================================================================== */
static u64 X[16];             /* RAX RCX RDX RBX RSP RBP RSI RDI R8..R15 */
static u64 RIP = 0;           /* 64 位指令指针 */
static u64 g_x64_cur = 0;     /* 解码游标：指向"当前指令之后"（供 RIP 相对寻址） */
static int g_x64_rex = 0;     /* 本指令是否带 REX（决定 8 位寄存器是 SPL 还是 AH） */
static int g_x64_jmp = 0;     /* 本指令是否已显式改写 RIP（跳转/调用/返回） */
static u64 g_x64_fault_addr = 0;   /* 越界访问的地址（诊断用）*/
static char g_x64_fault_what = 0;  /* 'F' 取指 / 'D' 取数 */
#define XFA(a, w) do { g_x64_fault_addr = (u64)(a); g_x64_fault_what = (w); } while (0)
static u64 g_xm[16][2];           /* xmm0..xmm15（128 位，按两个 64 位半存放）*/

static int x64_stop(const char* fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vsnprintf(g_stop_reason, sizeof(g_stop_reason), fmt, ap);
    va_end(ap);
    return 0;
}
static const char* x64_bytes(u64 at, int n) {
    static char b[64]; int k = 0; b[0] = 0;
    for (int i = 0; i < n; i++) {
        u8 v = 0;
        if (at + i > 0xFFFFFFFFull || !vm_read8((u32)(at + i), &v)) break;
        k += snprintf(b + k, sizeof(b) - (size_t)k, "%02X ", v);
    }
    return b;
}

/* ---- 最近指令环形缓冲：停机（尤其"取指/取数越界"）时自动打印 ----
 * 批次跑数百个样本时不可能都开 --insn，靠这个把"出事前那几十条"留下来。 */
#define XLAST 64
static struct { u32 rip; u8 b[10]; } g_last[XLAST];
static long g_lastn = 0;
static void x64_last_rec(u32 rip) {
    int i = (int)(g_lastn % XLAST);
    g_last[i].rip = rip;
    for (int k = 0; k < 10; k++) { u8 v = 0; g_last[i].b[k] = vm_read8(rip + (u32)k, &v) ? v : 0; }
    g_lastn++;
}
static void x64_dump_last(int cnt) {
    if (cnt > XLAST) cnt = XLAST;
    if (g_lastn < cnt) cnt = (int)g_lastn;
    if (cnt <= 0) return;
    say("  最近 %d 条指令（由旧到新）：\n", cnt);
    for (int i = 0; i < cnt; i++) {
        long idx = (g_lastn - cnt + i) % XLAST;
        char hex[40]; int k = 0;
        for (int j = 0; j < 10; j++) k += snprintf(hex + k, sizeof(hex) - (size_t)k, "%02X ", g_last[idx].b[j]);
        say("    [%06ld] %08X  %s\n", g_lastn - cnt + i, g_last[idx].rip, hex);
    }
    say("  RSP=0x%08X  栈顶 8 项：", (u32)X[4]);
    for (int i = 0; i < 8; i++) {
        u64 v = 0; int ok = 1;
        for (int k = 0; k < 8; k++) { u8 c = 0; if (!vm_read8((u32)(X[4] + i * 8 + k), &c)) { ok = 0; break; } ((u8*)&v)[k] = c; }
        if (ok) say(" %08X", (u32)v); else { say(" ??"); break; }
    }
    say("\n");
}

/* ---- 空转死循环识别：`pause; jmp $` / `nop; jmp $` / `jmp $` ----
 * 这类循环没有任何计数器，永远不会退出（我们单线程跑，没人能改它），
 * 直接判定"空转等待"并停机，避免把指令预算烧在 1500 万次 pause 上。 */
static int x64_is_pause_spin(u32 a) {
    u8 b0 = 0, b1 = 0, b2 = 0, b3 = 0;
    if (!vm_read8(a, &b0)) return 0;
    if (b0 == 0xF3) {                                  /* pause (F3 90) */
        if (!vm_read8(a + 1, &b1) || b1 != 0x90) return 0;
        if (!vm_read8(a + 2, &b2) || b2 != 0xEB) return 0;
        if (!vm_read8(a + 3, &b3) || (s8)b3 != -4) return 0;
        return 1;
    }
    if (b0 == 0x90) {                                  /* nop; jmp $ */
        if (!vm_read8(a + 1, &b1) || b1 != 0xEB) return 0;
        if (!vm_read8(a + 2, &b2) || (s8)b2 != -3) return 0;
        return 1;
    }
    if (b0 == 0xEB) {                                  /* jmp $ */
        if (!vm_read8(a + 1, &b1) || (s8)b1 != -2) return 0;
        return 1;
    }
    return 0;
}

/* ---- 取指游标（64 位地址按沙盒的 4GB 空间截断）----
 * 镜像被放在"首选基址的低 32 位"（x64 常见 0x140000000 -> 0x40000000），因此把
 * 64 位有效地址截断到低 32 位，恰好等价于把镜像整体平移到沙盒基址：样本里写死的
 * 0x140xxxxxx 静态指针/跳转目标都会正确落到沙盒内对应位置。 */
static u64 xf1(void) { u8 v = 0;  if (!vm_read8((u32)g_x64_cur, &v)) { XFA(g_x64_cur, 'F'); g_fault = 1; return 0; } g_x64_cur += 1; return v; }
static u64 xf2(void) { u16 v = 0; if (!vm_read16((u32)g_x64_cur, &v)) { XFA(g_x64_cur, 'F'); g_fault = 1; return 0; } g_x64_cur += 2; return v; }
static u64 xf4(void) { u32 v = 0; if (!vm_read32((u32)g_x64_cur, &v)) { XFA(g_x64_cur, 'F'); g_fault = 1; return 0; } g_x64_cur += 4; return v; }
static u64 xf8(void) { u64 v = 0; if (!vm_read((u32)g_x64_cur, &v, 8)) { XFA(g_x64_cur, 'F'); g_fault = 1; return 0; } g_x64_cur += 8; return v; }

/* ---- 64 位数据访问（地址截断到 4GB）---- */
static int xrd(u64 a, void* d, u32 n) { int r = vm_read((u32)a, d, n); if (!r) XFA(a, 'D'); return r; }
static int xwr(u64 a, const void* s, u32 n) { int r = vm_write((u32)a, s, n); if (!r) XFA(a, 'D'); return r; }
static void poke64(u32 a, u64 v) { vm_poke(a, &v, 8); }

/* ---- 寄存器读写（8 位时按有无 REX 区分 AH/BH/CH/DH 与 SPL/BPL/SIL/DIL）---- */
static u64 xr(int idx, int size) {
    if (size == 1) {
        if (!g_x64_rex && idx >= 4 && idx < 8) return (X[idx - 4] >> 8) & 0xFF;
        return X[idx & 15] & 0xFF;
    }
    if (size == 2) return X[idx & 15] & 0xFFFF;
    if (size == 4) return X[idx & 15] & 0xFFFFFFFFull;
    return X[idx & 15];
}
static void xw(int idx, int size, u64 v) {
    idx &= 15;
    if (size == 1) {
        if (!g_x64_rex && idx >= 4 && idx < 8) { X[idx - 4] = (X[idx - 4] & ~0xFF00ull) | ((v & 0xFF) << 8); return; }
        X[idx] = (X[idx] & ~0xFFull) | (v & 0xFF); return;
    }
    if (size == 2) { X[idx] = (X[idx] & ~0xFFFFull) | (v & 0xFFFF); return; }
    if (size == 4) { X[idx] = v & 0xFFFFFFFFull; return; }   /* 32 位写：零扩展到 64 位 */
    X[idx] = v;
}

/* ---- 标志位（支持 1/2/4/8 字节宽度）---- */
static u64 xmask(int sz) { return sz == 1 ? 0xFFull : (sz == 2 ? 0xFFFFull : (sz == 4 ? 0xFFFFFFFFull : 0xFFFFFFFFFFFFFFFFull)); }
static u64 xmsb(int sz)  { return sz == 1 ? 0x80ull : (sz == 2 ? 0x8000ull : (sz == 4 ? 0x80000000ull : 0x8000000000000000ull)); }
static void xset_pzs(u64 r, int sz) {
    r &= xmask(sz);
    EFLAGS &= ~(ZF | SF | PF);
    if (r == 0) EFLAGS |= ZF;
    if (r & xmsb(sz)) EFLAGS |= SF;
    if (__builtin_parity((unsigned)(r & 0xFF)) == 0) EFLAGS |= PF;
}
/* MSVC 不支持 __int128；以下用 64 位溢出检测等价实现（x86-32 的 sz 最多 4）。 */
static void xflags_add(u64 a, u64 b, u64 r, int sz) {
    u64 m = xmask(sz); a &= m; b &= m; r &= m;
    u64 s = a + b;
    EFLAGS &= ~(CF | OF | AF);
    if (sz == 8 ? (s < a) : ((s >> (sz * 8)) != 0)) EFLAGS |= CF;
    if (((a ^ r) & (b ^ r)) & xmsb(sz)) EFLAGS |= OF;
    if ((a ^ b ^ r) & 0x10) EFLAGS |= AF;
    xset_pzs(r, sz);
}
static void xflags_sub(u64 a, u64 b, u64 r, int sz) {
    u64 m = xmask(sz); a &= m; b &= m; r &= m;
    EFLAGS &= ~(CF | OF | AF);
    if (a < b) EFLAGS |= CF;
    if (((a ^ b) & (a ^ r)) & xmsb(sz)) EFLAGS |= OF;
    if ((a ^ b ^ r) & 0x10) EFLAGS |= AF;
    xset_pzs(r, sz);
}
static void xflags_adc(u64 a, u64 b, u64 r, int sz) {
    u64 m = xmask(sz); a &= m; b &= m; r &= m;
    u64 c = (EFLAGS & CF) ? 1ull : 0ull;
    u64 s = a + b;
    int carry = (s < a);
    u64 s2 = s + c;
    carry = carry || (s2 < s);
    EFLAGS &= ~(CF | OF | AF);
    if (carry || (sz != 8 && ((s2 >> (sz * 8)) != 0))) EFLAGS |= CF;
    if (((a ^ r) & (b ^ r)) & xmsb(sz)) EFLAGS |= OF;
    if ((a ^ b ^ r) & 0x10) EFLAGS |= AF;
    xset_pzs(r, sz);
}
static void xflags_sbb(u64 a, u64 b, u64 r, int sz) {
    u64 m = xmask(sz); a &= m; b &= m; r &= m;
    u64 c = (EFLAGS & CF) ? 1ull : 0ull;
    u64 t = b + c;
    int borrow = (t < b);
    EFLAGS &= ~(CF | OF | AF);
    if (borrow || a < t) EFLAGS |= CF;
    if (((a ^ b) & (a ^ r)) & xmsb(sz)) EFLAGS |= OF;
    if ((a ^ b ^ r) & 0x10) EFLAGS |= AF;
    xset_pzs(r, sz);
}
static void xflags_logic(u64 r, int sz) { EFLAGS &= ~(CF | OF | AF); xset_pzs(r, sz); }

/* ---- ALU（fam: 0 add 1 or 2 adc 3 sbb 4 and 5 sub 6 xor 7 cmp）---- */
static u64 xalu(int fam, u64 a, u64 b, int sz) {
    u64 m = xmask(sz), r;
    switch (fam) {
        case 0: r = (a + b) & m;       xflags_add(a, b, r, sz); break;
        case 1: r = (a | b) & m;       xflags_logic(r, sz); break;
        case 2: r = (a + b + (u64)((EFLAGS & CF) ? 1 : 0)) & m; xflags_adc(a, b, r, sz); break;
        case 3: r = (a - b - (u64)((EFLAGS & CF) ? 1 : 0)) & m; xflags_sbb(a, b, r, sz); break;
        case 4: r = (a & b) & m;       xflags_logic(r, sz); break;
        case 5: r = (a - b) & m;       xflags_sub(a, b, r, sz); break;
        case 6: r = (a ^ b) & m;       xflags_logic(r, sz); break;
        default: r = (a - b) & m;      xflags_sub(a, b, r, sz); break;
    }
    return r & m;
}

/* ---- 移位（sub: 0 rol 1 ror 2 rcl 3 rcr 4/6 shl 5 shr 7 sar）---- */
static u64 xshift(int sub, u64 v, u8 cnt0, int sz) {
    int bits = sz * 8;
    u64 m = xmask(sz); v &= m;
    u8 cnt = (u8)(cnt0 & ((sz == 8) ? 63 : 31));
    if (cnt == 0) return v;                                   /* 不移位：标志不变 */
    if (sub == 0 || sub == 1) cnt = (u8)(cnt % bits);         /* 循环移位按位宽取模 */
    if ((sub >= 4 || sub == 7) && cnt >= bits) {              /* 全移出（罕见）*/
        EFLAGS &= ~(CF | OF);
        if ((v >> (bits - 1)) & 1) EFLAGS |= CF;
        u64 r = (sub == 7 && (v & xmsb(sz))) ? m : 0;
        xset_pzs(r, sz);
        return r;
    }
    if (cnt == 0) return v;
    u64 r = v; int cf = 0, of = 0;
    switch (sub) {
        case 0: r = ((v << cnt) | (v >> (bits - cnt))) & m; cf = (int)(r & 1);
                of = (int)((((r & xmsb(sz)) ? 1 : 0) ^ cf)); break;
        case 1: r = ((v >> cnt) | (v << (bits - cnt))) & m; cf = (int)((r & xmsb(sz)) ? 1 : 0);
                of = (int)((((r & xmsb(sz)) ? 1 : 0) ^ ((((r << 1) & m) & xmsb(sz)) ? 1 : 0))); break;
        case 2: case 3: {
            int c = (EFLAGS & CF) ? 1 : 0;
            int n = (int)(cnt % (bits + 1));
            if (n == 0) return v;
            /* x86-32 的 sz 最大 4（bits<=32），所以 bits+1<=33，u64 足够。 */
            u64 big = ((u64)v << 1) | (u64)c;
            u64 all = (((u64)1) << (bits + 1)) - 1;
            u64 res = (sub == 2) ? (((big << n) | (big >> (bits + 1 - n))) & all)
                                 : (((big >> n) | (big << (bits + 1 - n))) & all);
            cf = (int)((res >> bits) & 1);
            r = (u64)res & m;
            of = (sub == 2) ? (int)((((r & xmsb(sz)) ? 1 : 0) ^ cf)) : 0;
            break;
        }
        case 4: case 6: cf = (int)((v >> (bits - cnt)) & 1); r = (v << cnt) & m;
                of = (int)((((r & xmsb(sz)) ? 1 : 0) ^ cf)); break;
        case 5: cf = (int)((v >> (cnt - 1)) & 1); r = (v >> cnt) & m;
                of = (int)((v & xmsb(sz)) ? 1 : 0); break;
        default: {
            s64 sv = (sz == 8) ? (s64)v : (s64)((v ^ xmsb(sz)) - xmsb(sz));
            cf = (int)(((u64)sv >> (cnt - 1)) & 1);
            r = ((u64)(sv >> cnt)) & m;
            break;
        }
    }
    EFLAGS &= ~(CF | OF);
    if (cf) EFLAGS |= CF;
    if (of) EFLAGS |= OF;
    xset_pzs(r, sz);
    return r & m;
}

/* ---- 64 位 ModRM / SIB（含 RIP 相对寻址）---- */
typedef struct { int is_mem; int reg; int rm; int size; int rip_rel; u64 disp; u64 addr; int seg; } x64m_t;
static void x64_modrm(x64m_t* m, int size, int rex_r, int rex_x, int rex_b) {
    u8 b = (u8)xf1();
    int mod = b >> 6, reg_f = (b >> 3) & 7, rm_f = b & 7;
    m->is_mem = 0; m->rm = rm_f | (rex_b ? 8 : 0); m->reg = reg_f | (rex_r ? 8 : 0);
    m->size = size; m->rip_rel = 0; m->disp = 0; m->addr = 0; m->seg = g_segovr;
    if (mod == 3) return;
    m->is_mem = 1;
    u64 addr = 0;
    if (rm_f == 4) {                                   /* SIB */
        u8 sib = (u8)xf1();
        int ss = sib >> 6, idx_f = (sib >> 3) & 7, base_f = sib & 7;
        u64 index = ((idx_f == 4) && !rex_x) ? 0 : X[idx_f | (rex_x ? 8 : 0)];
        if (base_f == 5 && mod == 0) addr = (u64)(s64)(s32)xf4();
        else addr = X[base_f | (rex_b ? 8 : 0)];
        addr += index << ss;
    } else if (rm_f == 5 && mod == 0) {                /* RIP 相对：基址 = 下一条指令地址 */
        m->rip_rel = 1; m->disp = (u64)(s64)(s32)xf4();
    } else {
        addr = X[rm_f | (rex_b ? 8 : 0)];
    }
    if (mod == 1) addr += (u64)(s64)(s8)xf1();
    else if (mod == 2) addr += (u64)(s64)(s32)xf4();
    m->addr = m->rip_rel ? 0 : ((u64)seg_base(m->seg) + addr);
}
static u64 x64_ea(x64m_t* m) { return m->rip_rel ? (g_x64_cur + m->disp) : m->addr; }
static u64 x64_read(x64m_t* m) {
    if (!m->is_mem) return xr(m->rm, m->size);
    u64 a = x64_ea(m);
    if (m->size == 1) { u8 v = 0;  if (!xrd(a, &v, 1)) { g_fault = 1; return 0; } return v; }
    if (m->size == 2) { u16 v = 0; if (!xrd(a, &v, 2)) { g_fault = 1; return 0; } return v; }
    if (m->size == 4) { u32 v = 0; if (!xrd(a, &v, 4)) { g_fault = 1; return 0; } return v; }
    { u64 v = 0; if (!xrd(a, &v, 8)) { g_fault = 1; return 0; } return v; }
}
static void x64_write(x64m_t* m, u64 v) {
    if (!m->is_mem) { xw(m->rm, m->size, v); return; }
    u64 a = x64_ea(m); int ok = 1;
    if (m->size == 1) { u8 t = (u8)v;      ok = xwr(a, &t, 1); }
    else if (m->size == 2) { u16 t = (u16)v; ok = xwr(a, &t, 2); }
    else if (m->size == 4) { u32 t = (u32)v; ok = xwr(a, &t, 4); }
    else { ok = xwr(a, &v, 8); }
    if (!ok) g_fault = 1; else reg_mark_written((u32)a, (u32)m->size);
}

/* ---- 64 位栈操作 ---- */
static void xpush(u64 v) { X[4] -= 8; if (!xwr(X[4], &v, 8)) g_fault = 1; }
static u64  xpop(void) { u64 v = 0; if (!xrd(X[4], &v, 8)) g_fault = 1; X[4] += 8; return v; }
static void xpush16(u16 v) { X[4] -= 2; if (!xwr(X[4], &v, 2)) g_fault = 1; }

/* ---- 字符串指令（A4..AF，含 REP/REPE/REPNE）---- */
static int x64_string(u8 op, int sz) {
    int unit = sz;                                  /* 元素宽度 */
    u64 count = g_rep ? X[1] : 1;
    int dir = (EFLAGS & DF) ? -1 : 1;
    if (count > (1u << 22)) return x64_stop("REP 串操作次数过多（%llu），如实停机", (unsigned long long)count);
    for (u64 k = 0; k < count; k++) {
        if (op == 0xA4 || op == 0xA5) {             /* movs */
            u64 v = (unit == 1) ? 0 : 0;
            u8 b8; u16 b16; u32 b32; u64 b64;
            if (unit == 1) { if (!xrd(X[6], &b8, 1)) { g_fault = 1; return 0; } if (!xwr(X[7], &b8, 1)) { g_fault = 1; return 0; } }
            else if (unit == 2) { if (!xrd(X[6], &b16, 2) || !xwr(X[7], &b16, 2)) { g_fault = 1; return 0; } }
            else if (unit == 4) { if (!xrd(X[6], &b32, 4) || !xwr(X[7], &b32, 4)) { g_fault = 1; return 0; } }
            else { if (!xrd(X[6], &b64, 8) || !xwr(X[7], &b64, 8)) { g_fault = 1; return 0; } }
            (void)v;
            X[6] += (u64)(dir * unit); X[7] += (u64)(dir * unit);
        } else if (op == 0xA6 || op == 0xA7) {      /* cmps */
            u64 a = 0, b = 0;
            if (unit == 1) { u8 z1 = 0, z2 = 0; if (!xrd(X[6], &z1, 1) || !xrd(X[7], &z2, 1)) { g_fault = 1; return 0; } a = z1; b = z2; }
            else if (unit == 2) { u16 z1 = 0, z2 = 0; if (!xrd(X[6], &z1, 2) || !xrd(X[7], &z2, 2)) { g_fault = 1; return 0; } a = z1; b = z2; }
            else if (unit == 4) { u32 z1 = 0, z2 = 0; if (!xrd(X[6], &z1, 4) || !xrd(X[7], &z2, 4)) { g_fault = 1; return 0; } a = z1; b = z2; }
            else { if (!xrd(X[6], &a, 8) || !xrd(X[7], &b, 8)) { g_fault = 1; return 0; } }
            xflags_sub(a, b, (a - b) & xmask(unit), unit);
            X[6] += (u64)(dir * unit); X[7] += (u64)(dir * unit);
            if (g_rep == 1 && !(EFLAGS & ZF)) break;   /* repe  */
            if (g_rep == 2 && (EFLAGS & ZF)) break;    /* repne */
        } else if (op == 0xAA || op == 0xAB) {       /* stos */
            u64 v = xr(0, unit);
            if (unit == 1) { u8 t = (u8)v; if (!xwr(X[7], &t, 1)) { g_fault = 1; return 0; } }
            else if (unit == 2) { u16 t = (u16)v; if (!xwr(X[7], &t, 2)) { g_fault = 1; return 0; } }
            else if (unit == 4) { u32 t = (u32)v; if (!xwr(X[7], &t, 4)) { g_fault = 1; return 0; } }
            else { if (!xwr(X[7], &v, 8)) { g_fault = 1; return 0; } }
            X[7] += (u64)(dir * unit);
        } else if (op == 0xAC || op == 0xAD) {       /* lods */
            u64 v = 0;
            if (unit == 1) { u8 t = 0; if (!xrd(X[6], &t, 1)) { g_fault = 1; return 0; } v = t; }
            else if (unit == 2) { u16 t = 0; if (!xrd(X[6], &t, 2)) { g_fault = 1; return 0; } v = t; }
            else if (unit == 4) { u32 t = 0; if (!xrd(X[6], &t, 4)) { g_fault = 1; return 0; } v = t; }
            else { if (!xrd(X[6], &v, 8)) { g_fault = 1; return 0; } }
            xw(0, unit, v);
            X[6] += (u64)(dir * unit);
        } else {                                     /* scas（AE/AF）*/
            u64 a = xr(0, unit), b = 0;
            if (unit == 1) { u8 t = 0; if (!xrd(X[7], &t, 1)) { g_fault = 1; return 0; } b = t; }
            else if (unit == 2) { u16 t = 0; if (!xrd(X[7], &t, 2)) { g_fault = 1; return 0; } b = t; }
            else if (unit == 4) { u32 t = 0; if (!xrd(X[7], &t, 4)) { g_fault = 1; return 0; } b = t; }
            else { if (!xrd(X[7], &b, 8)) { g_fault = 1; return 0; } }
            xflags_sub(a, b, (a - b) & xmask(unit), unit);
            X[7] += (u64)(dir * unit);
            if (g_rep == 1 && !(EFLAGS & ZF)) break;
            if (g_rep == 2 && (EFLAGS & ZF)) break;
        }
        if (g_rep) X[1]--;
    }
    return 1;
}

/* ---- x64 侧的运行时支撑：小型堆 / 全局小单元 / TLS / CRT 初始化链 ----
 * 样本（尤其自带静态 CRT 的外壳）入口是真正的 CRT 启动流程，会调用
 * malloc/_initterm/GetStartupInfo/__p___argc 等；这些桩一律返回 0 的话，
 * 样本随后就会解引用空指针（早期实测里 165 条指令处 48 C7 07 00 00 00 00
 * 崩在 NULL 就是这个原因）。这里给它们"像真机一样"的最小可用行为。 */
static u32 g_xh_cur = 0, g_xh_left = 0;
static u32 g_x64_cellbase = 0, g_x64_celloff = 0;
static u64 g_tls64[64];
static int g_tls_next = 1;
static u64 g_it_cur = 0, g_it_end = 0, g_it_ret = 0;
static u32 g_it_stub = 0;

/* 样本请求创建的工作线程：登记下来，等主入口返回后在同一沙盒里接着跑
 * （单线程解释器无法真并发；顺序执行是等价近似，且不会漏掉解壳工作） */
#define TH_MAX 8
static u64 g_th_fn[TH_MAX], g_th_arg[TH_MAX];
static int g_th_n = 0, g_th_ran = 0;

/* x64 第 n 个参数（n>=5 时在栈上）。入口处 RSP 指向返回地址，
 * 调用者预留的 shadow space 占 [rsp+8]..[rsp+0x20]，故第 5 个参数在 [rsp+0x28]。 */
static u64 x64_arg(int n) {
    u64 v = 0;
    if (n >= 5) xrd(X[4] + 0x20 + 8 * (u64)(n - 4), &v, 8);
    return v;
}

/* 读沙盒里的字符串（A/W 均可），越界/失败时给出空串 */
static void x64_rdstr(u64 p, char* out, int n, int wide) {
    out[0] = 0;
    if (!p || n < 2) return;
    if (wide) { int k = 0; for (; k < n - 1; k++) { u16 w = 0; if (!vm_read((u32)p + k * 2, &w, 2) || !w) break; out[k] = (char)w; } out[k] = 0; }
    else vm_cstr((u32)p, out, n);
}

static u64 x64_wpath(u64 buf, u64 size, const char* ascii, int wide) {
    u32 n = (u32)strlen(ascii);
    if (buf && size) {
        if (n > (u32)size - 1) n = (u32)size - 1;
        if (wide) { for (u32 i = 0; i < n; i++) { u16 w = (u16)(u8)ascii[i]; vm_poke((u32)buf + i * 2, &w, 2); } u16 z = 0; vm_poke((u32)buf + n * 2, &z, 2); }
        else { vm_poke((u32)buf, ascii, n); vm_write8((u32)buf + n, 0); }
    }
    return n;
}

/* 阶梯式小堆：每次向内核要 1MB，内部按 16 字节对齐切分（避免把区域表撑爆） */
static u32 x64_heap_alloc(u32 sz) {
    sz = (sz + 15) & ~15u; if (!sz) sz = 16;
    if (sz > g_xh_left) {
        u32 want = 0x100000; if (sz > want) want = (sz + 0xFFFFFu) & ~0xFFFFFu;
        u32 a = vm_alloc_region(0, want, P_R | P_W, RK_ALLOC, "x64堆");
        if (!a) return 0;
        g_xh_cur = a; g_xh_left = want;
    }
    u32 r = g_xh_cur; g_xh_cur += sz; g_xh_left -= sz; return r;
}
/* 小块"全局单元"（给 __p___argc 之类需要返回有效指针的 API） */
static u32 x64_cell(u32 n) {
    if (!g_x64_cellbase) { g_x64_cellbase = vm_alloc_region(0, 0x10000, P_R | P_W, RK_ALLOC, "x64单元"); g_x64_celloff = 0; }
    if (!g_x64_cellbase || g_x64_celloff + n > 0x10000) return 0;
    u32 a = g_x64_cellbase + g_x64_celloff; g_x64_celloff += (n + 15) & ~15u; return a;
}
static u32 x64_strcell(const char* s, int wide) {
    u32 n = (u32)strlen(s);
    u32 a = x64_cell(wide ? (n * 2 + 4) : (n + 2));
    if (!a) return 0;
    if (wide) { for (u32 i = 0; i <= n; i++) { u16 w = (u16)(u8)s[i]; vm_poke(a + i * 2, &w, 2); } }
    else vm_poke(a, s, n + 1);
    return a;
}
static int name_in(const char* n, const char* const* L) { for (int i = 0; L[i]; i++) if (!_stricmp(n, L[i])) return 1; return 0; }
static const char* const NM_MALLOC[]  = { "malloc", "_malloc_base", NULL };
static const char* const NM_CALLOC[]  = { "calloc", "_calloc_base", NULL };
static const char* const NM_REALLOC[] = { "realloc", "_realloc_base", NULL };
static const char* const NM_FREE[]    = { "free", "_free_base", "operator delete", NULL };
static const char* const NM_HEAPALLOC[]  = { "HeapAlloc", "HeapReAlloc", NULL };
static const char* const NM_LOCALALLOC[] = { "LocalAlloc", "GlobalAlloc", NULL };
static const char* const NM_RET1[] = { "HeapFree", "HeapDestroy", "HeapValidate", "HeapSetInformation",
    "GlobalFree", "LocalFree", "GlobalUnlock", "LocalUnlock", "FreeLibrary", "SetConsoleCtrlHandler",
    "FreeEnvironmentStringsW", "FreeEnvironmentStringsA", "ReleaseMutex", "CloseHandle", "TlsFree", "FlsFree",
    "_resetstkoflw", "VirtualLock", "VirtualUnlock", "SetThreadPriority", "SetPriorityClass", "FlushFileBuffers",
    "SetEndOfFile", "SetFilePointer", "UnmapViewOfFile", "RtlAddFunctionTable",
    "InitializeCriticalSectionEx", "InitializeCriticalSectionAndSpinCount", NULL };
static const char* const NM_RET0[] = { "_set_app_type", "_set_fmode", "_set_new_mode", "_configthreadlocale",
    "_set_error_mode", "__setusermatherr", "_crt_atexit", "atexit", "_onexit", "__cxa_atexit", "_controlfp",
    "__set_app_type", "SetLastError", "GetConsoleMode", "GetConsoleCP", "GetConsoleOutputCP", "SetConsoleMode",
    "IsProcessorFeaturePresent", "GetCurrentThreadId", "GetCurrentProcessId",
    "RtlCaptureContext", "RtlLookupFunctionEntry", "RtlVirtualUnwind",
    "RtlUnwind", "RtlUnwindEx", "__C_specific_handler", "_except_handler4_common", "__security_check_cookie",
    "_guard_check_icall", "DebugBreak", "LeaveCriticalSection", "DeleteCriticalSection", "EnterCriticalSection",
    "InitializeCriticalSection",
    "SleepConditionVariableSRW", "WakeAllConditionVariable", "WakeConditionVariable", "InitializeSListHead",
    "SwitchToThread", "GetThreadTimes", "SetThreadAffinityMask", "LoadLibraryExA", "LoadLibraryExW",
    "_lock", "_unlock", "_callnewh", "_getpid", "_get_osfhandle", "_register_onexit_function",
    "_crt_at_quick_exit", "_initialize_onexit_table", "_register_thread_local_exe_atexit_callback",
    "_set_invalid_parameter_handler", "_get_thread_local_invalid_parameter_handler", "_set_abort_behavior",
    "_cexit", "_c_exit", "_setjmp", "_query_new_handler", "_set_new_handler", "signal", "__cxa_thread_atexit",
    "GetEnvironmentVariableA", "SetEnvironmentVariableA", "SetEnvironmentVariableW",
    "FreeLibraryAndExitThread", "ExitThread", "TerminateThread", "GetExitCodeThread", "SetThreadContext",
    "SetUnhandledExceptionFilter", "AddVectoredExceptionHandler", "RemoveVectoredExceptionHandler",
    "SetThreadStackGuarantee", "SetThreadDescription", "CreateWaitableTimerExW", "SetWaitableTimer",
    "OpenProcessToken", "CheckRemoteDebuggerPresent", "SetErrorMode", "SetDefaultDllDirectories",
    "SetDllDirectoryW", "AddDllDirectory", "GetProcessTimes", "GetCurrentProcessorNumber",
    "SetProcessPriorityBoost", "SetThreadPriorityBoost", "GetThreadPriority", "DuplicateHandle",
    "OpenThread", "ResumeThread", "SuspendThread", "SetPriorityClass", "GetPriorityClass",
    "GetCurrentPackageFullName", "SetProcessMitigationPolicy", "GetSystemTimePreciseAsFileTime",
    "GetUserDefaultUILanguage", "GetUserDefaultLCID", "GetSystemDefaultLCID", "QueryDosDeviceW",
    "GetVolumeInformationW", "GetDiskFreeSpaceExW", "DeviceIoControl", "SetFileTime", "GetFileAttributesA",
    "GetFileAttributesW", "GetFileSizeEx", "SetFilePointerEx", "FlushFileBuffers", "GetFullPathNameA",
    "GetFullPathNameW", "CompareStringW", "LCMapStringW", "GetStringTypeW", "IsValidLocale",
    "GetLocaleInfoW", "EnumSystemLocalesW", "AdjustTokenPrivileges", "LookupPrivilegeValueW",
    "GetTokenInformation", "IsWow64Process",
    "WaitForSingleObject", "WaitForMultipleObjects", "SignalObjectAndWait", "MsgWaitForMultipleObjects",
    "WaitForInputIdle", "SetThreadIdealProcessor", "SetProcessWorkingSetSize", "SetThreadLocale",
    "GetThreadLocale", "SetConsoleOutputCP", "SetConsoleCP", "__setlc_active_func", NULL };

/* ---- x64 的 API 桩分发（Windows x64 调用约定：RCX RDX R8 R9 -> RAX）---- */
static int x64_api_dispatch(void) {
    imp_t* im = stub_lookup((u32)RIP);
    if (!im) return 0;
    const char* name = im->name;
    if (!_stricmp(name, "_CorExeMain") || !_stricmp(name, "_CorDllMain")) {
        blog("托管", "★.NET 程序集入口 %s：x64 解释器到此为止，需 IL 分析", name);
        say("  [托管] ★.NET 程序集（入口 %s）：x64 解释器不适用，需 IL 分析\n", name);
        x64_stop("托管程序集（.NET），x64 解释器不适用");
        g_halted = 1;
        return 0;
    }
    u64 rcx = X[1], rdx = X[2], r8 = X[8], r9 = X[9];
    g_api_calls++;
    u64 ret = 0;
    if (!_stricmp(name, "VirtualAlloc")) {
        u32 sz = (u32)rdx; if (sz < 0x1000) sz = 0x1000; sz = (sz + 0xFFF) & ~0xFFFu;
        u32 prot = (r9 & 0x40) ? (P_R | P_W | P_X) : (P_R | P_W);
        u32 a = vm_alloc_region((u32)rcx, sz, prot, RK_ALLOC, "VirtualAlloc64");
        blog("分配", "VirtualAlloc64(0x%X, %u, 0x%X, 0x%X) -> 0x%08X", (u32)rcx, sz, (u32)r8, (u32)r9, a);
        ret = a;
    } else if (!_stricmp(name, "VirtualProtect")) {
        u32 old = P_R | P_W;
        reg_setprot((u32)rcx, (u32)rdx, (r8 & 0x40) ? (P_R | P_W | P_X) : ((r8 & 0x04) ? (P_R | P_W) : P_R));
        if (r9) { u32 t = old; vm_poke((u32)r9, &t, 4); }
        blog("保护", "VirtualProtect64(0x%X, %u, 0x%X) -> 1", (u32)rcx, (u32)rdx, (u32)r8);
        ret = 1;
    } else if (!_stricmp(name, "VirtualFree")) {
        blog("释放", "VirtualFree64(0x%X, %u, 0x%X) -> 1", (u32)rcx, (u32)rdx, (u32)r8);
        ret = 1;
    } else if (!_stricmp(name, "LoadLibraryA") || !_stricmp(name, "LoadLibraryW")) {
        char d[256] = {0}; vm_cstr((u32)rcx, d, sizeof(d));
        u32 a = vm_alloc_region(0, 0x1000, P_R | P_W, RK_ALLOC, "DLL64");
        blog("加载", "LoadLibrary64(\"%s\") -> 0x%08X", d, a);
        ret = a;
    } else if (!_stricmp(name, "GetModuleHandleA") || !_stricmp(name, "GetModuleHandleW")) {
        char d[256] = {0}; vm_cstr((u32)rcx, d, sizeof(d));
        blog("加载", "GetModuleHandle64(\"%s\") -> 0x%08X", d, g_imagebase);
        ret = g_imagebase;
    } else if (!_stricmp(name, "GetProcAddress")) {
        char d[256] = {0}; vm_cstr((u32)rdx, d, sizeof(d));
        u32 st = is_data_import(d) ? stub_alloc_ex("x64", d, data_import_cell()) : stub_alloc("x64", d);
        blog("加载", "GetProcAddress64(\"%s\") -> 0x%08X", d, st);
        ret = st;
    } else if (!_stricmp(name, "ExitProcess")) {
        x64_stop("样本调用 ExitProcess(%u)", (u32)rcx);
        g_halted = 1;
        return 0;
    } else if (!_stricmp(name, "IsDebuggerPresent")) {
        ret = 0;
    } else if (!_stricmp(name, "GetTickCount") || !_stricmp(name, "GetTickCount64")) {
        g_tick += 0x137; ret = g_tick;
    } else if (!_stricmp(name, "Sleep")) {
        ret = 0;
    } else if (!_stricmp(name, "GetLastError")) {
        ret = g_last_error;
    } else if (!_stricmp(name, "OutputDebugStringA") || !_stricmp(name, "OutputDebugStringW")) {
        char d[256] = {0}; vm_cstr((u32)rcx, d, sizeof(d));
        blog("调试", "OutputDebugString64(\"%s\")", d);
        ret = 0;
    } else if (!_stricmp(name, "__inittram")) {
        /* CRT 初始化链的续跑点：依次调用初始化函数，每个函数返回后回到本桩继续 */
        while (g_it_cur + 8 <= g_it_end) {
            u64 fn = 0;
            if (!xrd(g_it_cur, &fn, 8)) break;
            g_it_cur += 8;
            if (fn) { xpush(g_it_stub); RIP = fn; g_x64_jmp = 1; return 1; }
        }
        RIP = g_it_ret; g_x64_jmp = 1;
        return 1;
    } else if (name_in(name, NM_MALLOC)) {
        u32 a = x64_heap_alloc((u32)rcx);
        blog("分配", "x64 %s(%u) -> 0x%08X", name, (u32)rcx, a);
        ret = a;
    } else if (name_in(name, NM_CALLOC)) {
        u32 a = x64_heap_alloc((u32)((rcx * (rdx ? rdx : 1)) & 0xFFFFFFFFu));
        blog("分配", "x64 %s(%u, %u) -> 0x%08X", name, (u32)rcx, (u32)rdx, a);
        ret = a;
    } else if (name_in(name, NM_REALLOC)) {
        u32 sz = (u32)rdx, a = x64_heap_alloc(sz);
        if (a && rcx) {
            u8 t[8192]; u32 done = 0;
            while (done < sz) { u32 n = sz - done; if (n > sizeof(t)) n = sizeof(t); if (!vm_read((u32)rcx + done, t, n)) break; vm_poke(a + done, t, n); done += n; }
        }
        blog("分配", "x64 %s(0x%08X, %u) -> 0x%08X", name, (u32)rcx, sz, a);
        ret = a;
    } else if (!strncmp(name, "??2@", 4) || !strncmp(name, "??_U@", 5)) {
        u32 a = x64_heap_alloc((u32)rcx);
        blog("分配", "x64 operator new(%u) -> 0x%08X", (u32)rcx, a);
        ret = a;
    } else if (name_in(name, NM_FREE) || !strncmp(name, "??3@", 4) || !strncmp(name, "??_V@", 5)) {
        ret = 0;
    } else if (name_in(name, NM_HEAPALLOC)) {
        /* HeapAlloc(hHeap,dwFlags,dwBytes) / HeapReAlloc(hHeap,dwFlags,lpMem,dwBytes)：
         * 注意 HeapReAlloc 的长度在 R9、旧指针在 R8（早期实测把 R8 当长度，
         * 于是按"指针值"去分配出 1.8GB 的巨型区域）。 */
        int re = !_stricmp(name, "HeapReAlloc");
        u32 sz = re ? (u32)r9 : (u32)r8;
        u32 old = re ? (u32)r8 : 0;
        u32 a = x64_heap_alloc(sz);
        if (a && old && sz) {
            u8 t[8192]; u32 done = 0;
            while (done < sz) { u32 n = sz - done; if (n > sizeof(t)) n = sizeof(t); if (!vm_read(old + done, t, n)) break; vm_poke(a + done, t, n); done += n; }
        }
        blog("分配", "x64 %s(堆, %u) -> 0x%08X", name, sz, a);
        ret = a;
    } else if (name_in(name, NM_LOCALALLOC)) {
        u32 a = x64_heap_alloc((u32)rdx);
        blog("分配", "x64 %s(0x%X, %u) -> 0x%08X", name, (u32)rcx, (u32)rdx, a);
        ret = a;
    } else if (!_stricmp(name, "GetProcessHeap") || !_stricmp(name, "HeapCreate")) {
        ret = 0x00A00000;
    } else if (!_stricmp(name, "LocalLock") || !_stricmp(name, "GlobalLock")) {
        ret = rcx;
    } else if (!_stricmp(name, "HeapSize")) {
        ret = 0x1000;
    } else if (!_stricmp(name, "_initterm") || !_stricmp(name, "_initterm_e")) {
        /* 真正执行 C/C++ 静态初始化函数（不做的话全局量保持 0，很容易假崩） */
        g_it_cur = rcx; g_it_end = rdx;
        g_it_ret = xpop();
        if (!g_it_stub) g_it_stub = stub_alloc("x64", "__inittram");
        X[0] = 0; RIP = g_it_stub; g_x64_jmp = 1;
        blog("动态API", "%s(0x%08X..0x%08X)：开始执行初始化函数链", name, (u32)rcx, (u32)rdx);
        return 1;
    } else if (!_stricmp(name, "GetStartupInfoW") || !_stricmp(name, "GetStartupInfoA")) {
        /* 只写 STARTUPINFO 的真实大小（x64=0x68）：以前写 0x100 会越过调用者栈上的结构，
         * 把返回地址/保存寄存器清零（2f7470a2 样本即因此 ret 到 0）。 */
        u8 z[0x68]; memset(z, 0, sizeof(z));
        u32 cb = 0x68; memcpy(z, &cb, 4);
        vm_poke((u32)rcx, z, sizeof(z));
        ret = 0;
    } else if (!_stricmp(name, "GetCommandLineA")) {
        char s[300]; snprintf(s, sizeof(s), "\"%s\"", g_sample_path);
        ret = x64_strcell(s, 0);
        blog("动态API", "GetCommandLineA -> \"%s\"", s);
    } else if (!_stricmp(name, "GetCommandLineW")) {
        char s[300]; snprintf(s, sizeof(s), "\"%s\"", g_sample_path);
        ret = x64_strcell(s, 1);
    } else if (!_stricmp(name, "GetEnvironmentStringsW") || !_stricmp(name, "GetEnvironmentStringsA")) {
        int wide = (name[strlen(name) - 1] == 'W');
        u32 p = vm_alloc_region(0, 64, P_R | P_W, RK_ALLOC, "env64");
        if (wide) { u16 z = 0; vm_poke(p, &z, 2); vm_poke(p + 2, &z, 2); }
        else { vm_write8(p, 0); vm_write8(p + 1, 0); }
        ret = p;
    } else if (!_stricmp(name, "CLRCreateInstance")) {
        ret = 0x80004005;                                /* E_FAIL */
    } else if (!_stricmp(name, "GetACP") || !_stricmp(name, "GetOEMCP") ||
               !_stricmp(name, "GetConsoleCP") || !_stricmp(name, "GetConsoleOutputCP")) {
        ret = 936;                                       /* GBK：返回 0 会被当成无效代码页 */
    } else if (!_stricmp(name, "GetModuleFileNameA") || !_stricmp(name, "GetModuleFileNameW")) {
        int wide = (name[strlen(name) - 1] == 'W');
        u32 n = (u32)r8;
        if (!n) n = 260;
        if (wide) { u32 k = 0; for (; k < n - 1 && g_sample_path[k]; k++) { u16 w = (u16)(u8)g_sample_path[k]; vm_poke((u32)rdx + k * 2, &w, 2); } u16 z = 0; vm_poke((u32)rdx + k * 2, &z, 2); ret = k; }
        else { u32 len = (u32)strlen(g_sample_path); if (len > n - 1) len = n - 1; vm_poke((u32)rdx, g_sample_path, len); vm_write8((u32)rdx + len, 0); ret = len; }
        blog("动态API", "GetModuleFileName -> %s", g_sample_path);
    } else if (!_stricmp(name, "__p___argc")) {
        ret = x64_cell(4); u32 one = 1; vm_poke((u32)ret, &one, 4);
    } else if (!_stricmp(name, "__p___argv") || !_stricmp(name, "__p___wargv")) {
        int wide = (name[strlen(name) - 2] == 'w');
        u32 arr = x64_cell(16), cell = x64_cell(8);
        u32 s = x64_strcell(g_sample_path, wide);
        vm_poke(arr, &s, 4); u32 z = 0; vm_poke(arr + 4, &z, 4);
        vm_poke(cell, &arr, 4);
        ret = cell;
    } else if (!_stricmp(name, "__p__environ") || !_stricmp(name, "__p__wenviron")) {
        int wide = (name[strlen(name) - 3] == 'w');
        u32 e = x64_cell(16);
        if (wide) { u16 z = 0; vm_poke(e, &z, 2); } else vm_write8(e, 0);
        ret = e;
    } else if (!_stricmp(name, "_get_initial_narrow_environment") || !_stricmp(name, "_get_initial_wide_environment")) {
        int wide = (name[strlen(name) - 8] == 'w');
        u32 p = x64_cell(16);
        if (wide) { u16 z = 0; vm_poke(p, &z, 2); } else vm_write8(p, 0);
        ret = p;
    } else if (!_stricmp(name, "_controlfp_s") || !_stricmp(name, "GetVersionExA") || !_stricmp(name, "GetVersionExW")
               || !_stricmp(name, "GetSystemInfo") || !_stricmp(name, "GetNativeSystemInfo")) {
        if (rcx) { u8 z[64]; memset(z, 0, sizeof(z)); vm_poke((u32)rcx, z, sizeof(z)); }
        ret = 0;
    } else if (!_stricmp(name, "GetVersion")) {
        ret = 0x0A280105;                      /* 6.2 build 9200 风格（假版本号） */
    } else if (!_stricmp(name, "VirtualQuery") || !_stricmp(name, "VirtualQueryEx")) {
        int ex = !_stricmp(name, "VirtualQueryEx");
        u32 a = (u32)(ex ? rdx : rcx), ob = (u32)(ex ? r8 : rdx);
        u8 mbi[48]; memset(mbi, 0, sizeof(mbi));
        u32 base = a & ~0xFFFu, sz = 0x1000, state = 0x1000, prot = 0x40;
        memcpy(mbi + 0, &base, 4); memcpy(mbi + 24, &sz, 4); memcpy(mbi + 32, &state, 4); memcpy(mbi + 36, &prot, 4);
        if (ob) vm_poke(ob, mbi, 48);
        ret = 48;
    } else if (!_stricmp(name, "GetSystemTimeAsFileTime")) {
        u64 z = 0; if (rcx) vm_poke((u32)rcx, &z, 8); ret = 0;
    } else if (!_stricmp(name, "GetSystemTime") || !_stricmp(name, "GetLocalTime")) {
        u8 z[16]; memset(z, 0, sizeof(z)); if (rcx) vm_poke((u32)rcx, z, 16); ret = 0;
    } else if (!_stricmp(name, "QueryPerformanceCounter")) {
        u64 v = (u64)g_insn * 100 + 1; if (rcx) vm_poke((u32)rcx, &v, 8); ret = 1;
    } else if (!_stricmp(name, "QueryPerformanceFrequency")) {
        u64 v = 10000000; if (rcx) vm_poke((u32)rcx, &v, 8); ret = 1;
    } else if (!_stricmp(name, "GetStdHandle")) {
        ret = ((u32)rcx == 0xFFFFFFF5u) ? 0x14 : 0x10;   /* 假的 stdin/stdout 句柄 */
    } else if (!_stricmp(name, "TlsAlloc") || !_stricmp(name, "FlsAlloc")) {
        ret = (u64)(g_tls_next++ & 63);
    } else if (!_stricmp(name, "TlsGetValue") || !_stricmp(name, "FlsGetValue")) {
        ret = g_tls64[(u32)rcx & 63];
    } else if (!_stricmp(name, "TlsSetValue") || !_stricmp(name, "FlsSetValue")) {
        g_tls64[(u32)rcx & 63] = rdx; ret = 1;
    } else if (!_stricmp(name, "MultiByteToWideChar")) {
        u64 a5 = x64_arg(5), a6 = x64_arg(6);
        int cb = (int)(s32)r9, cch = (int)(s32)a6; u32 cnt = 0;
        if (cb < 0) { u32 k = 0; u8 c = 1; while (k < 0x10000 && vm_read8((u32)r8 + k, &c) && c) k++; cb = (int)k + 1; }
        cnt = (u32)cb;
        if (cch == 0) ret = cnt;
        else {
            u32 k = 0; for (; k < cnt && k < (u32)cch; k++) { u8 c = 0; if (!vm_read8((u32)r8 + k, &c)) break; u16 w = c; vm_poke((u32)a5 + k * 2, &w, 2); }
            ret = k;
        }
    } else if (!_stricmp(name, "WideCharToMultiByte")) {
        u64 a5 = x64_arg(5), a6 = x64_arg(6);
        int cch = (int)(s32)r9, cb = (int)(s32)a6; u32 cnt = 0;
        if (cch < 0) { u32 k = 0; u16 w = 1; while (k < 0x10000 && vm_read((u32)r8 + k * 2, &w, 2) && w) k++; cch = (int)k + 1; }
        cnt = (u32)cch;
        if (cb == 0) ret = cnt;
        else {
            u32 k = 0; for (; k < cnt && k < (u32)cb; k++) { u16 w = 0; if (!vm_read((u32)r8 + k * 2, &w, 2)) break; u8 c = (u8)w; vm_poke((u32)a5 + k, &c, 1); }
            ret = k;
        }
    } else if (!_stricmp(name, "memcpy") || !_stricmp(name, "memmove")) {
        u32 n = (u32)r8; if (n > 0x4000000u) n = 0x4000000u;
        u8 t[4096]; u32 done = 0; ret = rcx;
        while (done < n) { u32 k = n - done; if (k > sizeof(t)) k = sizeof(t); if (!vm_read((u32)rdx + done, t, k)) break; if (!vm_poke((u32)rcx + done, t, k)) break; done += k; }
    } else if (!_stricmp(name, "memset")) {
        u32 n = (u32)r8; if (n > 0x4000000u) n = 0x4000000u;
        u8 t[4096]; memset(t, (int)(u8)rdx, sizeof(t)); u32 done = 0; ret = rcx;
        while (done < n) { u32 k = n - done; if (k > sizeof(t)) k = sizeof(t); if (!vm_poke((u32)rcx + done, t, k)) break; done += k; }
    } else if (!_stricmp(name, "memcmp")) {
        u32 n = (u32)r8; int r = 0;
        for (u32 k = 0; k < n; k++) { u8 a = 0, b = 0; if (!vm_read8((u32)rcx + k, &a) || !vm_read8((u32)rdx + k, &b)) break; if (a != b) { r = (a < b) ? -1 : 1; break; } }
        ret = (u64)(u32)(s64)r;
    } else if (!_stricmp(name, "strlen")) {
        u32 k = 0; u8 c = 1; while (k < 0x100000 && vm_read8((u32)rcx + k, &c) && c) k++; ret = k;
    } else if (!_stricmp(name, "wcslen")) {
        u32 k = 0; u16 w = 1; while (k < 0x100000 && vm_read((u32)rcx + k * 2, &w, 2) && w) k++; ret = k;
    } else if (!_stricmp(name, "strcmp") || !_stricmp(name, "strncmp")) {
        u32 n = (u32)r8; int r = 0;
        for (u32 k = 0; k < (n ? n : 0x100000); k++) { u8 a = 0, b = 0; if (!vm_read8((u32)rcx + k, &a) || !vm_read8((u32)rdx + k, &b)) break; if (a != b) { r = (a < b) ? -1 : 1; break; } if (!a) break; }
        ret = (u64)(u32)(s64)r;
    } else if (!_stricmp(name, "strcpy") || !_stricmp(name, "wcscpy")) {
        int wide = (name[0] == 'w'); u32 k = 0; ret = rcx;
        if (wide) { u16 w = 1; do { if (!vm_read((u32)rdx + k * 2, &w, 2)) break; vm_poke((u32)rcx + k * 2, &w, 2); k++; } while (w && k < 0x100000); }
        else { u8 c = 1; do { if (!vm_read8((u32)rdx + k, &c)) break; vm_poke((u32)rcx + k, &c, 1); k++; } while (c && k < 0x100000); }
    } else if (!_stricmp(name, "InterlockedIncrement") || !_stricmp(name, "InterlockedDecrement")
               || !_stricmp(name, "InterlockedExchangeAdd") || !_stricmp(name, "InterlockedExchange")
               || !_stricmp(name, "InterlockedCompareExchange")) {
        u32 v = 0; vm_read32((u32)rcx, &v);
        if (!_stricmp(name, "InterlockedIncrement")) { v++; vm_write32((u32)rcx, v); ret = v; }
        else if (!_stricmp(name, "InterlockedDecrement")) { v--; vm_write32((u32)rcx, v); ret = v; }
        else if (!_stricmp(name, "InterlockedExchangeAdd")) { u32 o = v; vm_write32((u32)rcx, v + (u32)rdx); ret = o; }
        else if (!_stricmp(name, "InterlockedExchange")) { u32 o = v; vm_write32((u32)rcx, (u32)rdx); ret = o; }
        else { u32 o = v; if (v == (u32)rdx) vm_write32((u32)rcx, (u32)r8); ret = o; }
    } else if (!_stricmp(name, "__getmainargs") || !_stricmp(name, "_getmainargs") || !_stricmp(name, "_wgetmainargs")) {
        int wide = (name[1] == 'w');
        u32 argc = 1;
        if (rcx) vm_poke((u32)rcx, &argc, 4);
        u32 arr = x64_cell(16), s = x64_strcell(g_sample_path, wide);
        vm_poke(arr, &s, 4); u32 z = 0; vm_poke(arr + 4, &z, 4);
        if (rdx) { u32 pa = arr; vm_poke((u32)rdx, &pa, 4); }
        u32 envp = x64_cell(16);
        if (wide) { u16 zz = 0; vm_poke(envp, &zz, 2); } else vm_write8(envp, 0);
        if (r8) { u32 pe = envp; vm_poke((u32)r8, &pe, 4); }
        ret = 0;
    } else if (!strncmp(name, "Reg", 3)) {
        int wide = (name[strlen(name) - 1] == 'W');
        char sub[300]; sub[0] = 0;
        
        // 1. 读取键名
        if (_stricmp(name, "RegCloseKey")) {
            x64_rdstr(rdx, sub, sizeof(sub), wide);
        }

        if (!_stricmp(name, "RegSetValueExW") || !_stricmp(name, "RegSetValueExA")) {
            u64 data = x64_arg(5); u32 cb = (u32)x64_arg(6), ty = (u32)r9;
            char prev[256] = {0};
            if (data && cb) {
                u32 limit = (wide ? cb / 2 : cb);
                if (limit > 250) limit = 250;
                if (wide) {
                    for (u32 i = 0; i < limit; i++) {
                        u16 w = 0; if (!vm_read((u32)data + i * 2, &w, 2)) break;
                        prev[i] = (w >= 32 && w < 127) ? (char)w : '.';
                    }
                } else {
                    for (u32 i = 0; i < limit; i++) {
                        u8 c = 0; if (!vm_read((u32)data + i, &c, 1)) break;
                        prev[i] = (c >= 32 && c < 127) ? (char)c : '.';
                    }
                }
            }
            blog("注册表", "★%s(名称=\"%s\", 类型=%u, 长度=%u, 数据=\"%s\")", name, sub, ty, cb, prev);
            tr("注册表\t设置值\t%s\t%s\n", sub, prev);
            say("  [注册表] ★样本写入注册表值：%s = \"%s\"（类型 %u）\n", sub, prev, ty);
            ret = 0;
        } else if (!_stricmp(name, "RegCreateKeyExW") || !_stricmp(name, "RegCreateKeyExA")) {
            blog("注册表", "★%s(\"%s\")", name, sub);
            tr("注册表\t创建键\t%s\n", sub);
            say("  [注册表] ★样本创建/打开注册表键：%s\n", sub);
            u64 phk = x64_arg(8);
            if (phk) { u32 h = 0x00E00000; vm_poke((u32)phk, &h, 4); }
            u64 disp = x64_arg(9); if (disp) { u32 one = 1; vm_poke((u32)disp, &one, 4); }
            ret = 0;
        } else if (!_stricmp(name, "RegOpenKeyExW") || !_stricmp(name, "RegOpenKeyExA") || !_stricmp(name, "RegCreateKeyW") || !_stricmp(name, "RegCreateKeyA")) {
            blog("注册表", "%s(\"%s\")", name, sub);
            u64 phk = 0;
            if (!_stricmp(name, "RegOpenKeyExW") || !_stricmp(name, "RegOpenKeyExA")) phk = x64_arg(5); // 正确提取第5个参数
            else phk = r8; // RegCreateKeyW/A 的第3个参数
            if (phk) { u32 h = 0x00E00000; vm_poke((u32)phk, &h, 4); }
            ret = 0;
        } else if (!_stricmp(name, "RegDeleteTreeW") || !_stricmp(name, "RegDeleteKeyW") || !_stricmp(name, "RegDeleteValueW")
                   || !_stricmp(name, "RegDeleteKeyA") || !_stricmp(name, "RegDeleteValueA")) {
            blog("注册表", "★%s(\"%s\")", name, sub);
            tr("注册表\t删除\t%s\n", sub);
            say("  [注册表] ★样本删除注册表项：%s\n", sub);
            ret = 0;
        } else if (!_stricmp(name, "RegQueryValueExW") || !_stricmp(name, "RegQueryValueExA")) {
            blog("注册表", "RegQueryValueEx(\"%s\") -> 未找到（沙盒注册表为空）", sub);
            ret = 2; g_last_error = 2;                     /* ERROR_FILE_NOT_FOUND */
        } else {
            blog("注册表", "%s(\"%s\")", name, sub);
            ret = 0;
        }
    } else if (!_stricmp(name, "ShellExecuteW") || !_stricmp(name, "ShellExecuteA")) {
        int wide = (name[strlen(name) - 1] == 'W');
        char op[64], file[300], par[300];
        x64_rdstr(rcx, op, sizeof(op), wide);
        x64_rdstr(rdx, file, sizeof(file), wide);
        x64_rdstr(r8, par, sizeof(par), wide);
        blog("执行", "★%s(\"%s\", 文件=\"%s\", 参数=\"%s\")", name, op, file, par);
        tr("执行\t%s\t%s\n", name, file);
        say("  [执行] ★样本调用 %s 启动：%s %s\n", name, file, par);
        ret = 33;
    } else if (!_stricmp(name, "ShellExecuteExW") || !_stricmp(name, "ShellExecuteExA")) {
        int wide = (name[strlen(name) - 1] == 'W');
        char file[300], par[300];
        /* SHELLEXECUTEINFO：cbSize(4) + fMask(4) + hwnd(8) + lpVerb(8) + lpFile(8) + lpParameters(8) */
        u64 pfile = 0, ppar = 0;
        vm_read((u32)rcx + 24, &pfile, 8);
        vm_read((u32)rcx + 32, &ppar, 8);
        x64_rdstr(pfile, file, sizeof(file), wide);
        x64_rdstr(ppar, par, sizeof(par), wide);
        blog("执行", "★%s(文件=\"%s\", 参数=\"%s\")", name, file, par);
        tr("执行\t%s\t%s\n", name, file);
        say("  [执行] ★样本调用 %s 启动：%s %s\n", name, file, par);
        ret = 1;
    } else if (!_stricmp(name, "WinExec")) {
        char cmd[300]; x64_rdstr(rcx, cmd, sizeof(cmd), 0);
        blog("执行", "★WinExec(\"%s\", %u)", cmd, (u32)rdx);
        tr("执行\tWinExec\t%s\n", cmd);
        say("  [执行] ★样本调用 WinExec：%s\n", cmd);
        ret = 33;
    } else if (!_stricmp(name, "CreateProcessW") || !_stricmp(name, "CreateProcessA") || !_stricmp(name, "CreateProcessAsUserW")) {
        int wide = (name[strlen(name) - 1] == 'W');
        char app[300], cmd[300];
        x64_rdstr(rcx, app, sizeof(app), wide);
        x64_rdstr(rdx, cmd, sizeof(cmd), wide);
        blog("执行", "★%s(应用=\"%s\", 命令行=\"%s\")", name, app, cmd);
        tr("执行\t%s\t%s %s\n", name, app, cmd);
        say("  [执行] ★样本尝试启动进程：%s %s\n", app, cmd);
        if (r8) { u8 pi[0x70]; memset(pi, 0, sizeof(pi)); vm_poke((u32)r8, pi, sizeof(pi)); }
        ret = 1;
    } else if (!_stricmp(name, "system") || !_stricmp(name, "popen")) {
        char cmd[300]; x64_rdstr(rcx, cmd, sizeof(cmd), 0);
        blog("执行", "★%s(\"%s\")", name, cmd);
        tr("执行\t%s\t%s\n", name, cmd);
        say("  [执行] ★样本调用 %s：%s\n", name, cmd);
        ret = 0;
    } else if (!_stricmp(name, "URLDownloadToFileW") || !_stricmp(name, "URLDownloadToFileA")) {
        int wide = (name[strlen(name) - 1] == 'W');
        char url[300], fn[300];
        x64_rdstr(rdx, url, sizeof(url), wide);
        x64_rdstr(r8, fn, sizeof(fn), wide);
        blog("网络", "★%s(URL=\"%s\", 保存到=\"%s\")", name, url, fn);
        tr("网络\t下载\t%s -> %s\n", url, fn);
        say("  [网络] ★样本尝试下载文件：%s -> %s\n", url, fn);
        ret = 0;
    } else if (!_stricmp(name, "InternetOpenUrlA") || !_stricmp(name, "InternetOpenUrlW")
               || !_stricmp(name, "InternetConnectA") || !_stricmp(name, "InternetConnectW")
               || !_stricmp(name, "InternetOpenA") || !_stricmp(name, "InternetOpenW")
               || !_stricmp(name, "HttpOpenRequestA") || !_stricmp(name, "HttpSendRequestA")) {
        int wide = (name[strlen(name) - 1] == 'W');
        char a[300]; x64_rdstr(rcx, a, sizeof(a), wide);
        blog("网络", "★%s(\"%s\")", name, a);
        say("  [网络] ★样本调用网络 API：%s（沙盒内假成功）\n", name);
        ret = 0x00F00000;
    } else if (!_stricmp(name, "WSAStartup") || !_stricmp(name, "socket") || !_stricmp(name, "connect")
               || !_stricmp(name, "send") || !_stricmp(name, "recv") || !_stricmp(name, "gethostbyname")) {
        blog("网络", "★%s：样本尝试联网（沙盒内一律假成功）", name);
        say("  [网络] ★样本调用网络 API：%s\n", name);
        ret = 0;
    } else if (!_stricmp(name, "OpenProcess") || !_stricmp(name, "OpenThread") || !_stricmp(name, "DuplicateHandle")) {
        blog("动态API", "★%s：样本尝试打开/复制其他进程（沙盒里只记录，不真做）", name);
        tr("动态API\t%s\t打开进程/线程句柄\n", name);
        say("  [动态API] ★样本调用 %s（进程/线程操作）\n", name);
        ret = 0x00A10000;
    } else if (!_stricmp(name, "ReadProcessMemory") || !_stricmp(name, "WriteProcessMemory")
               || !_stricmp(name, "NtReadVirtualMemory") || !_stricmp(name, "NtWriteVirtualMemory")) {
        blog("动态API", "★%s：样本尝试读写其他进程内存（写进程内存常为注入手法）", name);
        tr("动态API\t%s\t跨进程内存\n", name);
        say("  [动态API] ★样本调用 %s（跨进程内存操作）\n", name);
        ret = 0;
    } else if (!_stricmp(name, "VirtualAllocEx") || !_stricmp(name, "VirtualFreeEx") || !_stricmp(name, "VirtualProtectEx")) {
        blog("动态API", "★%s：样本在目标进程内申请/改内存（注入准备）", name);
        ret = 0;
    } else if (!_stricmp(name, "CreateToolhelp32Snapshot") || !_stricmp(name, "Process32FirstW") || !_stricmp(name, "Process32NextW")
               || !_stricmp(name, "Module32FirstW") || !_stricmp(name, "Module32NextW")) {
        blog("动态API", "★%s：样本枚举进程/模块列表", name);
        ret = 0;
    } else if (!_stricmp(name, "GetCurrentProcess") || !_stricmp(name, "GetCurrentThread")) {
        ret = (u64)-1;                                   /* 伪句柄 */
    } else if (!_stricmp(name, "EncodePointer") || !_stricmp(name, "DecodePointer")) {
        ret = rcx;
    } else if (!_stricmp(name, "CreateMutexA") || !_stricmp(name, "CreateMutexW") || !_stricmp(name, "CreateEventA")
               || !_stricmp(name, "CreateEventW") || !_stricmp(name, "CreateSemaphoreA") || !_stricmp(name, "OpenMutexA")
               || !_stricmp(name, "OpenEventA") || !_stricmp(name, "CreateFileMappingA") || !_stricmp(name, "CreateFileMappingW")) {
        ret = 0x00B00000;
    } else if (!_stricmp(name, "GetModuleHandleExA") || !_stricmp(name, "GetModuleHandleExW")) {
        if (r8) { u32 h = g_imagebase; vm_poke((u32)r8, &h, 4); }
        ret = 1;
    } else if (!_stricmp(name, "_beginthread") || !_stricmp(name, "_beginthreadex")
               || !_stricmp(name, "CreateThread") || !_stricmp(name, "CreateRemoteThread")) {
        u64 fn = 0, arg = 0;
        if (!_stricmp(name, "_beginthread")) { fn = rcx; arg = r8; }         /* (start, stack, arg) */
        else { fn = r8; arg = r9; }                                          /* lpStartAddress / lpParameter */
        if (g_th_n < TH_MAX && fn) { g_th_fn[g_th_n] = fn; g_th_arg[g_th_n] = arg; g_th_n++; }
        blog("线程", "★%s(入口=0x%08X, 参数=0x%llX)：已登记，主入口返回后在沙盒内运行", name, (u32)fn, (unsigned long long)arg);
        say("  [线程] ★样本请求创建工作线程 0x%08X（登记，稍后运行）\n", (u32)fn);
        ret = 0x00C00000 + (u64)g_th_n;
    } else if (!_stricmp(name, "GetSystemDirectoryA") || !_stricmp(name, "GetSystemDirectoryW")) {
        ret = x64_wpath(rcx, rdx, "C:\\Windows\\System32", name[strlen(name) - 1] == 'W');
    } else if (!_stricmp(name, "GetWindowsDirectoryA") || !_stricmp(name, "GetWindowsDirectoryW")) {
        ret = x64_wpath(rcx, rdx, "C:\\Windows", name[strlen(name) - 1] == 'W');
    } else if (!_stricmp(name, "GetTempPathA") || !_stricmp(name, "GetTempPathW")) {
        ret = x64_wpath(rcx, rdx, "C:\\Users\\Public\\AppData\\Local\\Temp\\", name[strlen(name) - 1] == 'W');
    } else if (!_stricmp(name, "GetCurrentDirectoryA") || !_stricmp(name, "GetCurrentDirectoryW")) {
        ret = x64_wpath(rcx, rdx, "C:\\Users\\Public", name[strlen(name) - 1] == 'W');
    } else if (!_stricmp(name, "CreateFileA") || !_stricmp(name, "CreateFileW") || !_stricmp(name, "CreateFile2")) {
        char p[300] = {0};
        if (name[strlen(name) - 1] == 'W') {
            u32 k = 0; for (; k < 299; k++) { u16 w = 0; if (!vm_read((u32)rcx + k * 2, &w, 2) || !w) break; p[k] = (char)w; } p[k] = 0;
        } else vm_cstr((u32)rcx, p, sizeof(p));
        vfile_t* vf = vf_get(p);
        blog("文件", "★%s(\"%s\", access=0x%X) -> 句柄 0x%X%s", name, p, (u32)rdx, vf ? vf->handle : 0,
             (vf && vf->rd) ? "（样本自身，只读）" : "");
        say("  [文件] ★样本打开文件：%s（访问 0x%X）\n", p, (u32)rdx);
        ret = vf ? vf->handle : 0xFFFFFFFFu;
    } else if (!_stricmp(name, "WriteFile")) {
        u8 t[64] = {0}; u32 n = (u32)r8; if (n > sizeof(t)) n = sizeof(t); vm_read((u32)rdx, t, n);
        if (r9) { u32 full = (u32)r8; vm_poke((u32)r9, &full, 4); }
        blog("文件", "★WriteFile(句柄=0x%X, 长度=%u)：%02X %02X %02X %02X …", (u32)rcx, (u32)r8, t[0], t[1], t[2], t[3]);
        ret = 1;
    } else if (!_stricmp(name, "ReadFile")) {
        u32 h = (u32)rcx, buf = (u32)rdx, n = (u32)r8, got = 0;
        vfile_t* vf = vf_find(h);
        if (vf && n) {
            if (vf->rd) {
                u8 tmp[4096];
                while (got < n) {
                    u32 want = n - got; if (want > sizeof(tmp)) want = sizeof(tmp);
                    size_t rd = fread(tmp, 1, want, vf->rd);
                    if (!rd) break;
                    vm_poke(buf + got, tmp, (u32)rd); got += (u32)rd;
                }
            } else if (vf->data && vf->pos < vf->len) {
                got = vf->len - vf->pos; if (got > n) got = n;
                vm_poke(buf, vf->data + vf->pos, got); vf->pos += got;
            }
        }
        if (r9) vm_poke((u32)r9, &got, 4);
        blog("文件", "ReadFile64(句柄 0x%X, 请求 %u) -> %u 字节", h, n, got);
        ret = 1;
    } else if (!_stricmp(name, "GetFileType")) {
        ret = vf_find((u32)rcx) ? 1 : 0;                 /* FILE_TYPE_DISK */
    } else if (!_stricmp(name, "GetFileSizeEx")) {
        vfile_t* vf = vf_find((u32)rcx);
        if (vf) { u64 sz = vf_size(vf); if (rdx) vm_poke((u32)rdx, &sz, 8); ret = 1; }
        else ret = 0;
    } else if (!_stricmp(name, "SetFilePointerEx")) {
        vfile_t* vf = vf_find((u32)rcx);
        int ok = 0;
        if (vf) {
            s64 dist = (s64)rdx; u32 method = (u32)r9;
            if (vf->rd) {
                int whence = (method == 1) ? SEEK_CUR : (method == 2) ? SEEK_END : SEEK_SET;
                ok = (_fseeki64(vf->rd, dist, whence) == 0);
                if (ok && r8) { u64 pos = (u64)_ftelli64(vf->rd); vm_poke((u32)r8, &pos, 8); }
            } else {
                s64 np = (method == 2) ? (s64)vf->len + dist : (method == 1) ? (s64)vf->pos + dist : dist;
                if (np < 0) np = 0;
                vf->pos = (u32)np; if (r8) { u64 pos = (u64)vf->pos; vm_poke((u32)r8, &pos, 8); }
                ok = 1;
            }
        }
        ret = ok ? 1 : 0;
    } else if (!_stricmp(name, "CloseHandle")) {
        vfile_t* vf = vf_find((u32)rcx);
        if (vf && vf->rd) { fclose(vf->rd); vf->rd = NULL; }
        ret = 1;
    } else if (!_stricmp(name, "GetFileSize")) {
        vfile_t* vf = vf_find((u32)rcx);
        u32 sz = vf_size(vf);
        if (rdx) vm_poke((u32)rdx, &sz, 4);
        ret = sz;
    } else if (!_stricmp(name, "DeleteFileA") || !_stricmp(name, "DeleteFileW") || !_stricmp(name, "CopyFileA")
               || !_stricmp(name, "CopyFileW") || !_stricmp(name, "MoveFileA") || !_stricmp(name, "MoveFileW")
               || !_stricmp(name, "CreateDirectoryA") || !_stricmp(name, "CreateDirectoryW")
               || !_stricmp(name, "RemoveDirectoryA") || !_stricmp(name, "SetFileAttributesA") || !_stricmp(name, "SetFileAttributesW")) {
        char p[300] = {0};
        if (name[strlen(name) - 1] == 'W') { u32 k = 0; for (; k < 299; k++) { u16 w = 0; if (!vm_read((u32)rcx + k * 2, &w, 2) || !w) break; p[k] = (char)w; } p[k] = 0; }
        else vm_cstr((u32)rcx, p, sizeof(p));
        blog("文件", "★%s(\"%s\")", name, p);
        say("  [文件] ★样本 %s：%s\n", name, p);
        ret = 1;
    } else if (!_stricmp(name, "___lc_codepage_func") || !_stricmp(name, "__lc_codepage_func")
               || !_stricmp(name, "___lc_collate_cp_func") || !_stricmp(name, "__lc_collate_cp_func")) {
        ret = 936;                                  /* 简体中文 ANSI 代码页（0x3A8），避免返回 0 让 CRT 走异常分支 */
    } else if (!_stricmp(name, "___mb_cur_max_func") || !_stricmp(name, "__mb_cur_max_func")
               || !_stricmp(name, "___mb_cur_max") || !_stricmp(name, "__p___mb_cur_max")) {
        ret = 1;
    } else if (!_stricmp(name, "ConvertStringSecurityDescriptorToSecurityDescriptorW") ||
               !_stricmp(name, "ConvertStringSecurityDescriptorToSecurityDescriptorA")) {
        /* PyInstaller 等 onefile 释放器会给临时目录设 DACL；返回一个假的 SECURITY_DESCRIPTOR 即可 */
        u32 sd = vm_alloc_region(0, 0x100, P_R | P_W, RK_ALLOC, "SD64");
        if (r8) { u64 p = sd; vm_poke((u32)r8, &p, 8); }
        if (r9) { u32 sz = 0x14; vm_poke((u32)r9, &sz, 4); }
        blog("动态API", "%s -> 假安全描述符 0x%08X", name, sd);
        ret = 1;
    } else if (name_in(name, NM_RET1)) {
        ret = 1;
    } else if (name_in(name, NM_RET0)) {
        ret = 0;
    } else {
        blog("API未实现", "%s -> 返回 0（x64 解释器按 0 处理）", name);
        ret = 0;
    }
    X[0] = ret;
    if (getenv("PEVM_API_LOG")) fprintf(stderr, "[API64] %s -> 0x%llX\n", name, (unsigned long long)ret);
    u64 ra = xpop();
    RIP = ra; g_x64_jmp = 1;
    if (RIP == (u64)EXIT_MAGIC) { x64_stop("样本在 API 调用后结束（回到返回哨兵）"); g_halted = 1; return 0; }
    if (RIP <= 0xFFFFFFFFull) {
        u32 pg = (u32)RIP >> PG_SHIFT;
        if (pg >= PG_COUNT || !g_pg[pg].p || !(g_pg[pg].prot & P_X)) {
            x64_stop("API 返回地址 0x%08X 不是可执行内存（样本实现可能在系统 DLL 内）", (u32)RIP);
            g_halted = 1; return 0;
        }
    }
    return 1;
}

/* ---- 单条指令执行（op 已解码；rex_* 为 REX 位；size 已按 REX.W/0x66 定）---- */
static int x64_execute(u8 op, int rex_w, int rex_r, int rex_x, int rex_b) {
    int opsz = rex_w ? 8 : (g_opsz16 ? 2 : 4);
    switch (op) {
    /* ---- mov ---- */
    case 0x88: case 0x89: { int sz = (op == 0x88) ? 1 : opsz; x64m_t m; x64_modrm(&m, sz, rex_r, rex_x, rex_b); x64_write(&m, xr(m.reg, sz)); return 1; }
    case 0x8A: case 0x8B: { int sz = (op == 0x8A) ? 1 : opsz; x64m_t m; x64_modrm(&m, sz, rex_r, rex_x, rex_b); xw(m.reg, sz, x64_read(&m)); return 1; }
    case 0x8C: { x64m_t m; x64_modrm(&m, 2, rex_r, rex_x, rex_b); x64_write(&m, (u64)((g_segovr == 1) ? 0x3B : 0x23)); return 1; }
    case 0x8E: { x64m_t m; x64_modrm(&m, 2, rex_r, rex_x, rex_b); (void)x64_read(&m); return 1; }
    case 0x8D: { x64m_t m; x64_modrm(&m, opsz, rex_r, rex_x, rex_b); if (!m.is_mem) return x64_stop("LEA 需要内存操作数 @0x%08X", (u32)RIP); xw(m.reg, opsz, x64_ea(&m)); return 1; }
    case 0xC6: case 0xC7: {
        int sz = (op == 0xC6) ? 1 : opsz;
        x64m_t m; x64_modrm(&m, sz, rex_r, rex_x, rex_b);
        if ((m.reg & 7) != 0) return x64_stop("C6/C7 非法 reg 域 @0x%08X", (u32)RIP);
        u64 imm;
        if (sz == 1) imm = xf1();
        else if (sz == 2) imm = xf2();
        else if (sz == 8) imm = (u64)(s64)(s32)xf4();
        else imm = xf4();
        x64_write(&m, imm);
        return 1;
    }
    case 0xB0: case 0xB1: case 0xB2: case 0xB3: case 0xB4: case 0xB5: case 0xB6: case 0xB7:
        xw((op - 0xB0) | (rex_b ? 8 : 0), 1, xf1()); return 1;
    case 0xB8: case 0xB9: case 0xBA: case 0xBB: case 0xBC: case 0xBD: case 0xBE: case 0xBF: {
        int r = (op - 0xB8) | (rex_b ? 8 : 0);
        u64 imm;
        if (rex_w) imm = xf8();                       /* mov r64, imm64 */
        else if (g_opsz16) imm = xf2();
        else imm = xf4();
        xw(r, opsz, imm);
        return 1;
    }
    case 0xA0: case 0xA1: { u64 a = xf8(); int sz = (op == 0xA0) ? 1 : opsz; xw(0, sz, x64_read(&(x64m_t){ .is_mem = 1, .size = sz, .addr = a, .seg = g_segovr })); return 1; }
    case 0xA2: case 0xA3: { u64 a = xf8(); int sz = (op == 0xA2) ? 1 : opsz; x64_write(&(x64m_t){ .is_mem = 1, .size = sz, .addr = a, .seg = g_segovr }, xr(0, sz)); return 1; }
    case 0x86: case 0x87: { int sz = (op == 0x86) ? 1 : opsz; x64m_t m; x64_modrm(&m, sz, rex_r, rex_x, rex_b); u64 v = x64_read(&m); x64_write(&m, xr(m.reg, sz)); xw(m.reg, sz, v); return 1; }
    case 0x90: return 1;                              /* nop（含 0x66/REX 修饰）*/
    case 0x91: case 0x92: case 0x93: case 0x94: case 0x95: case 0x96: case 0x97: {
        int r = (op - 0x90) | (rex_b ? 8 : 0);
        u64 t = X[0]; X[0] = X[r]; X[r] = t; return 1;
    }
    case 0x98: { if (rex_w) X[0] = (u64)(s64)(s32)X[0]; else if (g_opsz16) X[0] = (X[0] & 0xFFFFFFFFFFFF0000ull) | (u64)(u16)(s16)X[0]; else X[0] = (u64)(s64)(s32)(u32)X[0]; return 1; }
    case 0x99: { if (rex_w) X[2] = (X[0] & 0x8000000000000000ull) ? 0xFFFFFFFFFFFFFFFFull : 0; else if (g_opsz16) X[2] = (X[0] & 0x8000) ? 0xFFFF : 0; else X[2] = (X[0] & 0x80000000u) ? 0xFFFFFFFFull : 0; return 1; }
    case 0x63: { x64m_t m; x64_modrm(&m, 4, rex_r, rex_x, rex_b); s32 v = (s32)(u32)x64_read(&m); xw(m.reg, opsz, (u64)(s64)v); return 1; }
    case 0x60: case 0x61: return x64_stop("pusha/popa 在 64 位模式下非法 @0x%08X", (u32)RIP);

    /* ---- 栈 ---- */
    case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57:
        if (g_opsz16) xpush16((u16)xr((op - 0x50) | (rex_b ? 8 : 0), 2)); else xpush(xr((op - 0x50) | (rex_b ? 8 : 0), 8));
        return 1;
    case 0x58: case 0x59: case 0x5A: case 0x5B: case 0x5C: case 0x5D: case 0x5E: case 0x5F: {
        int r = (op - 0x58) | (rex_b ? 8 : 0);
        if (g_opsz16) { u16 v = 0; if (!xrd(X[4], &v, 2)) g_fault = 1; X[4] += 2; xw(r, 2, v); }
        else xw(r, 8, xpop());
        return 1;
    }
    case 0x68: if (g_opsz16) xpush16((u16)xf2()); else xpush((u64)(s64)(s32)xf4()); return 1;
    case 0x6A: { s8 v = (s8)xf1(); xpush((u64)(s64)v); return 1; }
    case 0x8F: { x64m_t m; x64_modrm(&m, 8, rex_r, rex_x, rex_b); if ((m.reg & 7) != 0) return x64_stop("8F 非法 reg 域 @0x%08X", (u32)RIP); x64_write(&m, xpop()); return 1; }
    case 0x9C: xpush((u64)EFLAGS | 0x02); return 1;
    case 0x9D: { u64 v = xpop(); EFLAGS = (u32)v | 0x02; return 1; }
    case 0xC9: { X[4] = X[5]; xw(5, 8, xpop()); return 1; }   /* leave */

    /* ---- 跳转/调用/返回 ---- */
    case 0xE8: { s32 rel = (s32)xf4(); xpush(g_x64_cur); RIP = g_x64_cur + (u64)(s64)rel; g_x64_jmp = 1; return 1; }
    case 0xE9: { s32 rel = (s32)xf4(); RIP = g_x64_cur + (u64)(s64)rel; g_x64_jmp = 1; return 1; }
    case 0xEB: { s8 rel = (s8)xf1(); RIP = g_x64_cur + (u64)(s64)rel; g_x64_jmp = 1; return 1; }
    case 0xC3: { u64 ra = xpop(); if (ra == (u64)EXIT_MAGIC) { g_halted = 1; x64_stop("样本从入口正常返回"); return 0; } RIP = ra; g_x64_jmp = 1; return 1; }
    case 0xC2: { u16 imm = (u16)xf2(); u64 ra = xpop(); if (ra == (u64)EXIT_MAGIC) { g_halted = 1; x64_stop("样本正常返回"); return 0; } RIP = ra; X[4] += imm; g_x64_jmp = 1; return 1; }
    case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75: case 0x76: case 0x77:
    case 0x78: case 0x79: case 0x7A: case 0x7B: case 0x7C: case 0x7D: case 0x7E: case 0x7F: { s8 rel = (s8)xf1(); if (cond(op & 0xF)) { RIP = g_x64_cur + (u64)(s64)rel; g_x64_jmp = 1; } return 1; }
    case 0xE0: case 0xE1: case 0xE2: case 0xE3: {
        s8 rel = (s8)xf1(); X[1]--; int z = (X[1] == 0);
        if (op == 0xE3 ? z : (op == 0xE0 ? !z : (op == 0xE1 ? z : !z))) { RIP = g_x64_cur + (u64)(s64)rel; g_x64_jmp = 1; }
        return 1;
    }
    case 0xCC: g_halted = 1; return x64_stop("命中 int3（可能是反调试/异常处理）");
    case 0xCD: {
        u8 n = (u8)xf1(); g_halted = 1;
        if (n == 0x29) {
            /* int 0x29 = __fastfail：把"自毁"如实记成反调试/反篡改证据 */
            blog("反调试", "★样本命中 int 0x29（__fastfail，ecx=0x%08X）：反调试/完整性校验触发的自毁", (u32)X[1]);
            tr("反调试\tint 0x29\t__fastfail ecx=0x%08X\n", (u32)X[1]);
            return x64_stop("命中 int 0x29（__fastfail，ecx=0x%08X）：样本主动自毁，通常为反调试/反篡改", (u32)X[1]);
        }
        return x64_stop("命中 int 0x%02X（未模拟中断/异常）", n);
    }
    case 0xF4: g_halted = 1; return x64_stop("命中 hlt");

    /* ---- 标志位 / 反 VM 常用空操作 ---- */
    case 0xF8: EFLAGS &= ~CF; return 1;
    case 0xF9: EFLAGS |=  CF; return 1;
    case 0xF5: EFLAGS ^=  CF; return 1;
    case 0xFC: EFLAGS &= ~DF; return 1;
    case 0xFD: EFLAGS |=  DF; return 1;
    case 0xFA: EFLAGS &= ~IF; return 1;
    case 0xFB: EFLAGS |=  IF; return 1;
    case 0x6C: case 0x6D: case 0x6E: case 0x6F: { blog("反虚拟机", "INS/OUTS(x64) 0x%02X @0x%08X 已按空操作处理", op, (u32)RIP); return 1; }
    case 0xE4: case 0xE5: case 0xEC: case 0xED: { if (op == 0xE4 || op == 0xE5) (void)xf1(); X[0] = (X[0] & 0xFFFFFFFFFFFF0000ull) | 0xFFFFull; blog("反虚拟机", "IN(x64) @0x%08X 已按非虚拟机返回 0xFFFF", (u32)RIP); return 1; }
    case 0xE6: case 0xE7: { (void)xf1(); return 1; }
    case 0xEE: case 0xEF: return 1;
    case 0xF1: blog("反调试", "ICEBP(x64) @0x%08X 已跳过", (u32)RIP); return 1;
    case 0xD4: { u8 b = (u8)xf1(); if (b == 0) return x64_stop("AAM 立即数为 0"); u8 al = (u8)X[0]; X[0] = (X[0] & 0xFFFFFFFFFFFFFF00ull) | ((u64)(al / b) << 8) | (u64)(al % b); xset_pzs(X[0] & 0xFF, 1); return 1; }
    case 0xD5: { u8 b = (u8)xf1(); u8 al = (u8)((u8)(X[0] >> 8) * b + (u8)X[0]); X[0] = (X[0] & 0xFFFFFFFFFFFFFF00ull) | al; xset_pzs(al, 1); return 1; }

    /* ---- x87（D8..DF）：x64 通路只做"解码同步 + 触碰内存"，不模拟运算 ----
     * 与 x86 通路对"无法模拟的编码"同一口径：按空操作处理并记日志，不中断执行
     * （首个样本若靠 x87 解密，这里会记在报告里，供人工复核）。 */
    case 0xD8: case 0xD9: case 0xDA: case 0xDB: case 0xDC: case 0xDD: case 0xDE: case 0xDF: {
        static int seen[8] = {0};
        u8 mb = 0; vm_read8((u32)g_x64_cur, &mb);
        x64m_t m; x64_modrm(&m, 8, rex_r, rex_x, rex_b);
        if (m.is_mem) { u64 a = x64_ea(&m); u8 t[16]; if (!xrd(a, t, 8)) { g_fault = 1; return 0; } }
        if (!seen[op - 0xD8]) {
            seen[op - 0xD8] = 1;
            say("  [说明] x64 通路遇到 x87 编码 0x%02X /%d @0x%08X：不模拟运算，按空操作继续。\n", op, (mb >> 3) & 7, (u32)RIP);
        }
        tr("x87\tx64 空操作 0x%02X /%d @0x%08X\n", op, (mb >> 3) & 7, (u32)RIP);
        return 1;
    }

    /* ---- ALU（r/m, r / r, r/m）---- */
    case 0x00: case 0x01: case 0x02: case 0x03: case 0x08: case 0x09: case 0x0A: case 0x0B:
    case 0x10: case 0x11: case 0x12: case 0x13: case 0x18: case 0x19: case 0x1A: case 0x1B:
    case 0x20: case 0x21: case 0x22: case 0x23: case 0x28: case 0x29: case 0x2A: case 0x2B:
    case 0x30: case 0x31: case 0x32: case 0x33: case 0x38: case 0x39: case 0x3A: case 0x3B: {
        int fam = (op >> 3) & 7, form = op & 3, sz = (op & 1) ? opsz : 1;
        x64m_t m; x64_modrm(&m, sz, rex_r, rex_x, rex_b);
        u64 rv = xr(m.reg, sz), a, b, r; int dst_mem;
        if (form == 0 || form == 1) { a = x64_read(&m); b = rv; dst_mem = 1; }
        else { a = rv; b = x64_read(&m); dst_mem = 0; }
        r = xalu(fam, a, b, sz);
        if (fam != 7) { if (dst_mem) x64_write(&m, r); else xw(m.reg, sz, r); }
        return 1;
    }
    case 0x04: case 0x05: case 0x0C: case 0x0D: case 0x14: case 0x15: case 0x1C: case 0x1D:
    case 0x24: case 0x25: case 0x2C: case 0x2D: case 0x34: case 0x35: case 0x3C: case 0x3D: {
        int fam = (op >> 3) & 7, sz = (op & 1) ? opsz : 1;
        u64 a = xr(0, sz), b;
        if (sz == 1) b = xf1(); else if (sz == 2) b = xf2(); else if (sz == 8) b = (u64)(s64)(s32)xf4(); else b = xf4();
        u64 r = xalu(fam, a, b, sz);
        if (fam != 7) xw(0, sz, r);
        return 1;
    }
    case 0x80: case 0x81: case 0x83: {
        int sz = (op == 0x80) ? 1 : opsz;
        x64m_t m; x64_modrm(&m, sz, rex_r, rex_x, rex_b);
        int sub = m.reg & 7;
        u64 b;
        if (op == 0x83) b = (u64)(s64)(s8)xf1();
        else if (sz == 1) b = xf1();
        else if (sz == 2) b = xf2();
        else if (sz == 8) b = (u64)(s64)(s32)xf4();
        else b = xf4();
        u64 a = x64_read(&m);
        u64 r = xalu(sub, a, b, sz);
        if (sub != 7) x64_write(&m, r);
        return 1;
    }
    case 0x84: case 0x85: { int sz = (op == 0x84) ? 1 : opsz; x64m_t m; x64_modrm(&m, sz, rex_r, rex_x, rex_b); u64 v = x64_read(&m); xflags_logic(v & xr(m.reg, sz), sz); return 1; }
    case 0xA8: case 0xA9: { int sz = (op == 0xA8) ? 1 : opsz; u64 b = (sz == 1) ? xf1() : (sz == 2 ? xf2() : (sz == 8 ? xf4() : xf4())); xflags_logic(xr(0, sz) & b, sz); return 1; }
    case 0xF6: case 0xF7: {
        int sz = (op == 0xF6) ? 1 : opsz;
        x64m_t m; x64_modrm(&m, sz, rex_r, rex_x, rex_b);
        int sub = m.reg & 7;
        u64 msk = xmask(sz);
        if (sub == 0 || sub == 1) {
            u64 b = (sz == 1) ? xf1() : (sz == 2 ? xf2() : (sz == 8 ? (u64)(s64)(s32)xf4() : xf4()));
            u64 a = x64_read(&m);
            xflags_logic(a & b, sz);
            return 1;
        }
        u64 a = x64_read(&m);
        if (sub == 2) { x64_write(&m, ~a & msk); return 1; }
        if (sub == 3) { u64 r = (0 - a) & msk; xflags_sub(0, a, r, sz); x64_write(&m, r); return 1; }
        if (sub == 4) { /* mul */
            u64 b = xr(0, sz);
            if (sz == 8) {
                u64 hi = 0;
                u64 lo = _umul128(a, b, &hi);
                X[0] = lo; X[2] = hi;
                EFLAGS &= ~(CF | OF);
                if (hi != 0) EFLAGS |= CF | OF;
            } else {
                u64 p = a * b;
                xw(0, sz, p & msk);
                xw(2, sz, (p >> (sz * 8)) & msk);
                EFLAGS &= ~(CF | OF);
                if ((p >> (sz * 8)) != 0) EFLAGS |= CF | OF;
            }
            return 1;
        }
        if (sub == 5) { /* imul 单操作数 */
            s64 sv = (sz == 8) ? (s64)a : (s64)((a ^ xmsb(sz)) - xmsb(sz));
            s64 sa = (sz == 8) ? (s64)xr(0, sz) : (s64)(((xr(0, sz)) ^ xmsb(sz)) - xmsb(sz));
            if (sz == 8) {
                s64 hi = 0;
                s64 lo = _mul128(sa, sv, &hi);
                X[0] = (u64)lo; X[2] = (u64)hi;
                EFLAGS &= ~(CF | OF);
                if (hi != (lo >> 63)) EFLAGS |= CF | OF;
            } else {
                s64 p = sa * sv;
                xw(0, sz, (u64)p & msk);
                xw(2, sz, ((u64)p >> (sz * 8)) & msk);
                EFLAGS &= ~(CF | OF);
                s64 truncated = (sz == 1) ? (s64)(s8)(u8)p
                               : (sz == 2 ? (s64)(s16)(u16)p : (s64)(s32)(u32)p);
                if (p != truncated) EFLAGS |= CF | OF;
            }
            return 1;
        }
        /* div / idiv */
        if (a == 0) { g_halted = 1; return x64_stop("除零（0x%08X）", (u32)RIP); }
        if (sz == 8) {
            if (sub == 6) {
                u64 rem = 0, q;
                if (X[2] >= a) { g_halted = 1; return x64_stop("div 溢出"); }
                q = _udiv128(X[2], X[0], a, &rem);
                X[0] = q; X[2] = rem;
            } else {
                s64 rem = 0;
                s64 q = _div128((s64)X[2], (s64)X[0], (s64)a, &rem);
                X[0] = (u64)q; X[2] = (u64)rem;
            }
            return 1;
        }
        u64 dv = (sz == 1) ? (xr(0, 2) & 0xFFFF) : (((xr(2, 2) & 0xFFFF) << 16) | (xr(0, 2) & 0xFFFF));
        if (sub == 6) { xw(0, sz, (dv / a) & msk); xw(2, sz, (dv % a) & msk); }
        else { s32 sdv = (s32)dv; s32 sa2 = (sz == 1) ? (s32)(s8)a : (s32)(s16)a; if (sa2 == 0) { g_halted = 1; return x64_stop("idiv 除零"); } xw(0, sz, (u64)(u32)(sdv / sa2) & msk); xw(2, sz, (u64)(u32)(sdv % sa2) & msk); }
        return 1;
    }
    case 0xFE: {
        x64m_t m; x64_modrm(&m, 1, rex_r, rex_x, rex_b);
        int sub = m.reg & 7; u64 a = x64_read(&m), msk = xmask(1);
        if (sub == 0) { int cf = EFLAGS & CF; u64 r = (a + 1) & msk; xflags_add(a, 1, r, 1); EFLAGS = (EFLAGS & ~CF) | cf; x64_write(&m, r); }
        else if (sub == 1) { int cf = EFLAGS & CF; u64 r = (a - 1) & msk; xflags_sub(a, 1, r, 1); EFLAGS = (EFLAGS & ~CF) | cf; x64_write(&m, r); }
        else return x64_stop("FE 未支持 reg=%d", sub);
        return 1;
    }
    case 0xFF: {
        x64m_t m; x64_modrm(&m, 8, rex_r, rex_x, rex_b);
        int sub = m.reg & 7;
        switch (sub) {
            case 0: { u64 a = x64_read(&m), msk = xmask(m.size); int cf = EFLAGS & CF; u64 r = (a + 1) & msk; xflags_add(a, 1, r, m.size); EFLAGS = (EFLAGS & ~CF) | cf; x64_write(&m, r); return 1; }
            case 1: { u64 a = x64_read(&m), msk = xmask(m.size); int cf = EFLAGS & CF; u64 r = (a - 1) & msk; xflags_sub(a, 1, r, m.size); EFLAGS = (EFLAGS & ~CF) | cf; x64_write(&m, r); return 1; }
            case 2: { u64 t = x64_read(&m); xpush(g_x64_cur); RIP = t; g_x64_jmp = 1; return 1; }
            case 3: { u64 t = m.is_mem ? x64_read(&(x64m_t){ .is_mem = 1, .size = 8, .addr = x64_ea(&m) }) : x64_read(&m); xpush(g_x64_cur); RIP = t; g_x64_jmp = 1; return 1; }
            case 4: { u64 t = x64_read(&m); RIP = t; g_x64_jmp = 1; return 1; }
            case 5: { u64 t = m.is_mem ? x64_read(&(x64m_t){ .is_mem = 1, .size = 8, .addr = x64_ea(&m) }) : x64_read(&m); RIP = t; g_x64_jmp = 1; return 1; }
            case 6: { xpush(x64_read(&m)); return 1; }
            case 7: { xpush(x64_read(&m)); return 1; }
            default: return x64_stop("FF 组未支持 reg=%d @0x%08X", sub, (u32)RIP);
        }
    }
    case 0x69: case 0x6B: {
        x64m_t m; x64_modrm(&m, opsz, rex_r, rex_x, rex_b);
        u64 imm;
        if (op == 0x6B) imm = (u64)(s64)(s8)xf1();
        else if (opsz == 2) imm = xf2();
        else if (opsz == 8) imm = (u64)(s64)(s32)xf4();
        else imm = xf4();
        u64 src = x64_read(&m);
        if (opsz == 8) {
            s64 hi = 0;
            s64 lo = _mul128((s64)src, (s64)imm, &hi);
            X[m.reg] = (u64)lo;
            EFLAGS &= ~(CF | OF);
            if (hi != (lo >> 63)) EFLAGS |= CF | OF;
        } else {
            s64 p = (s64)(s32)(u32)src * (s64)(s32)(u32)imm;
            u64 r = (u64)p & xmask(opsz);
            xw(m.reg, opsz, r);
            EFLAGS &= ~(CF | OF);
            if (p != (s64)(s32)(u32)r) EFLAGS |= CF | OF;
        }
        return 1;
    }
    /* ---- 移位 ---- */
    case 0xC0: case 0xC1: case 0xD0: case 0xD1: case 0xD2: case 0xD3: {
        int sz = (op == 0xC0 || op == 0xD0 || op == 0xD2) ? 1 : opsz;
        x64m_t m; x64_modrm(&m, sz, rex_r, rex_x, rex_b);
        int sub = m.reg & 7;
        u8 cnt;
        if (op == 0xD0 || op == 0xD1) cnt = 1;
        else if (op == 0xD2 || op == 0xD3) cnt = (u8)X[1];
        else cnt = (u8)xf1();
        u64 v = x64_read(&m);
        x64_write(&m, xshift(sub, v, cnt, sz));
        return 1;
    }
    /* ---- 字符串 ---- */
    case 0xA4: return x64_string(op, 1);
    case 0xA5: return x64_string(op, opsz);
    case 0xA6: return x64_string(op, 1);
    case 0xA7: return x64_string(op, opsz);
    case 0xAA: return x64_string(op, 1);
    case 0xAB: return x64_string(op, opsz);
    case 0xAC: return x64_string(op, 1);
    case 0xAD: return x64_string(op, opsz);
    case 0xAE: return x64_string(op, 1);
    case 0xAF: return x64_string(op, opsz);
    default: break;
    }

    /* ---------- 双字节 0F ---------- */
    if (op == 0x0F) {
        u8 op2 = (u8)xf1();
        if (g_fault) return x64_stop("取指越界（0F 后）@0x%08X", (u32)RIP);
        switch (op2) {
        case 0x1F: { x64m_t m; x64_modrm(&m, opsz, rex_r, rex_x, rex_b); return 1; }   /* nop r/m */
        case 0x0D:                                                                     /* prefetchw（3DNow/Intel 预取提示） */
        case 0x18: { x64m_t m; x64_modrm(&m, 1, rex_r, rex_x, rex_b); return 1; }      /* prefetchnta/t0/t1/t2：纯提示 */
        case 0xAE: { x64m_t m; x64_modrm(&m, 1, rex_r, rex_x, rex_b); return 1; }      /* fxsave/fxrstor/ldmxcsr/stmxcsr/clflush */
        case 0x05: return x64_stop("syscall（未模拟）@0x%08X", (u32)RIP);
        case 0x0B: return x64_stop("ud2（真机必异常）@0x%08X", (u32)RIP);
        case 0x34: case 0x35: return x64_stop("sysenter/sysexit（未模拟）");
        case 0xC0: case 0xC1: {                                                                       /* xadd r/m, r */
            int sz = (op2 == 0xC0) ? 1 : opsz;
            x64m_t m; x64_modrm(&m, sz, rex_r, rex_x, rex_b);
            u64 src = xr(m.reg, sz);
            u64 dst = x64_read(&m);
            u64 sum = (dst + src) & xmask(sz);
            xflags_add(dst, src, sum, sz);
            xw(m.reg, sz, dst);                    /* 目标寄存器 <- 原内存值 */
            x64_write(&m, sum);
            return 1;
        }
        case 0xB0: case 0xB1: {                                                                       /* cmpxchg r/m, r */
            int sz = (op2 == 0xB0) ? 1 : opsz;
            x64m_t m; x64_modrm(&m, sz, rex_r, rex_x, rex_b);
            u64 acc = xr(0, sz), src = xr(m.reg, sz), dst = x64_read(&m);
            xflags_sub(acc, dst, (acc - dst) & xmask(sz), sz);
            if (acc == dst) { EFLAGS |= ZF; x64_write(&m, src); }
            else { EFLAGS &= ~ZF; xw(0, sz, dst); }
            return 1;
        }
        /* ---------- SSE / SSE2：覆盖解壳常用的"整块搬移 + 按位运算" ---------- */
        case 0x10: case 0x11: case 0x28: case 0x29: case 0x6F: case 0x7F: {   /* movups/ups/aps/dqa */
            x64m_t m; x64_modrm(&m, 8, rex_r, rex_x, rex_b);
            int store = (op2 == 0x11 || op2 == 0x29 || op2 == 0x7F);
            int w = 16;
            if ((op2 == 0x10 || op2 == 0x11) && (g_rep == 2 || g_rep == 1)) w = (g_rep == 2) ? 8 : 4;
            u8 tmp[16] = {0};
            if (store) {
                memcpy(tmp, g_xm[m.reg & 15], (size_t)w);
                if (m.is_mem) { u64 a = x64_ea(&m); if (!xwr(a, tmp, (u32)w)) { g_fault = 1; return 0; } reg_mark_written((u32)a, (u32)w); }
                else memcpy(g_xm[m.rm & 15], tmp, (size_t)w);
            } else {
                if (m.is_mem) { u64 a = x64_ea(&m); if (!xrd(a, tmp, (u32)w)) { g_fault = 1; return 0; } }
                else memcpy(tmp, g_xm[m.rm & 15], (size_t)w);
                if (w == 16) memcpy(g_xm[m.reg & 15], tmp, 16);
                else { memset(g_xm[m.reg & 15], 0, 16); memcpy(g_xm[m.reg & 15], tmp, (size_t)w); }
            }
            return 1;
        }
        case 0x54: case 0x55: case 0x56: case 0x57: case 0xEF: {              /* andps/andnps/orps/xorps/pxor */
            x64m_t m; x64_modrm(&m, 8, rex_r, rex_x, rex_b);
            u8 r16[16] = {0};
            if (m.is_mem) { u64 a = x64_ea(&m); if (!xrd(a, r16, 16)) { g_fault = 1; return 0; } }
            else memcpy(r16, g_xm[m.rm & 15], 16);
            u8* d = (u8*)g_xm[m.reg & 15];
            for (int i = 0; i < 16; i++) {
                if (op2 == 0x54) d[i] = (u8)(d[i] & r16[i]);
                else if (op2 == 0x55) d[i] = (u8)(~d[i] & r16[i]);
                else if (op2 == 0x56) d[i] = (u8)(d[i] | r16[i]);
                else d[i] = (u8)(d[i] ^ r16[i]);
            }
            return 1;
        }
        case 0xD6: {                                                          /* movq xmm/m64, xmm */
            x64m_t m; x64_modrm(&m, 8, rex_r, rex_x, rex_b);
            u64 v = 0; memcpy(&v, g_xm[m.reg & 15], 8);
            if (m.is_mem) { u64 a = x64_ea(&m); if (!xwr(a, &v, 8)) { g_fault = 1; return 0; } reg_mark_written((u32)a, 8); }
            else { memset(g_xm[m.rm & 15], 0, 16); memcpy(g_xm[m.rm & 15], &v, 8); }
            return 1;
        }
        case 0x6E: {                                                          /* movd/movq xmm, r/m32|64 */
            int w = rex_w ? 8 : 4;
            x64m_t m; x64_modrm(&m, w, rex_r, rex_x, rex_b);
            u64 v = x64_read(&m);
            memset(g_xm[m.reg & 15], 0, 16);
            memcpy(g_xm[m.reg & 15], &v, (size_t)w);
            return 1;
        }
        case 0x7E: {                                                          /* movd r/m, xmm（F3 则 movq xmm, r/m）*/
            if (g_rep == 1) {
                x64m_t m; x64_modrm(&m, 8, rex_r, rex_x, rex_b);
                u64 v = x64_read(&m);
                memset(g_xm[m.reg & 15], 0, 16); memcpy(g_xm[m.reg & 15], &v, 8);
                return 1;
            }
            int w = rex_w ? 8 : 4;
            x64m_t m; x64_modrm(&m, w, rex_r, rex_x, rex_b);
            u64 v = 0; memcpy(&v, g_xm[m.reg & 15], (size_t)w);
            x64_write(&m, v);
            return 1;
        }
        case 0x12: case 0x16: {                                               /* movlps/movhps xmm, m64 */
            x64m_t m; x64_modrm(&m, 8, rex_r, rex_x, rex_b);
            u64 v = 0;
            if (m.is_mem) { u64 a = x64_ea(&m); if (!xrd(a, &v, 8)) { g_fault = 1; return 0; } }
            else memcpy(&v, g_xm[m.rm & 15], 8);
            memcpy((u8*)g_xm[m.reg & 15] + (op2 == 0x12 ? 0 : 8), &v, 8);
            return 1;
        }
        case 0x13: case 0x17: {                                               /* movlps/movhps m64, xmm */
            x64m_t m; x64_modrm(&m, 8, rex_r, rex_x, rex_b);
            u64 v = 0; memcpy(&v, (u8*)g_xm[m.reg & 15] + (op2 == 0x13 ? 0 : 8), 8);
            if (m.is_mem) { u64 a = x64_ea(&m); if (!xwr(a, &v, 8)) { g_fault = 1; return 0; } reg_mark_written((u32)a, 8); }
            else memcpy((u8*)g_xm[m.rm & 15] + (op2 == 0x13 ? 0 : 8), &v, 8);
            return 1;
        }
        case 0x14: case 0x15: {                                               /* unpcklps/unpckhps */
            x64m_t m; x64_modrm(&m, 8, rex_r, rex_x, rex_b);
            u8 r16[16] = {0};
            if (m.is_mem) { u64 a = x64_ea(&m); if (!xrd(a, r16, 16)) { g_fault = 1; return 0; } }
            else memcpy(r16, g_xm[m.rm & 15], 16);
            u8* d = (u8*)g_xm[m.reg & 15]; u8 t[16];
            int base = (op2 == 0x14) ? 0 : 8;
            memcpy(t + 0, d + base, 4); memcpy(t + 4, r16 + base, 4);
            memcpy(t + 8, d + base + 4, 4); memcpy(t + 12, r16 + base + 4, 4);
            memcpy(d, t, 16);
            return 1;
        }
        case 0x2E: case 0x2F: {                                               /* ucomiss/ucomisd（2F 按 2E 处理）*/
            int dbl = g_opsz16;
            x64m_t m; x64_modrm(&m, 4, rex_r, rex_x, rex_b);
            double a = 0, b = 0;
            if (dbl) {
                u64 x = 0, y = 0;
                memcpy(&x, g_xm[m.reg & 15], 8);
                if (m.is_mem) { u64 av = x64_ea(&m); if (!xrd(av, &y, 8)) { g_fault = 1; return 0; } }
                else memcpy(&y, g_xm[m.rm & 15], 8);
                memcpy(&a, &x, 8); memcpy(&b, &y, 8);
            } else {
                u32 x = 0, y = 0;
                memcpy(&x, g_xm[m.reg & 15], 4);
                if (m.is_mem) { u64 av = x64_ea(&m); if (!xrd(av, &y, 4)) { g_fault = 1; return 0; } }
                else memcpy(&y, g_xm[m.rm & 15], 4);
                float fa = 0, fb = 0; memcpy(&fa, &x, 4); memcpy(&fb, &y, 4); a = fa; b = fb;
            }
            EFLAGS &= ~(CF | PF | ZF | OF | SF | AF);
            if (a != a || b != b) EFLAGS |= CF | PF | ZF;          /* 有 NaN */
            else if (a < b) EFLAGS |= CF;
            else if (a == b) EFLAGS |= ZF;
            return 1;
        }
        /* ---------- SSE/SSE2 浮点算术与整数转换 ---------- */
        case 0x2A: {                                                          /* cvtsi2ss/cvtsi2sd */
            int dbl = (g_rep == 2);
            x64m_t m; x64_modrm(&m, rex_w ? 8 : 4, rex_r, rex_x, rex_b);
            s64 iv = (s64)x64_read(&m);
            u8* d = (u8*)g_xm[m.reg & 15];
            if (dbl) { double dv = (double)iv; memcpy(d, &dv, 8); }
            else { float fv = (float)iv; memcpy(d, &fv, 4); }
            return 1;
        }
        case 0x2C: case 0x2D: {                                               /* cvtt/cvt ss|sd -> si */
            int dbl = (g_rep == 2);
            x64m_t m; x64_modrm(&m, rex_w ? 8 : 4, rex_r, rex_x, rex_b);
            u8 r16[16] = {0};
            if (m.is_mem) { u64 a = x64_ea(&m); if (!xrd(a, r16, dbl ? 8 : 4)) { g_fault = 1; return 0; } }
            else memcpy(r16, g_xm[m.rm & 15], 16);
            if (dbl) { double dv = 0; memcpy(&dv, r16, 8); xw(m.reg, rex_w ? 8 : 4, (u64)(s64)dv); }
            else { float fv = 0; memcpy(&fv, r16, 4); xw(m.reg, rex_w ? 8 : 4, (u64)(s64)fv); }
            return 1;
        }
        case 0x58: case 0x59: case 0x5C: case 0x5E: case 0x5D: case 0x5F: case 0x51: {
            /* add/mul/sub/div/min/max/sqrt，标量 ss(F3)/sd(F2) 或 打包 ps/pd */
            x64m_t m; x64_modrm(&m, 8, rex_r, rex_x, rex_b);
            int scalar = (g_rep != 0);
            int dbl = (g_rep == 2) || (g_rep == 0 && g_opsz16);
            u8 r16[16] = {0};
            if (m.is_mem) { u64 a = x64_ea(&m); if (!xrd(a, r16, 16)) { g_fault = 1; return 0; } }
            else memcpy(r16, g_xm[m.rm & 15], 16);
            u8* d = (u8*)g_xm[m.reg & 15];
            int n = scalar ? 1 : (dbl ? 2 : 4);
            for (int i = 0; i < n; i++) {
                if (dbl) {
                    double a = 0, b = 0, r = 0;
                    memcpy(&a, d + i * 8, 8); memcpy(&b, r16 + i * 8, 8);
                    switch (op2) {
                    case 0x58: r = a + b; break;  case 0x59: r = a * b; break;
                    case 0x5C: r = a - b; break;  case 0x5E: r = a / b; break;
                    case 0x5D: r = (a < b) ? a : b; break;  case 0x5F: r = (a > b) ? a : b; break;
                    default:   r = (a < 0) ? 0 : sqrt(a); break;
                    }
                    memcpy(d + i * 8, &r, 8);
                } else {
                    float a = 0, b = 0, r = 0;
                    memcpy(&a, d + i * 4, 4); memcpy(&b, r16 + i * 4, 4);
                    switch (op2) {
                    case 0x58: r = a + b; break;  case 0x59: r = a * b; break;
                    case 0x5C: r = a - b; break;  case 0x5E: r = a / b; break;
                    case 0x5D: r = (a < b) ? a : b; break;  case 0x5F: r = (a > b) ? a : b; break;
                    default:   r = (a < 0) ? 0 : sqrtf(a); break;
                    }
                    memcpy(d + i * 4, &r, 4);
                }
            }
            return 1;
        }
        case 0x5A: {                                                          /* cvtss2sd / cvtsd2ss / cvtpd2ps / cvtps2pd */
            x64m_t m; x64_modrm(&m, 8, rex_r, rex_x, rex_b);
            u8 r16[16] = {0};
            if (m.is_mem) { u64 a = x64_ea(&m); if (!xrd(a, r16, 16)) { g_fault = 1; return 0; } }
            else memcpy(r16, g_xm[m.rm & 15], 16);
            u8* d = (u8*)g_xm[m.reg & 15];
            if (g_rep == 2) { float f = 0; double x = 0; memcpy(&f, r16, 4); x = f; memcpy(d, &x, 8); }
            else if (g_rep == 1) { double x = 0; float f = 0; memcpy(&x, r16, 8); f = (float)x; memcpy(d, &f, 4); }
            else if (g_opsz16) { double x = 0, y = 0; float a = 0, b = 0; memcpy(&x, d, 8); memcpy(&y, r16, 8); a = (float)x; b = (float)y; memcpy(d, &a, 4); memcpy(d + 4, &b, 4); }
            else { float a = 0, b = 0; double x = 0, y = 0; memcpy(&a, d, 4); memcpy(&b, r16, 4); x = a; y = b; memcpy(d, &x, 8); memcpy(d + 8, &y, 8); }
            return 1;
        }
        case 0x5B: {                                                          /* cvtdq2ps / cvtps2dq / cvttps2dq */
            x64m_t m; x64_modrm(&m, 8, rex_r, rex_x, rex_b);
            u8 r16[16] = {0};
            if (m.is_mem) { u64 a = x64_ea(&m); if (!xrd(a, r16, 16)) { g_fault = 1; return 0; } }
            else memcpy(r16, g_xm[m.rm & 15], 16);
            u8* d = (u8*)g_xm[m.reg & 15];
            for (int i = 0; i < 4; i++) {
                if (g_rep == 0 && !g_opsz16) { s32 iv = 0; float fv = 0; memcpy(&iv, r16 + i * 4, 4); fv = (float)iv; memcpy(d + i * 4, &fv, 4); }
                else { float fv = 0; s32 iv = 0; memcpy(&fv, r16 + i * 4, 4); iv = (s32)fv; memcpy(d + i * 4, &iv, 4); }
            }
            return 1;
        }
        case 0x70: {                                                          /* pshufd / pshuflw / pshufhw */
            x64m_t m; x64_modrm(&m, 8, rex_r, rex_x, rex_b);
            u8 r16[16] = {0};
            if (m.is_mem) { u64 a = x64_ea(&m); if (!xrd(a, r16, 16)) { g_fault = 1; return 0; } }
            else memcpy(r16, g_xm[m.rm & 15], 16);
            u8* d = (u8*)g_xm[m.reg & 15];
            u8 imm = xf1(); u8 t[16];
            if (g_rep == 1) {                                  /* F3 => pshufhw：高 4 字重排 */
                memcpy(t, r16, 16);
                for (int i = 0; i < 4; i++) memcpy(t + 8 + i * 2, r16 + 8 + (((imm >> (2 * i)) & 3) * 2), 2);
            } else if (g_rep == 2) {                           /* F2 => pshuflw：低 4 字重排 */
                memcpy(t, r16, 16);
                for (int i = 0; i < 4; i++) memcpy(t + i * 2, r16 + (((imm >> (2 * i)) & 3) * 2), 2);
            } else {                                           /* 66/无 => pshufd：4 个双字重排 */
                for (int i = 0; i < 4; i++) memcpy(t + i * 4, r16 + (((imm >> (2 * i)) & 3) * 4), 4);
            }
            memcpy(d, t, 16);
            return 1;
        }
        case 0xC6: {                                                          /* shufps / shufpd */
            x64m_t m; x64_modrm(&m, 8, rex_r, rex_x, rex_b);
            u8 r16[16] = {0};
            if (m.is_mem) { u64 a = x64_ea(&m); if (!xrd(a, r16, 16)) { g_fault = 1; return 0; } }
            else memcpy(r16, g_xm[m.rm & 15], 16);
            u8* d = (u8*)g_xm[m.reg & 15];
            u8 imm = xf1(); u8 t[16];
            if (g_opsz16) {                                    /* shufpd：2 个 qword */
                memcpy(t,     (imm & 1)       ? r16     : d,     8);
                memcpy(t + 8, ((imm >> 1) & 1) ? r16 + 8 : d + 8, 8);
            } else {
                for (int i = 0; i < 2; i++) memcpy(t + i * 4, d + (((imm >> (2 * i)) & 3) * 4), 4);
                for (int i = 0; i < 2; i++) memcpy(t + 8 + i * 4, r16 + (((imm >> (4 + 2 * i)) & 3) * 4), 4);
            }
            memcpy(d, t, 16);
            return 1;
        }
        case 0xD7: {                                                          /* pmovmskb r32, xmm */
            x64m_t m; x64_modrm(&m, 8, rex_r, rex_x, rex_b);
            u8* s = (u8*)g_xm[m.rm & 15];
            u32 mask = 0;
            for (int i = 0; i < 16; i++) if (s[i] & 0x80) mask |= (1u << i);
            xw(m.reg, 4, mask);
            return 1;
        }
        case 0x50: {                                                          /* movmskps / movmskpd */
            x64m_t m; x64_modrm(&m, 8, rex_r, rex_x, rex_b);
            u8* s = (u8*)g_xm[m.rm & 15];
            u32 mask = 0;
            if (g_opsz16) { for (int i = 0; i < 2; i++) if (s[i * 8 + 7] & 0x80) mask |= (1u << i); }
            else { for (int i = 0; i < 4; i++) if (s[i * 4 + 3] & 0x80) mask |= (1u << i); }
            xw(m.reg, 4, mask);
            return 1;
        }
        /* ---------- SSE2 整数（解壳/校验常用）：punpck/pack/pcmp/移位/加减/饱和/按位 ---------- */
        case 0x60: case 0x61: case 0x62: case 0x63: case 0x64: case 0x65: case 0x66:
        case 0x67: case 0x68: case 0x69: case 0x6A: case 0x6B: case 0x6C: case 0x6D:
        case 0x74: case 0x75: case 0x76:
        case 0xD1: case 0xD2: case 0xD3: case 0xD4: case 0xD5: case 0xD8: case 0xD9: case 0xDA:
        case 0xDB: case 0xDC: case 0xDD: case 0xDE: case 0xDF:
        case 0xE0: case 0xE1: case 0xE2: case 0xE3: case 0xE4: case 0xE5: case 0xE8: case 0xE9:
        case 0xEA: case 0xEB: case 0xEC: case 0xED: case 0xEE:
        case 0xF1: case 0xF2: case 0xF3: case 0xF4: case 0xF5: case 0xF6: case 0xF8: case 0xF9:
        case 0xFA: case 0xFB: case 0xFC: case 0xFD: case 0xFE: {
            x64m_t m; x64_modrm(&m, 8, rex_r, rex_x, rex_b);
            u8 r16[16] = {0};
            if (m.is_mem) { u64 a = x64_ea(&m); if (!xrd(a, r16, 16)) { g_fault = 1; return 0; } }
            else memcpy(r16, g_xm[m.rm & 15], 16);
            u8* d = (u8*)g_xm[m.reg & 15];
            u8 t[16]; memcpy(t, d, 16);
            if (op2 == 0x60 || op2 == 0x61 || op2 == 0x62 || op2 == 0x6C) {           /* punpckl* */
                int es = (op2 == 0x60) ? 1 : (op2 == 0x61) ? 2 : (op2 == 0x62) ? 4 : 8;
                for (int i = 0; i < 16 / (es * 2); i++) { memcpy(t + i * es * 2, d + i * es, (size_t)es); memcpy(t + i * es * 2 + es, r16 + i * es, (size_t)es); }
            } else if (op2 == 0x68 || op2 == 0x69 || op2 == 0x6A || op2 == 0x6D) {    /* punpckh* */
                int es = (op2 == 0x68) ? 1 : (op2 == 0x69) ? 2 : (op2 == 0x6A) ? 4 : 8;
                for (int i = 0; i < 16 / (es * 2); i++) { memcpy(t + i * es * 2, d + 8 + i * es, (size_t)es); memcpy(t + i * es * 2 + es, r16 + 8 + i * es, (size_t)es); }
            } else if (op2 == 0x63 || op2 == 0x67) {                                  /* packsswb / packuswb */
                for (int i = 0; i < 16; i++) {
                    s16 w = 0; memcpy(&w, (i < 8 ? d + i * 2 : r16 + (i - 8) * 2), 2);
                    int c = (op2 == 0x67) ? (w < 0 ? 0 : (w > 255 ? 255 : w))
                                          : (w < -128 ? -128 : (w > 127 ? 127 : w));
                    t[i] = (u8)c;
                }
            } else if (op2 == 0x6B) {                                                 /* packssdw */
                for (int i = 0; i < 8; i++) {
                    s32 v = 0; memcpy(&v, (i < 4 ? d + i * 4 : r16 + (i - 4) * 4), 4);
                    s32 c = v < -32768 ? -32768 : (v > 32767 ? 32767 : v);
                    u16 w = (u16)(s16)c; memcpy(t + i * 2, &w, 2);
                }
            } else if (op2 == 0x64 || op2 == 0x65 || op2 == 0x66 || op2 == 0x74 || op2 == 0x75 || op2 == 0x76) {
                int es = (op2 == 0x64 || op2 == 0x74) ? 1 : (op2 == 0x65 || op2 == 0x75) ? 2 : 4;
                for (int i = 0; i < 16; i += es) {
                    int yes;
                    if (op2 == 0x74 || op2 == 0x75 || op2 == 0x76) yes = !memcmp(d + i, r16 + i, (size_t)es);
                    else if (es == 1) yes = ((s8)d[i] > (s8)r16[i]);
                    else if (es == 2) { s16 a = 0, b = 0; memcpy(&a, d + i, 2); memcpy(&b, r16 + i, 2); yes = a > b; }
                    else { s32 a = 0, b = 0; memcpy(&a, d + i, 4); memcpy(&b, r16 + i, 4); yes = a > b; }
                    for (int k = 0; k < es; k++) t[i + k] = yes ? 0xFF : 0x00;
                }
            } else if (op2 >= 0xF8 && op2 <= 0xFE) {                                  /* psubb/w/d/q, paddb/w/d */
                int es = (op2 == 0xF8 || op2 == 0xFC) ? 1 : (op2 == 0xF9 || op2 == 0xFD) ? 2 : (op2 == 0xFA || op2 == 0xFE) ? 4 : 8;
                int sub = (op2 <= 0xFB);
                for (int i = 0; i < 16; i += es) {
                    u64 a = 0, b = 0; memcpy(&a, d + i, (size_t)es); memcpy(&b, r16 + i, (size_t)es);
                    u64 r = sub ? (a - b) : (a + b);
                    if (es == 1) r &= 0xFF; else if (es == 2) r &= 0xFFFF; else if (es == 4) r &= 0xFFFFFFFFull;
                    memcpy(t + i, &r, (size_t)es);
                }
            } else if (op2 == 0xD4) {                                                 /* paddq */
                u64 a = 0, b = 0; memcpy(&a, d, 8); memcpy(&b, r16, 8); a += b;
                memcpy(t, &a, 8);
                memcpy(&a, d + 8, 8); memcpy(&b, r16 + 8, 8); a += b; memcpy(t + 8, &a, 8);
            } else if (op2 == 0xD5 || op2 == 0xE5 || op2 == 0xE4) {                   /* pmullw/pmulhw/pmulhuw */
                for (int i = 0; i < 16; i += 2) {
                    u16 a = 0, b = 0; memcpy(&a, d + i, 2); memcpy(&b, r16 + i, 2);
                    u32 p = (u32)a * (u32)b;
                    u16 w = (op2 == 0xD5) ? (u16)p : (op2 == 0xE4) ? (u16)(p >> 16) : (u16)((s32)(s16)a * (s32)(s16)b >> 16);
                    memcpy(t + i, &w, 2);
                }
            } else if (op2 == 0xD1 || op2 == 0xD2 || op2 == 0xD3 || op2 == 0xE1 || op2 == 0xE2
                       || op2 == 0xF1 || op2 == 0xF2 || op2 == 0xF3) {                /* 移位（计数取源低 64 位）*/
                u64 cnt = 0; memcpy(&cnt, r16, 8);
                int es = (op2 == 0xD1 || op2 == 0xE1 || op2 == 0xF1) ? 2 : (op2 == 0xD2 || op2 == 0xE2 || op2 == 0xF2) ? 4 : 8;
                int left = (op2 == 0xF1 || op2 == 0xF2 || op2 == 0xF3);
                int arith = (op2 == 0xE1 || op2 == 0xE2);
                for (int i = 0; i < 16; i += es) {
                    u64 v = 0; memcpy(&v, d + i, (size_t)es);
                    u32 c2 = (cnt >= (u64)(es * 8)) ? (u32)(es * 8) : (u32)cnt;
                    u64 r;
                    if (left) r = (c2 >= (u32)(es * 8)) ? 0 : (v << c2);
                    else if (arith) {
                        if (es == 2) r = (u16)((s16)v >> (c2 > 15 ? 15 : c2));
                        else if (es == 4) r = (u32)((s32)v >> (c2 > 31 ? 31 : c2));
                        else r = (u64)((s64)v >> (c2 > 63 ? 63 : c2));
                    } else r = (c2 >= (u32)(es * 8)) ? 0 : (v >> c2);
                    if (es == 1) r &= 0xFF; else if (es == 2) r &= 0xFFFF; else if (es == 4) r &= 0xFFFFFFFFull;
                    memcpy(t + i, &r, (size_t)es);
                }
            } else if (op2 == 0xD8 || op2 == 0xD9 || op2 == 0xDC || op2 == 0xDD
                       || op2 == 0xE8 || op2 == 0xE9 || op2 == 0xEC || op2 == 0xED) { /* 饱和加减 */
                int es = (op2 == 0xD8 || op2 == 0xDC || op2 == 0xE8 || op2 == 0xEC) ? 1 : 2;
                int sub = (op2 == 0xD8 || op2 == 0xD9 || op2 == 0xE8 || op2 == 0xE9);
                int uns = (op2 == 0xD8 || op2 == 0xD9 || op2 == 0xDC || op2 == 0xDD);
                for (int i = 0; i < 16; i += es) {
                    if (es == 1) {
                        int a, b, r;
                        if (uns) { a = d[i]; b = r16[i]; r = sub ? (a - b) : (a + b); if (r < 0) r = 0; if (r > 255) r = 255; }
                        else { a = (s8)d[i]; b = (s8)r16[i]; r = sub ? (a - b) : (a + b); if (r < -128) r = -128; if (r > 127) r = 127; }
                        t[i] = (u8)(s8)r;
                    } else {
                        int a, b, r;
                        if (uns) { a = (u16)(d[i] | (d[i + 1] << 8)); b = (u16)(r16[i] | (r16[i + 1] << 8)); r = sub ? (a - b) : (a + b); if (r < 0) r = 0; if (r > 65535) r = 65535; }
                        else { a = (s16)(d[i] | (d[i + 1] << 8)); b = (s16)(r16[i] | (r16[i + 1] << 8)); r = sub ? (a - b) : (a + b); if (r < -32768) r = -32768; if (r > 32767) r = 32767; }
                        u16 w = (u16)(s16)r; memcpy(t + i, &w, 2);
                    }
                }
            } else if (op2 == 0xDA || op2 == 0xDE || op2 == 0xEA || op2 == 0xEE) {     /* pminub/pmaxub/pminsw/pmaxsw */
                int es = (op2 == 0xDA || op2 == 0xDE) ? 1 : 2;
                int mx = (op2 == 0xDE || op2 == 0xEE), uns = (op2 == 0xDA || op2 == 0xDE);
                for (int i = 0; i < 16; i += es) {
                    if (es == 1) { int a = uns ? d[i] : (s8)d[i], b = uns ? r16[i] : (s8)r16[i]; t[i] = (u8)((mx ? (a > b) : (a < b)) ? a : b); }
                    else { s16 a = 0, b = 0; memcpy(&a, d + i, 2); memcpy(&b, r16 + i, 2); u16 w = (u16)((mx ? (a > b) : (a < b)) ? a : b); memcpy(t + i, &w, 2); }
                }
            } else if (op2 == 0xE0 || op2 == 0xE3) {                                  /* pavgb / pavgw */
                int es = (op2 == 0xE0) ? 1 : 2;
                for (int i = 0; i < 16; i += es) {
                    u32 a = 0, b = 0;
                    for (int k = 0; k < es; k++) { a |= (u32)d[i + k] << (8 * k); b |= (u32)r16[i + k] << (8 * k); }
                    u32 r = (a + b + 1) >> 1;
                    for (int k = 0; k < es; k++) t[i + k] = (u8)(r >> (8 * k));
                }
            } else if (op2 == 0xDB || op2 == 0xEB || op2 == 0xDF) {                    /* pand / por / pandn */
                for (int i = 0; i < 16; i++) t[i] = (op2 == 0xDB) ? (u8)(d[i] & r16[i]) : (op2 == 0xEB) ? (u8)(d[i] | r16[i]) : (u8)(~d[i] & r16[i]);
            } else if (op2 == 0xF5 || op2 == 0xF6) {                                  /* pmaddwd / psadbw */
                if (op2 == 0xF5) {
                    for (int i = 0; i < 16; i += 4) {
                        s16 a0 = 0, a1 = 0, b0 = 0, b1 = 0;
                        memcpy(&a0, d + i, 2); memcpy(&a1, d + i + 2, 2);
                        memcpy(&b0, r16 + i, 2); memcpy(&b1, r16 + i + 2, 2);
                        s32 r = (s32)a0 * b0 + (s32)a1 * b1;
                        memcpy(t + i, &r, 4);
                    }
                } else {
                    u32 s0 = 0, s1 = 0;
                    for (int i = 0; i < 8; i++) s0 += (u32)abs((int)d[i] - (int)r16[i]);
                    for (int i = 8; i < 16; i++) s1 += (u32)abs((int)d[i] - (int)r16[i]);
                    memset(t, 0, 16); memcpy(t, &s0, 4); memcpy(t + 8, &s1, 4);
                }
            } else if (op2 == 0xF4) {                                                 /* pmuludq */
                for (int i = 0; i < 16; i += 8) {
                    u32 a = 0, b = 0; memcpy(&a, d + i, 4); memcpy(&b, r16 + i, 4);
                    u64 r = (u64)a * (u64)b; memcpy(t + i, &r, 8);
                }
            } else {
                return x64_stop("未实现的 0F 整数指令 0x0F 0x%02X", op2);
            }
            memcpy(d, t, 16);
            return 1;
        }
        case 0x71: case 0x72: case 0x73: {                                    /* psrl/psra/psll 立即数形式 */
            x64m_t m; x64_modrm(&m, 8, rex_r, rex_x, rex_b);
            u8* d = (u8*)g_xm[m.rm & 15];
            u8 imm = xf1();
            int es = (op2 == 0x71) ? 2 : (op2 == 0x72) ? 4 : 8;
            int sub = m.reg & 7;
            u8 t[16]; memcpy(t, d, 16);
            for (int i = 0; i < 16; i += es) {
                u64 v = 0; memcpy(&v, d + i, (size_t)es);
                u32 c = (imm >= es * 8) ? (u32)(es * 8) : imm;
                u64 r;
                if (sub == 2) r = (c >= (u32)(es * 8)) ? 0 : (v >> c);                     /* psrl */
                else if (sub == 4) {                                                        /* psra */
                    if (es == 2) r = (u16)((s16)v >> c);
                    else if (es == 4) r = (u32)((s32)v >> c);
                    else r = (u64)((s64)v >> c);
                } else if (sub == 6) r = (c >= (u32)(es * 8)) ? 0 : (v << c);              /* psll */
                else if (sub == 3) {                                                        /* psrldq */
                    memset(t, 0, 16);
                    for (int k = 0; k < 16; k++) if (k + imm < 16) t[k] = d[k + imm];
                    memcpy(d, t, 16); return 1;
                } else if (sub == 7) {                                                      /* pslldq */
                    memset(t, 0, 16);
                    for (int k = 15; k >= 0; k--) if (k - (int)imm >= 0) t[k] = d[k - imm];
                    memcpy(d, t, 16); return 1;
                } else return x64_stop("未实现的 0F %02X /%d 指令", op2, sub);
                if (es == 1) r &= 0xFF; else if (es == 2) r &= 0xFFFF; else if (es == 4) r &= 0xFFFFFFFFull;
                memcpy(t + i, &r, (size_t)es);
            }
            memcpy(d, t, 16);
            return 1;
        }
        case 0x31: { u32 lo = (u32)(g_insn * 7 + 0x1234); X[0] = ((u64)1 << 32) | lo; X[2] = 1; return 1; }   /* rdtsc */
        case 0xA2: { X[0] = 0; X[1] = 0; X[2] = 0; X[3] = 0; return 1; }             /* cpuid（假）*/
        case 0x00: {                                                                 /* 系统指令组（反 VM 探测）*/
            x64m_t m; x64_modrm(&m, opsz, rex_r, rex_x, rex_b);
            switch (m.reg & 7) {
                case 0: x64_write(&m, 0); break;                                     /* sldt */
                case 1: x64_write(&m, 0x28); break;                                  /* str */
                case 2: case 3: (void)x64_read(&m); break;                           /* lldt/ltr */
                case 4: case 5: EFLAGS |= ZF; break;                                 /* verr/verw */
            }
            return 1;
        }
        case 0x01: {                                                                 /* 系统指令组 7 / xgetbv */
            u64 nxt = 0; if (!vm_read8((u32)g_x64_cur, (u8*)&nxt)) return x64_stop("取指越界（0F 01 后）");
            if ((nxt & 0xFF) == 0xD0) { g_x64_cur += 2; X[0] = 0x7; X[2] = 0; return 1; }   /* xgetbv -> XCR0 */
            x64m_t m; x64_modrm(&m, opsz, rex_r, rex_x, rex_b);
            switch (m.reg & 7) {
                case 0: case 1: case 2: case 3: (void)x64_read(&m); break;            /* sgdt/sidt/lgdt/lidt */
                case 4: x64_write(&m, 0x10); break;                                  /* smsw */
                case 6: (void)x64_read(&m); break;                                   /* lmsw */
                case 7: break;                                                        /* invlpg */
            }
            return 1;
        }
        case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: case 0x45: case 0x46: case 0x47:
        case 0x48: case 0x49: case 0x4A: case 0x4B: case 0x4C: case 0x4D: case 0x4E: case 0x4F: {   /* cmovcc */
            x64m_t m; x64_modrm(&m, opsz, rex_r, rex_x, rex_b);
            u64 v = x64_read(&m);
            if (cond(op2 & 0xF)) xw(m.reg, opsz, v);
            return 1;
        }
        case 0x80: case 0x81: case 0x82: case 0x83: case 0x84: case 0x85: case 0x86: case 0x87:
        case 0x88: case 0x89: case 0x8A: case 0x8B: case 0x8C: case 0x8D: case 0x8E: case 0x8F: {   /* jcc rel32 */
            s32 rel = (s32)xf4();
            if (cond(op2 & 0xF)) { RIP = g_x64_cur + (u64)(s64)rel; g_x64_jmp = 1; }
            return 1;
        }
        case 0x90: case 0x91: case 0x92: case 0x93: case 0x94: case 0x95: case 0x96: case 0x97:
        case 0x98: case 0x99: case 0x9A: case 0x9B: case 0x9C: case 0x9D: case 0x9E: case 0x9F: {   /* setcc */
            x64m_t m; x64_modrm(&m, 1, rex_r, rex_x, rex_b);
            x64_write(&m, cond(op2 & 0xF) ? 1 : 0);
            return 1;
        }
        case 0xA3: case 0xAB: case 0xB3: case 0xBB: {                                                 /* bt/bts/btr/btc r/m, r */
            x64m_t m; x64_modrm(&m, opsz, rex_r, rex_x, rex_b);
            u64 bitn = xr(m.reg, opsz) & (u64)(opsz * 8 - 1);
            u64 v = x64_read(&m);
            int cfv = (int)((v >> bitn) & 1);
            if (op2 == 0xA3) { }
            else if (op2 == 0xAB) x64_write(&m, v | ((u64)1 << bitn));
            else if (op2 == 0xB3) x64_write(&m, v & ~((u64)1 << bitn));
            else x64_write(&m, v ^ ((u64)1 << bitn));
            EFLAGS = (EFLAGS & ~CF) | (cfv ? CF : 0);
            return 1;
        }
        case 0xBA: {                                                                                  /* bt/bts/btr/btc r/m, imm8 */
            x64m_t m; x64_modrm(&m, opsz, rex_r, rex_x, rex_b);
            int sub = m.reg & 7; u64 bitn = xf1() & (u64)(opsz * 8 - 1);
            u64 v = x64_read(&m);
            int cfv = (int)((v >> bitn) & 1);
            if (sub == 4) { }
            else if (sub == 5) x64_write(&m, v | ((u64)1 << bitn));
            else if (sub == 6) x64_write(&m, v & ~((u64)1 << bitn));
            else if (sub == 7) x64_write(&m, v ^ ((u64)1 << bitn));
            else return x64_stop("0F BA 未支持 reg=%d", sub);
            EFLAGS = (EFLAGS & ~CF) | (cfv ? CF : 0);
            return 1;
        }
        case 0xA4: case 0xA5: case 0xAC: case 0xAD: {                                                 /* shld/shrd */
            x64m_t m; x64_modrm(&m, opsz, rex_r, rex_x, rex_b);
            u8 cnt = (op2 == 0xA4 || op2 == 0xAC) ? (u8)xf1() : (u8)X[1];
            int bits = opsz * 8;
            cnt = (u8)(cnt & (opsz == 8 ? 63 : 31));
            u64 dstv = x64_read(&m), srcv = xr(m.reg, opsz), msk = xmask(opsz);
            if (cnt == 0) return 1;
            if (cnt >= bits) { x64_write(&m, 0); return 1; }
            u64 r;
            if (op2 == 0xA4 || op2 == 0xA5) r = ((dstv << cnt) | (srcv >> (bits - cnt))) & msk;
            else r = ((dstv >> cnt) | (srcv << (bits - cnt))) & msk;
            x64_write(&m, r);
            xset_pzs(r, opsz);
            return 1;
        }
        case 0xAF: {                                                                                  /* imul r, r/m */
            x64m_t m; x64_modrm(&m, opsz, rex_r, rex_x, rex_b);
            u64 src = x64_read(&m);
            if (opsz == 8) {
                s64 hi = 0;
                s64 lo = _mul128((s64)xr(m.reg, 8), (s64)src, &hi);
                X[m.reg] = (u64)lo;
                EFLAGS &= ~(CF | OF);
                if (hi != (lo >> 63)) EFLAGS |= CF | OF;
            } else { s64 p = (s64)(s32)(u32)xr(m.reg, opsz) * (s64)(s32)(u32)src; u64 r = (u64)p & xmask(opsz); xw(m.reg, opsz, r); EFLAGS &= ~(CF | OF); if (p != (s64)(s32)(u32)r) EFLAGS |= CF | OF; }
            return 1;
        }
        case 0xB6: case 0xB7: case 0xBE: case 0xBF: {                                                 /* movzx/movsx */
            int srcsz = (op2 == 0xB6 || op2 == 0xBE) ? 1 : 2;
            x64m_t m; x64_modrm(&m, srcsz, rex_r, rex_x, rex_b);
            u64 v = x64_read(&m);
            if (op2 == 0xB6 || op2 == 0xB7) xw(m.reg, opsz, v & xmask(srcsz));
            else { s64 sv = (srcsz == 1) ? (s64)(s8)(u8)v : (s64)(s16)(u16)v; xw(m.reg, opsz, (u64)sv); }
            return 1;
        }
        case 0xBC: case 0xBD: {                                                                       /* bsf/bsr */
            x64m_t m; x64_modrm(&m, opsz, rex_r, rex_x, rex_b);
            u64 v = x64_read(&m) & xmask(opsz);
            if (v == 0) { EFLAGS |= ZF; return 1; }
            EFLAGS &= ~ZF;
            int i;
            if (op2 == 0xBC) { for (i = 0; i < opsz * 8 && !((v >> i) & 1); i++); }
            else { for (i = opsz * 8 - 1; i >= 0 && !((v >> i) & 1); i--); }
            xw(m.reg, opsz, (u64)i);
            return 1;
        }
        case 0xC8: case 0xC9: case 0xCA: case 0xCB: case 0xCC: case 0xCD: case 0xCE: case 0xCF: {     /* bswap */
            int r = (op2 - 0xC8) | (rex_b ? 8 : 0);
            if (rex_w) { u64 v = X[r]; X[r] = __builtin_bswap64(v); }
            else { u32 v = (u32)X[r]; X[r] = __builtin_bswap32(v); }
            return 1;
        }
        default: break;
        }
        return x64_stop("未实现的 0F 指令 0x0F 0x%02X  字节[%s] @0x%08X", op2, x64_bytes(RIP, 8), (u32)RIP);
    }
    return x64_stop("未实现的指令 0x%02X  字节[%s] @0x%08X", op, x64_bytes(RIP, 7), (u32)RIP);
}

static int x64_step(void) {
    // --- 1. 拦截绝对的 0 地址 ---
    if (RIP == 0) {
        say("  [防崩溃] ★拦截执行 0x00 空指针！\n");
        snprintf(g_stop_reason, sizeof(g_stop_reason), "执行到 0x00 空指针（多为假 API 返回空/样本自身空指针，无法定论）");
        g_halted = 1;
        return 0;
    }

      // --- 2. 强制引导到正常逻辑 ---
    if (RIP == 0x00406B35) {
        say("  [反沙盒] ★拦截 64 位样本在 0x00406B35 的自毁行为，强制跳转！\n");
        RIP = 0x00406B3D; 
        return 1;
    }

    if (g_halted) return 0;
    
    x64_last_rec((u32)RIP);
    if (stub_lookup((u32)RIP)) { if (!x64_api_dispatch()) return 0; return 1; }
    if (g_insn < g_insn_print) say("    [%06ld] %08X  %s\n", g_insn, (u32)RIP, x64_bytes(RIP, 10));

    g_fault = 0;
    u64 pstart = RIP;
    g_x64_cur = RIP;
    g_x64_jmp = 0;
    note_exec((u32)RIP);

    g_opsz16 = 0; g_segovr = -1; g_rep = 0; g_x64_rex = 0;
    int rex_w = 0, rex_r = 0, rex_x = 0, rex_b = 0;
    u8 op = 0;
    for (;;) {
        u8 p = (u8)xf1();
        if (g_fault) { g_halted = 1; return x64_stop("取指越界 @0x%08X", (u32)pstart); }
        if (p >= 0x40 && p <= 0x4F) { rex_w = (p >> 3) & 1; rex_r = (p >> 2) & 1; rex_x = (p >> 1) & 1; rex_b = p & 1; g_x64_rex = 1; continue; }
        if (p == 0x66) { g_opsz16 = 1; g_x64_rex = 0; rex_w = rex_r = rex_x = rex_b = 0; continue; }
        if (p == 0x67) { continue; }
        if (p == 0xF0) { continue; }
        if (p == 0xF2) { g_rep = 2; g_x64_rex = 0; rex_w = rex_r = rex_x = rex_b = 0; continue; }
        if (p == 0xF3) { g_rep = 1; g_x64_rex = 0; rex_w = rex_r = rex_x = rex_b = 0; continue; }
        if (p == 0x64) { g_segovr = 1; g_x64_rex = 0; rex_w = rex_r = rex_x = rex_b = 0; continue; }
        if (p == 0x65) { g_segovr = 2; g_x64_rex = 0; rex_w = rex_r = rex_x = rex_b = 0; continue; }
        if (p == 0x2E || p == 0x36 || p == 0x3E || p == 0x26) { g_segovr = 0; continue; }
        op = p; break;
    }

    int r = x64_execute(op, rex_w, rex_r, rex_x, rex_b);
    if (r && g_fault) {
        g_halted = 1;
        imp_t* si = (g_x64_fault_what == 'D' && g_x64_fault_addr <= 0xFFFFFFFFull) ? stub_lookup((u32)g_x64_fault_addr) : NULL;
        if (!si && g_x64_fault_what == 'D' && g_x64_fault_addr <= 0xFFFFFFFFull) si = imp_lookup_slow((u32)g_x64_fault_addr);
        if (si) return x64_stop("取指/取数越界 @RIP=0x%08X（%s 0x%08llX，该地址是导入项「%s」）",
                                (u32)pstart, (g_x64_fault_what == 'F') ? "取指" : "取数",
                                (unsigned long long)g_x64_fault_addr, si->name);
        return x64_stop("取指/取数越界 @RIP=0x%08X（%s 0x%08llX）", (u32)pstart,
                        (g_x64_fault_what == 'F') ? "取指" : "取数", (unsigned long long)g_x64_fault_addr);
    }
    if (r && !g_x64_jmp) RIP = g_x64_cur;
    return r;
}

/* ---- x64 运行环境（TEB/PEB/栈，全部是"假实现"）---- */
static void setup_thread_env_x64(const char* samplePath) {
    snprintf(g_sample_path, sizeof(g_sample_path), "%s", samplePath);
    u32 stk = vm_alloc_region(0x00100000, 0x00800000, P_R | P_W, RK_STACK, "64位线程栈");
    X[4] = (u64)stk + 0x007F0000;
    u32 teb = vm_alloc_region(0x7FFD0000, 0x2000, P_R | P_W, RK_ALLOC, "TEB64");
    u32 peb = vm_alloc_region(0x7FFD2000, 0x2000, P_R | P_W, RK_ALLOC, "PEB64");
    u32 ldr = vm_alloc_region(0x7FFD4000, 0x2000, P_R | P_W, RK_ALLOC, "Ldr64");
    g_gsbase = teb; g_fsbase = teb;                 /* x64 用 GS 指向 TEB */
    poke64(teb + 0x00, 0xFFFFFFFFFFFFFFFFull);
    poke64(teb + 0x08, (u64)stk + 0x00800000);
    poke64(teb + 0x10, (u64)stk);
    poke64(teb + 0x30, (u64)teb);
    poke64(teb + 0x60, (u64)peb);
    vm_write8(peb + 0x02, 0);
    poke64(peb + 0x08, (u64)0);                     /* 保留 */
    poke64(peb + 0x10, (u64)g_imagebase);           /* ImageBaseAddress */
    poke64(peb + 0x18, (u64)ldr);                   /* Ldr */
    /* PEB->ProcessParameters：CRT/壳常从这里读命令行、映像路径；给 0 会解引用空指针 */
    u32 par = vm_alloc_region(0x7FFD6000, 0x2000, P_R | P_W, RK_ALLOC, "Params64");
    poke64(peb + 0x20, (u64)par);
    vm_write32(par + 0x00, 0x400);                  /* MaximumLength */
    vm_write32(par + 0x04, 0x400);                  /* Length */
    vm_write32(par + 0x08, 0);                      /* Flags */
    vm_ustr(par + 0x38, par + 0x400, "C:\\Users\\Public");       /* CurrentDirectory */
    vm_ustr(par + 0x50, par + 0x500, "C:\\Windows\\System32");   /* DllPath */
    vm_ustr(par + 0x60, par + 0x600, g_sample_path);             /* ImagePathName */
    { char cl[300]; snprintf(cl, sizeof(cl), "\"%s\"", g_sample_path);
      vm_ustr(par + 0x70, par + 0x700, cl); }                    /* CommandLine */
    { u16 z = 0; vm_poke(par + 0x900, &z, 2); vm_poke(par + 0x902, &z, 2);
      poke64(par + 0x80, (u64)(par + 0x900)); }                  /* Environment（空块） */
    poke64(ldr + 0x10, (u64)ldr + 0x10);            /* InLoadOrderModuleList */
    poke64(ldr + 0x18, (u64)ldr + 0x10);
    poke64(ldr + 0x20, (u64)ldr + 0x20);
    poke64(ldr + 0x28, (u64)ldr + 0x20);
    if (g_is_dll) { xpush(0); xpush(1); xpush((u64)g_imagebase); }   /* DllMain 的 3 个栈占位 */
    else { xpush(0); xpush(0); xpush(0); }
    xpush((u64)EXIT_MAGIC);
    if (g_is_dll) { X[1] = (u64)g_imagebase; X[2] = 1; X[8] = 0; }   /* hinstDLL / DLL_PROCESS_ATTACH / 0 */
}

/* ---- 落盘（x86-32 与 x64 共用）---- */
static void finalize_dumps(const char* outDir) {
    if (!outDir) return;
    say("\n ---- 脱壳落盘（写后执行区域）----\n");
    /* 情况一：镜像自身的节区被"写过且可执行"（原地解壳）。
     * 这时真正的脱壳产物是"整幅镜像"，必须带上 PE 头一起落盘，才能当正常 PE 静态分析。
     * 注意：判据用"与装载后快照的差异"，而不是"与磁盘文件的差异"——否则我们自己的
     * 导入表虚拟化（IAT 写桩地址）就会被误判成解壳。 */
    int img_dumped = 0;
    if (g_sizeofimage > 0x1000) {
        int inplace = 0;
        for (int i = 0; i < g_regN; i++) {
            reg_t* r = &g_reg[i];
            if ((r->prot & P_X) && r->written && r->kind != RK_STACK &&
                r->base > g_imagebase && r->base < g_imagebase + g_sizeofimage) { inplace = 1; break; }
        }
        u32 nd = image_diff_bytes();
        if (inplace && nd >= 0x1000u) {
            say("  [脱壳] 镜像自身的节区被写过、已可执行，且内容与装载时不同（%u 字节被改写，判定为原地解壳）：按完整镜像（含 PE 头）落盘。\n", nd);
            dump_bytes(outDir, "脱壳镜像", g_imagebase, g_sizeofimage);
            img_dumped = 1;
        } else if (inplace) {
            say("  [脱壳] 镜像自身出现过「写后执行」，但只改写了 %u 字节（未达 4096 字节判据）：不计为解壳产物，不落盘。\n", nd);
        }
    }
    int d = 0;
    for (int i = 0; i < g_regN; i++) {
        reg_t* r = &g_reg[i];
        /* 镜像内部的节区一律交给上面"整幅镜像"那条判据处理（带 PE 头、有 4096 字节门槛），
         * 否则样本往自己镜像里写几个字节就会把 3MB 的节区当"释放体"落一遍。 */
        if (r->base >= g_imagebase && r->base < g_imagebase + g_sizeofimage) continue;
        if ((r->prot & P_X) && r->written && r->kind != RK_STACK)
            { dump_bytes(outDir, "写后执行区", r->base, r->size); d++; }
    }
    if (!d) say("  （本次没有被写过且可执行的新区域）\n");
    dump_oep_and_scan(outDir);
    if (g_vfN) {
        say("\n ---- 样本落地文件（虚拟写入，未碰真盘）----\n");
        for (int i = 0; i < g_vfN; i++) {
            if (!g_vf[i].len) { say("  [空] %s\n", g_vf[i].path); continue; }
            const char* bn = g_vf[i].path; for (const char* p = bn; *p; p++) if (*p == '\\' || *p == '/') bn = p + 1;
            char fn[MAX_PATH]; snprintf(fn, sizeof(fn), "%s\\落地_%s", outDir, bn);
            FILE* f = fopen(fn, "wb"); if (f) { fwrite(g_vf[i].data, 1, g_vf[i].len, f); fclose(f); say("  [落盘] %s  (%u 字节) -> %s\n", g_vf[i].path, g_vf[i].len, fn); }
        }
    }
}

static int run_x64_program(const char* samplePath, const char* outDir, long maxinsn, int maxsec) {
    setup_thread_env_x64(samplePath);
    img_take_snapshot();
    setup_kuser_shared();
    RIP = (u64)g_imagebase + g_entry;
    g_halted = 0;
    g_insn = 0;
    clock_t t0 = clock();
    say("\n ---- 虚拟执行（x86-64 解释器，虚拟环境内，真机零接触）----\n");
    say("  镜像 0x%08X - 0x%08X（SizeOfImage 0x%X）\n", g_imagebase, g_imagebase + g_sizeofimage, g_sizeofimage);
    say("  入口 0x%08X  指令上限 %ld  时间上限 %d 秒\n", (u32)RIP, maxinsn, maxsec);
    char mainstop[160]; snprintf(mainstop, sizeof(mainstop), "%s", g_stop_reason);
    long spinn = 0; u32 sprev = 0;
    while (!g_halted) {
        if (g_insn >= maxinsn) { snprintf(g_stop_reason, sizeof(g_stop_reason), "达到指令上限（%ld）", maxinsn); break; }
        /* 空转检测：pause 与"跳回 pause"的 jmp 交替出现，两条都算（只看当前条会漏） */
        if (x64_is_pause_spin((u32)RIP) || (sprev && x64_is_pause_spin(sprev))) {
            if (++spinn > 1000) {
                blog("反虚拟机", "样本进入空转死循环（0x%08X 处 pause/jmp 自旋）：典型等待信号或反分析", (u32)RIP);
                tr("反虚拟机\t空转自旋\t0x%08X\n", (u32)RIP);
                snprintf(g_stop_reason, sizeof(g_stop_reason), "检测到空转死循环（0x%08X 处 pause/jmp 自旋，不推进内存）", (u32)RIP);
                g_halted = 1; break;
            }
        } else spinn = 0;
        sprev = (u32)RIP;
        if (!x64_step()) {
            if (g_fault && !strcmp(g_stop_reason, "正常退出"))
                snprintf(g_stop_reason, sizeof(g_stop_reason), "%s越界/未映射 @RIP=0x%08X（0x%llX）",
                         (g_x64_fault_what == 'F') ? "取指" : "取数", (u32)RIP, (unsigned long long)g_x64_fault_addr);
            break;
        }
        g_insn++;
        if ((g_insn & 0x3FFFF) == 0) {
            double el = (double)(clock() - t0) / CLOCKS_PER_SEC;
            if (el > (double)maxsec) { snprintf(g_stop_reason, sizeof(g_stop_reason), "达到时间上限（%.0f 秒 / %ld 条指令）", el, g_insn); break; }
        }
    }
    snprintf(mainstop, sizeof(mainstop), "%s", g_stop_reason);
    char thstop[160] = {0};
    /* ---- 主入口结束后，接着跑样本请求创建的工作线程（单线程顺序近似）---- */
    while (g_th_n > 0) {
        int i = --g_th_n;
        u64 saveX[16]; memcpy(saveX, X, sizeof(saveX));
        u32 stk2 = vm_alloc_region(0, 0x00100000, P_R | P_W, RK_STACK, "64位工作线程栈");
        if (!stk2) break;
        X[4] = (u64)stk2 + 0x000F0000;
        X[1] = g_th_arg[i]; X[2] = 0; X[8] = 0;
        xpush(0); xpush(0); xpush(0); xpush((u64)EXIT_MAGIC);
        RIP = g_th_fn[i]; g_halted = 0; g_x64_jmp = 1; g_fault = 0;
        say("  [线程] 开始运行工作线程 0x%08X（参数 0x%llX）\n", (u32)RIP, (unsigned long long)g_th_arg[i]);
        tr("线程\t运行工作线程 0x%08X\n", (u32)RIP);
        long base = g_insn; clock_t t1 = clock();
        long spinn2 = 0; u32 sprev2 = 0;
        while (!g_halted) {
            if (g_insn - base >= maxinsn) { snprintf(g_stop_reason, sizeof(g_stop_reason), "达到指令上限（%ld）", maxinsn); break; }
            if (x64_is_pause_spin((u32)RIP) || (sprev2 && x64_is_pause_spin(sprev2))) {
                if (++spinn2 > 1000) { snprintf(g_stop_reason, sizeof(g_stop_reason), "检测到空转死循环（0x%08X 处 pause/jmp 自旋）", (u32)RIP); g_halted = 1; break; }
            } else spinn2 = 0;
            sprev2 = (u32)RIP;
            if (!x64_step()) break;
            g_insn++;
            if ((g_insn & 0x3FFFF) == 0) {
                double el = (double)(clock() - t1) / CLOCKS_PER_SEC;
                if (el > (double)maxsec) { snprintf(g_stop_reason, sizeof(g_stop_reason), "达到时间上限（%.0f 秒 / %ld 条指令）", el, g_insn); break; }
            }
        }
        say("  [线程] 工作线程结束：%s（线程内执行 %ld 条指令）\n", g_stop_reason, g_insn - base);
        snprintf(thstop, sizeof(thstop), "%s", g_stop_reason);
        g_th_ran++;
        memcpy(X, saveX, sizeof(saveX));
    }
    if (g_th_ran) snprintf(g_stop_reason, sizeof(g_stop_reason), "%s；另有 %d 个工作线程已运行（最后一条：%s）", mainstop, g_th_ran, thstop);
    say("  停机：%s（共执行 %ld 条指令，虚拟内存 %u 页 / %u MB）\n", g_stop_reason, g_insn, g_vm_alloced, g_vm_alloced >> 10);
    if (g_insn >= 1000) x64_dump_last(28);
    tr("STOP\t%s\t%ld\n", g_stop_reason, g_insn);
    finalize_dumps(outDir);
    return 0;
}

/* ---- x64 解释器自检（手写 x86-64 程序）---- */
static int selftest_x64(void) {
    int fail = 0;
    say("\n ---- 解释器自检（手写 x86-64 程序）----\n");
    u32 code = vm_alloc_region(0x00E00000, 0x1000, P_R | P_X, RK_IMAGE, "x64测试代码");
    u32 data = vm_alloc_region(0x00F00000, 0x1000, P_R | P_W, RK_ALLOC, "x64测试数据");
    u32 stk  = vm_alloc_region(0x01000000, 0x10000, P_R | P_W, RK_STACK, "x64测试栈");
    if (!code || !data || !stk) { say("  [NG] 测试内存分配失败\n"); return 1; }

    /* mov rax,0x12345678 / mov rbx,5 / xor rcx,rcx / L: add rcx,rax / dec rbx / jnz L
       mov [data],rcx / mov rdx,[data] / movsxd rbx,edx / lea rax,[rip+4] / mov rax,[rax] / int3
       db 0xDEADBEEFCAFEBABE */
    u8 prog[] = {
        0x48,0xC7,0xC0,0x78,0x56,0x34,0x12,               /* off 0  mov rax,0x12345678 */
        0x48,0xC7,0xC3,0x05,0x00,0x00,0x00,               /* off 7  mov rbx,5 */
        0x48,0x31,0xC9,                                    /* off 14 xor rcx,rcx */
        0x48,0x01,0xC1,                                    /* off 17 add rcx,rax   <- L */
        0x48,0xFF,0xCB,                                    /* off 20 dec rbx */
        0x75,0xF8,                                         /* off 23 jnz L */
        0x48,0x89,0x0C,0x25,0,0,0,0,                       /* off 25 mov [data],rcx */
        0x48,0x8B,0x14,0x25,0,0,0,0,                       /* off 33 mov rdx,[data] */
        0x48,0x63,0xDA,                                    /* off 41 movsxd rbx,edx */
        0x48,0x8D,0x05,0x04,0x00,0x00,0x00,               /* off 44 lea rax,[rip+4] -> off 55 */
        0x48,0x8B,0x00,                                    /* off 51 mov rax,[rax] */
        0xCC,                                              /* off 54 int3 */
        0xBE,0xBA,0xFE,0xCA,0xEF,0xBE,0xAD,0xDE        /* off 55 常量 0xDEADBEEFCAFEBABE */
    };
    memcpy(prog + 29, &data, 4);
    memcpy(prog + 37, &data, 4);
    vm_poke(code, prog, sizeof(prog));
    reg_setprot(code, 0x1000, P_R | P_X);

    X[4] = (u64)stk + 0x8000;
    RIP = code; g_halted = 0; g_fault = 0; g_insn = 0;
    int n = 0;
    for (; n < 200 && !g_halted; n++) { if (!x64_step()) break; g_insn++; }
    u64 expect = 0x12345678ull * 5ull;   /* 0x5B05B058 */
    say("  [%s] x64 循环累加 5 次：RCX=0x%llX（期望 0x%llX）\n", X[1] == expect ? "OK" : "NG", (unsigned long long)X[1], (unsigned long long)expect);
    if (X[1] != expect) fail++;
    say("  [%s] x64 内存写入后读回：RDX=0x%llX\n", X[2] == expect ? "OK" : "NG", (unsigned long long)X[2]);
    if (X[2] != expect) fail++;
    u32 mem = 0; vm_read32(data, &mem);
    say("  [%s] x64 [0x%08X]=0x%08X（内存真实被写）\n", mem == (u32)expect ? "OK" : "NG", data, mem);
    if (mem != (u32)expect) fail++;
    say("  [%s] movsxd rbx,edx：RBX=0x%llX\n", X[3] == expect ? "OK" : "NG", (unsigned long long)X[3]);
    if (X[3] != expect) fail++;
    say("  [%s] RIP 相对寻址 lea/mov：RAX=0x%llX（期望 0xDEADBEEFCAFEBABE）\n", X[0] == 0xDEADBEEFCAFEBABEull ? "OK" : "NG", (unsigned long long)X[0]);
    if (X[0] != 0xDEADBEEFCAFEBABEull) fail++;
    say("  [%s] 指令数=%ld，停机：%s\n", (n > 0 && n < 200) ? "OK" : "NG", g_insn, g_stop_reason);
    if (!(n > 0 && n < 200)) fail++;

    say("\n x64 解释器自检：%s（失败项 %d）\n", fail ? "未通过" : "全部通过", fail);
    return fail;
}

static int run_program(const char* samplePath, const char* outDir, long maxinsn, int maxsec) {
    setup_thread_env(samplePath);

    /* ---- 新增：先执行 TLS 回调（如果有）---- */
    run_tls_callbacks();

    EIP = g_imagebase + g_entry;

    /* ---- 新增：入口可执行性检查 ---- */
    {
        reg_t* r = reg_find(EIP);
        u32 epg = EIP >> PG_SHIFT;
        int exec = (epg < PG_COUNT && g_pg[epg].p && (g_pg[epg].prot & P_X));
        say("  入口 0x%08X  所在节：%s  prot=%d  %s可执行\n",
            EIP, r ? r->tag : "(无)", r ? (int)r->prot : -1, exec ? "" : "★不");
        if (!exec) {
            say("  [警告] 入口不在可执行内存！真实加载器会拒绝加载。\n");
            say("         若样本含 TLS 回调，解壳逻辑很可能在 TLS 里，EP 只是占位。\n");
        }
    }

    g_halted = 0;
    g_insn = 0;
    clock_t t0 = clock();
    say("\n ---- 虚拟执行（x86-32 解释器）----\n");
    say("  镜像 0x%08X - 0x%08X（SizeOfImage 0x%X）\n", g_imagebase, g_imagebase + g_sizeofimage, g_sizeofimage);
    say("  入口 0x%08X  指令上限 %ld  时间上限 %d 秒\n", EIP, maxinsn, maxsec);
    int rc = 1;
    while (!g_halted) {
        if (g_insn >= maxinsn) { snprintf(g_stop_reason, sizeof(g_stop_reason), "达到指令上限（%ld）", maxinsn); break; }
        if (!step()) { 
            if (g_fault && !strcmp(g_stop_reason, "正常退出")) 
                snprintf(g_stop_reason, sizeof(g_stop_reason), "内存访问越界/未映射 @EIP=0x%08X", EIP); 
            break; 
        }
        g_insn++;
        if ((g_insn & 0x3FFFF) == 0) {
            double el = (double)(clock() - t0) / CLOCKS_PER_SEC;
            if (el > (double)maxsec) { 
                snprintf(g_stop_reason, sizeof(g_stop_reason), "达到时间上限（%.0f 秒 / %ld 条指令）", el, g_insn); 
                break; 
            }
        }
    }
    (void)rc;
    
    /* ---- 下面是结尾部分，必须加上黑匣子打印 ---- */
    say("  停机：%s（共执行 %ld 条指令，虚拟内存 %u 页 / %u MB）\n", g_stop_reason, g_insn, g_vm_alloced, g_vm_alloced >> 10);
    tr("STOP\t%s\t%ld\n", g_stop_reason, g_insn);

    if (g_insn >= 50) x32_dump_last(30);  /* ★ 新增：自动打印最后 30 条指令 */

    /* 落盘 */
    finalize_dumps(outDir);
    return 0;
}

/* 解释器自检：手写 x86 程序 + "写后执行"检测 */
static int selftest_cpu(void) {
    int fail = 0;
    say("\n ---- 解释器自检（手写 x86-32 程序）----\n");

    u32 code = vm_alloc_region(0x00A00000, 0x1000, P_R | P_X, RK_IMAGE, "测试代码");
    u32 data = vm_alloc_region(0x00B00000, 0x1000, P_R | P_W, RK_ALLOC, "测试数据");
    u32 stk  = vm_alloc_region(0x00C00000, 0x10000, P_R | P_W, RK_STACK, "测试栈");

    /* mov eax,0x12345678; mov ecx,5; xor edx,edx; L: add edx,eax; dec ecx; jnz L;
       mov [data],edx; mov ebx,[data]; int3 */
    u8 prog[] = {
        0xB8,0x78,0x56,0x34,0x12,
        0xB9,0x05,0x00,0x00,0x00,
        0x31,0xD2,
        0x01,0xC2, 0x49, 0x75,0xFB,
        0x89,0x15,0,0,0,0,
        0x8B,0x1D,0,0,0,0,
        0xCC
    };
    memcpy(prog + 19, &data, 4);
    memcpy(prog + 25, &data, 4);
    vm_poke(code, prog, sizeof(prog));
    reg_setprot(code, 0x1000, P_R | P_X);

    ESP = stk + 0x8000;
    EIP = code; g_halted = 0; g_fault = 0; g_insn = 0;
    int n = 0;
    for (; n < 200 && !g_halted; n++) { if (!step()) break; g_insn++; }
    u32 expect = 0x12345678u * 5u;
    say("  [%s] 循环累加 5 次：EDX=0x%08X（期望 0x%08X）\n", EDX == expect ? "OK" : "NG", EDX, expect);
    if (EDX != expect) fail++;
    say("  [%s] 内存写入后读回：EBX=0x%08X\n", EBX == expect ? "OK" : "NG", EBX);
    if (EBX != expect) fail++;
    u32 mem = 0; vm_read32(data, &mem);
    say("  [%s] [0x%08X]=0x%08X（内存真实被写）\n", mem == expect ? "OK" : "NG", data, mem);
    if (mem != expect) fail++;
    say("  [%s] 指令数=%ld，停机：%s\n", (n > 0 && n < 200) ? "OK" : "NG", g_insn, g_stop_reason);
    if (!(n > 0 && n < 200)) fail++;

    /* 写后执行检测：先以 RW 写入一段代码，再改成可执行并跳进去 */
    g_oep_hits = 0; g_oep_candidate = 0;
    u32 buf = vm_alloc_region(0x00D00000, 0x1000, P_R | P_W, RK_ALLOC, "假解壳区");
    u8 stub[] = { 0xB8, 0x41, 0x41, 0x41, 0x41, 0xC3 };   /* mov eax,'AAAA'; ret */
    for (u32 i = 0; i < sizeof(stub); i++) vm_write8(buf + i, stub[i]);   /* 走 vm_write -> 标记 written */
    reg_setprot(buf, 0x1000, P_R | P_W | P_X);
    push32(EXIT_MAGIC);
    EIP = buf; g_halted = 0; g_fault = 0;
    step();
    say("  [%s] 写后执行被检出（疑似 OEP 命中 %d 次）\n", g_oep_hits > 0 ? "OK" : "NG", g_oep_hits);
    if (g_oep_hits <= 0) fail++;
    say("  [%s] 跳进去的假载荷被执行（EAX=0x%08X 期望 0x41414141）\n", EAX == 0x41414141u ? "OK" : "NG", EAX);
    if (EAX != 0x41414141u) fail++;
    step();   /* ret -> EXIT_MAGIC */
    say("  [%s] 返回哨兵生效（停机：%s）\n", g_halted ? "OK" : "NG", g_stop_reason);
    if (!g_halted) fail++;

    say("\n 解释器自检：%s（失败项 %d）\n", fail ? "未通过" : "全部通过", fail);
    return fail;
}

/* --------------------------------------------------------------- 自检 ----- */
static int selftest(void) {
    int fail = 0;
    say("%s\n", VERSION_STR);
    say("---- 自检 ----\n");

    /* 1) 虚拟内存读写与越界保护 */
    u32 base = vm_alloc_region(0x400000, 0x2000, P_R | P_W, RK_ALLOC, "selftest");
    say("  [%s] 虚拟分配 0x%08X\n", base ? "OK" : "NG", base);
    if (!base) fail++;
    u32 v = 0xDEADBEEF;
    if (base && vm_write32(base, v)) { u32 r = 0; vm_read32(base, &r); say("  [%s] 写后读一致 0x%08X\n", r == v ? "OK" : "NG", r); if (r != v) fail++; }
    else fail++;
    if (base && !vm_read32(0x00000010, &v)) say("  [OK] 未映射地址读取被安全拒绝\n"); else { say("  [NG] 未映射地址竟然读成功\n"); fail++; }
    u32 ro = vm_alloc_region(0x500000, 0x1000, P_R, RK_ALLOC, "ro");
    if (ro && !vm_write32(ro, 1)) say("  [OK] 只读内存写入被拒绝\n"); else { say("  [NG] 只读内存可写\n"); fail++; }

    /* 2) 导入桩分配与查找 */
    u32 a1 = stub_alloc("kernel32.dll", "CreateFileA");
    u32 a2 = stub_alloc("kernel32.dll", "CreateFileA");
    u32 a3 = stub_alloc("urlmon.dll", "URLDownloadToFileA");
    say("  [%s] 桩复用（同 API 同地址）0x%08X\n", (a1 && a1 == a2) ? "OK" : "NG", a1);
    if (!(a1 && a1 == a2)) fail++;
    say("  [%s] 不同 API 不同桩 0x%08X\n", (a3 && a3 != a1) ? "OK" : "NG", a3);
    if (!(a3 && a3 != a1)) fail++;
    imp_t* im = stub_lookup(a1);
    say("  [%s] 桩反查 Name=%s\n", (im && !strcmp(im->name, "CreateFileA")) ? "OK" : "NG", im ? im->name : "(空)");
    if (!(im && !strcmp(im->name, "CreateFileA"))) fail++;

    say("\n 结果：%s（失败项 %d）\n", fail ? "未通过" : "全部通过", fail);
    fail += selftest_cpu();
    fail += selftest_x64();
    say("\n 总结果：%s（累计失败项 %d）\n", fail ? "未通过" : "全部通过", fail);
    return fail ? 1 : 0;
}

/* ---------------------------------------------------------------- main ---- */
int main(int argc, char** argv) {
    SetConsoleOutputCP(65001);
    say("%s\n", VERSION_STR);
    if (argc < 2) {
        say("用法:\n");
        say("  pe_vm.exe --load <sample.exe>      只装载并打印结构（不执行）\n");
        say("  pe_vm.exe --selftest               自检\n");
        say("  pe_vm.exe <sample.exe> [--dump f] [--trace f] [--max-insn N]   （x86-32 与 x86-64 均可执行）\n");
        return 2;
    }
    if (!strcmp(argv[1], "--selftest")) return selftest();

    const char* sample = NULL;
    int load_only = 0, do_ext = 0;
    char outDir[MAX_PATH] = "pev_out";
    long maxinsn = 40000000L;
    int maxsec = 30;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--load")) { load_only = 1; if (i + 1 < argc) sample = argv[++i]; }
        else if (!strcmp(argv[i], "--extract")) do_ext = 1;
        else if (!strcmp(argv[i], "--outdir") && i + 1 < argc) snprintf(outDir, sizeof(outDir), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--max-insn") && i + 1 < argc) maxinsn = atol(argv[++i]);
        else if (!strcmp(argv[i], "--max-sec") && i + 1 < argc) maxsec = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--insn") && i + 1 < argc) g_insn_print = atol(argv[++i]);
        else if (!strcmp(argv[i], "--trace") && i + 1 < argc) { g_trace = fopen(argv[++i], "wb"); }
        else if (!strcmp(argv[i], "--verbose")) g_verbose = 1;
        else if (argv[i][0] != '-') sample = argv[i];
    }
    if (!sample) { say("  [错误] 未指定样本\n"); return 2; }

    if (!pe_load(sample)) return 3;
    if (load_only) { print_load_view(sample); return 0; }
    if (do_ext)    { do_extract(sample, outDir); return 0; }

    /* 默认：虚拟执行（x86-32 与 x86-64 各走各的解释器，互不影响） */
    CreateDirectoryA(outDir, NULL);
    if (g_is64) run_x64_program(sample, outDir, maxinsn, maxsec);
    else        run_program(sample, outDir, maxinsn, maxsec);

    /* 行为摘要（中文） */
    say("\n ---- 虚拟行为摘要 ----\n");
    say("  API 调用次数 : %d\n", g_api_calls);
    if (g_unk_total) say("  ★ 未登记参数个数的 API：%d 次（%s）—— 这类调用会让栈错位，请优先补表\n", g_unk_total, unk_api_hint());
    if (g_logN == 0) say("  （本次未记录到行为日志）\n");
    for (int i = 0; i < g_logN && i < 60; i++) say("  [%s] %s\n", g_log_kind[i], g_log_text[i]);
    if (g_logN > 60) say("  ...（其余 %d 条见 --trace 文件）\n", g_logN - 60);
    say("  落盘目录 : %s\n", outDir);
    return 0;
}