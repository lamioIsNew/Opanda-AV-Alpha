#include "feature_extractor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

/* ============================================================
 * 549 维特征提取（与训练端语义严格对齐）
 *
 * 训练链路：EMBER features.py (lief) -> 原始特征 JSON -> jsonl_to_csv.py 打平
 * 本文件的每个维度必须与 jsonl_to_csv.py 的取数方式一致，否则模型输入是
 * 分布外的垃圾值（这正是此前 Process Hacker 误报的根因之一）。
 *
 * 关键语义（对齐后）：
 *  512..520 strings: runs of [0x20-0x7f] len>=5; entropy=字符分布香农熵;
 *                    paths=数 "c:\"(不分大小写), urls=数 "http(s)://",
 *                    registry=数 "HKEY_"(大小写敏感), MZ=数 "MZ"; 非重叠
 *                    printable_ratio 恒 0（训练 JSON 无此 key, get 默认 0）
 *  521..530 general: size, vsize=SizeOfImage, imports=导入函数计数,
 *                    exports=导出函数计数, has_*=数据目录标志, symbols=COFF 符号数
 *  531..547 header:  machine/subsystem/magic 为映射枚举（见 jsonl_to_csv）;
 *                    characteristics 取"已命名位"的数量
 *  548      section: entry 为字符串, float() 失败恒 0
 * ============================================================ */

static int popcount16(unsigned int v, unsigned int mask) {
    v &= mask & 0xFFFF;
    int c = 0;
    while (v) { c += (int)(v & 1); v >>= 1; }
    return c;
}

/* ============================================================
 * PE 解析
 * ============================================================ */

typedef struct {
    unsigned int machine;                  /* 映射后：I386=0 AMD64=1 ARM=2 ARM64=3 其它=4 */
    unsigned int subsystem;                /* 映射后：GUI=0 CUI=1 NATIVE=2 其它=3 */
    unsigned int magic;                    /* 映射后：PE32=0 其它(含PE32+)=2 */
    unsigned int characteristics_len;
    unsigned int dll_characteristics_len;
    unsigned int timestamp;
    unsigned int major_image_version;
    unsigned int minor_image_version;
    unsigned int major_linker_version;
    unsigned int minor_linker_version;
    unsigned int major_os_version;
    unsigned int minor_os_version;
    unsigned int major_subsystem_version;
    unsigned int minor_subsystem_version;
    unsigned int sizeof_code;
    unsigned int sizeof_headers;
    unsigned int sizeof_heap_commit;
    unsigned int vsize;                    /* SizeOfImage */
    unsigned int num_imports;              /* 导入函数计数 */
    unsigned int num_exports;              /* 导出函数计数 */
    int has_debug;
    int has_relocations;
    int has_resources;
    int has_signature;
    int has_tls;
    unsigned int num_symbols;              /* COFF 符号数（无符号表=0） */
} PEInfo;

typedef struct { unsigned int va, vsize, raw, rawsize; } SecHdr;

/* 检查是否是合法 PE 文件 */
int is_valid_pe(const char *filepath) {
    FILE *fp = fopen(filepath, "rb");
    if (!fp) return 0;

    unsigned char dos[2];
    if (fread(dos, 1, 2, fp) != 2 || dos[0] != 'M' || dos[1] != 'Z') {
        fclose(fp); return 0;
    }

    fseek(fp, 0x3C, SEEK_SET);
    unsigned int e_lfanew;
    if (fread(&e_lfanew, 4, 1, fp) != 1) { fclose(fp); return 0; }
    if (e_lfanew < 0x40 || e_lfanew > 0x1000) { fclose(fp); return 0; }

    fseek(fp, e_lfanew, SEEK_SET);
    unsigned char nt[4];
    if (fread(nt, 1, 4, fp) != 4 || nt[0] != 'P' || nt[1] != 'E') {
        fclose(fp); return 0;
    }
    fclose(fp);
    return 1;
}

/* 内存缓冲版 PE 合法性检查（流模式用） */
int is_valid_pe_buf(const unsigned char *buf, long size) {
    if (size < 0x40) return 0;
    if (buf[0] != 'M' || buf[1] != 'Z') return 0;
    unsigned int e_lfanew = *(const unsigned int *)(buf + 0x3C);
    if (e_lfanew < 0x40 || e_lfanew > 0x1000) return 0;
    if ((long)e_lfanew + 4 > size) return 0;
    if (buf[e_lfanew] != 'P' || buf[e_lfanew + 1] != 'E') return 0;
    return 1;
}

/* RVA -> 文件偏移（通过节区表；头部区域按恒等映射兜底） */
static long rva_to_off(const unsigned char *buf, long size, const SecHdr *secs, int nsec, unsigned int rva) {
    for (int i = 0; i < nsec; i++) {
        unsigned int sz = secs[i].rawsize ? secs[i].rawsize : secs[i].vsize;
        if (sz && rva >= secs[i].va && (unsigned long long)rva < (unsigned long long)secs[i].va + sz)
            return (long)secs[i].raw + (long)(rva - secs[i].va);
    }
    if ((long)rva < size) return (long)rva;
    return -1;
}

/* 导入函数计数（与 lief imported_functions 语义对齐：逐 DLL 数 thunk 条目） */
static unsigned int count_imports(const unsigned char *buf, long size, const SecHdr *secs, int nsec, unsigned int rva, int is64) {
    if (!rva) return 0;
    long off = rva_to_off(buf, size, secs, nsec, rva);
    if (off < 0 || off + 20 > size) return 0;

    unsigned int total = 0;
    for (int guard = 0; guard < 4096; guard++) {
        if (off + 20 > size) break;
        const unsigned char *d = buf + off;
        unsigned int oft  = *(const unsigned int *)(d + 0);
        unsigned int name = *(const unsigned int *)(d + 12);
        unsigned int ft   = *(const unsigned int *)(d + 16);
        if (oft == 0 && name == 0 && ft == 0) break;

        unsigned int thunk = oft ? oft : ft;
        if (thunk) {
            long to = rva_to_off(buf, size, secs, nsec, thunk);
            if (to >= 0) {
                if (!is64) {
                    while (to + 4 <= size) {
                        unsigned int v = *(const unsigned int *)(buf + to);
                        if (v == 0) break;
                        total++;
                        to += 4;
                    }
                } else {
                    while (to + 8 <= size) {
                        unsigned long long v = *(const unsigned long long *)(buf + to);
                        if (v == 0) break;
                        total++;
                        to += 8;
                    }
                }
            }
        }
        off += 20;
    }
    return total;
}

/* 导出函数计数（与 lief exported_functions 语义对齐：数 EAT 非空条目） */
static unsigned int count_exports(const unsigned char *buf, long size, const SecHdr *secs, int nsec, unsigned int rva) {
    if (!rva) return 0;
    long off = rva_to_off(buf, size, secs, nsec, rva);
    if (off < 0 || off + 0x28 > size) return 0;

    unsigned int num_funcs = *(const unsigned int *)(buf + off + 0x14);
    unsigned int aof       = *(const unsigned int *)(buf + off + 0x1C);
    if (!num_funcs || !aof) return 0;
    if (num_funcs > 0x40000) num_funcs = 0x40000;   /* 防御疯狂样本 */

    long ao = rva_to_off(buf, size, secs, nsec, aof);
    if (ao < 0) return 0;

    unsigned int cnt = 0;
    for (unsigned int i = 0; i < num_funcs; i++) {
        long p = ao + (long)i * 4;
        if (p + 4 > size) break;
        if (*(const unsigned int *)(buf + p) != 0) cnt++;
    }
    return cnt;
}

static void parse_pe(unsigned char *buf, long size, PEInfo *info) {
    memset(info, 0, sizeof(PEInfo));
    if (size < 0x40) return;
    if (buf[0] != 'M' || buf[1] != 'Z') return;

    unsigned int e_lfanew = *(unsigned int *)(buf + 0x3C);
    if ((long)e_lfanew + 0x18 > size) return;
    if (buf[e_lfanew] != 'P' || buf[e_lfanew + 1] != 'E') return;

    unsigned char *nt = buf + e_lfanew;
    unsigned short machine = *(unsigned short *)(nt + 4);
    unsigned short num_sections = *(unsigned short *)(nt + 6);
    unsigned int ptr_sym = *(unsigned int *)(nt + 8);
    unsigned int coff_syms = *(unsigned int *)(nt + 12);
    unsigned short opt_size = *(unsigned short *)(nt + 20);
    unsigned short characteristics = *(unsigned short *)(nt + 22);

    /* machine：训练端为 lief 名称映射 {I386:0, AMD64:1, ARM:2, ARM64:3, 其它:4} */
    switch (machine) {
        case 0x014C: info->machine = 0; break;   /* I386 */
        case 0x8664: info->machine = 1; break;   /* AMD64 */
        case 0x01C0: case 0x01C2: case 0x01C4: info->machine = 2; break; /* ARM 系列 */
        case 0xAA64: info->machine = 3; break;   /* ARM64 */
        default:     info->machine = 4; break;
    }
    info->timestamp = *(unsigned int *)(nt + 8);

    /* symbols：COFF 符号表计数（无符号表指针则为 0；防疯狂值） */
    if (ptr_sym != 0 && coff_syms <= 0x40000) info->num_symbols = coff_syms;

    /* characteristics：lief 只给出"已命名位"，0x0040 为未命名保留位 */
    info->characteristics_len = popcount16(characteristics, 0xFFBF);

    unsigned char *opt = nt + 24;
    long opt_avail = size - (long)(opt - buf);
    if (opt_avail < 0) opt_avail = 0;
    if ((long)opt_size > opt_avail) opt_size = (unsigned short)opt_avail;

    unsigned int import_rva = 0, export_rva = 0;
    int is64 = 0;

    if (opt_size >= 0x60) {
        unsigned short magic = *(unsigned short *)opt;
        info->magic = (magic == 0x10B) ? 0 : 2;   /* 训练端 'PE32'->0，'PE32_PLUS' 落 else->2 */
        is64 = (magic == 0x20B);
        unsigned int ddir_base = is64 ? 0x70 : 0x60;

        if (opt_size >= 0x3C) info->vsize = *(unsigned int *)(opt + 0x38);   /* SizeOfImage */

        unsigned short subsystem = *(unsigned short *)(opt + 0x44);
        if (subsystem == 2) info->subsystem = 0;        /* WINDOWS_GUI */
        else if (subsystem == 3) info->subsystem = 1;   /* WINDOWS_CUI */
        else if (subsystem == 1) info->subsystem = 2;   /* NATIVE */
        else info->subsystem = 3;

        info->major_image_version = *(unsigned short *)(opt + 0x2C);
        info->minor_image_version = *(unsigned short *)(opt + 0x2E);
        info->major_linker_version = *(unsigned char *)(opt + 0x02);
        info->minor_linker_version = *(unsigned char *)(opt + 0x03);
        info->major_os_version = *(unsigned short *)(opt + 0x28);
        info->minor_os_version = *(unsigned short *)(opt + 0x2A);
        info->major_subsystem_version = *(unsigned short *)(opt + 0x30);
        info->minor_subsystem_version = *(unsigned short *)(opt + 0x32);
        info->sizeof_code = *(unsigned int *)(opt + 0x04);
        info->sizeof_headers = *(unsigned int *)(opt + 0x3C);
        /* SizeOfHeapCommit：PE32 在 0x54，PE32+ 在 0x60（各不相同！） */
        if (is64) {
            if (opt_size >= 0x64) info->sizeof_heap_commit = *(unsigned int *)(opt + 0x60);
        } else {
            if (opt_size >= 0x58) info->sizeof_heap_commit = *(unsigned int *)(opt + 0x54);
        }

        /* dll_characteristics：低 5 位未命名 */
        unsigned short dll_chars = *(unsigned short *)(opt + 0x46);
        info->dll_characteristics_len = popcount16(dll_chars, 0xFFE0);

        /* 数据目录：PE32 基线 0x60，PE32+ 基线 0x70（此前写死 0x60 导致 64 位全错） */
        unsigned int dd[16];
        memset(dd, 0, sizeof(dd));
        for (int i = 0; i < 16; i++) {
            if ((unsigned int)ddir_base + (unsigned int)(i * 8) + 8 <= (unsigned int)opt_size)
                dd[i] = *(unsigned int *)(opt + ddir_base + i * 8);
        }
        export_rva = dd[0];
        import_rva = dd[1];
        info->has_resources   = (dd[2] != 0);
        info->has_signature   = (dd[4] != 0);
        info->has_relocations = (dd[5] != 0);
        info->has_debug       = (dd[6] != 0);
        info->has_tls         = (dd[9] != 0);
    }

    /* 节区表 */
    SecHdr secs[96];
    int nsec = 0;
    long sec_off = (long)(nt - buf) + 24 + opt_size;
    int ns = num_sections > 96 ? 96 : num_sections;
    for (int i = 0; i < ns; i++) {
        long p = sec_off + (long)i * 40;
        if (p + 40 > size) break;
        const unsigned char *s = buf + p;
        secs[nsec].vsize   = *(const unsigned int *)(s + 8);
        secs[nsec].va      = *(const unsigned int *)(s + 12);
        secs[nsec].rawsize = *(const unsigned int *)(s + 16);
        secs[nsec].raw     = *(const unsigned int *)(s + 20);
        nsec++;
    }

    info->num_imports = count_imports(buf, size, secs, nsec, import_rva, is64);
    info->num_exports = count_exports(buf, size, secs, nsec, export_rva);
}

/* ============================================================
 * 特征块
 * ============================================================ */

static void extract_histogram(const unsigned char *buf, long size, unsigned int *hist) {
    memset(hist, 0, sizeof(unsigned int) * 256);
    for (long i = 0; i < size; i++) hist[buf[i]]++;
}

static double shannon_entropy(const unsigned char *buf, long size) {
    if (size <= 0) return 0.0;
    unsigned int hist[256] = {0};
    for (long i = 0; i < size; i++) hist[buf[i]]++;
    double e = 0.0;
    for (int i = 0; i < 256; i++) {
        if (hist[i] > 0) {
            double p = (double)hist[i] / size;
            e -= p * log2(p);
        }
    }
    return e;
}

/* 单块量化：高半字节 16 桶计数 + 熵箱（对齐 EMBER ByteEntropyHistogram._entropy_bin_counts） */
static void byteentropy_block(const unsigned char *p, long n, double *be) {
    int c[16];
    memset(c, 0, sizeof(c));
    for (long i = 0; i < n; i++) c[p[i] >> 4]++;

    double H = 0.0;
    for (int j = 0; j < 16; j++) {
        if (c[j]) {
            double pr = (double)c[j] / 2048.0;   /* 恒除以窗口大小（含不足窗口的短文件） */
            H -= pr * log2(pr);
        }
    }
    H *= 2.0;
    int hbin = (int)(H * 2.0);
    if (hbin >= 16) hbin = 15;

    double *row = be + hbin * 16;
    for (int j = 0; j < 16; j++) row[j] += (double)c[j];
}

/* EMBER ByteEntropyHistogram 精确复刻：window=2048, step=1024, 输出 16x16 展平 */
static void extract_byteentropy(const unsigned char *buf, long size, double *be) {
    memset(be, 0, sizeof(double) * 256);
    if (size <= 0) return;
    if (size < 2048) {
        byteentropy_block(buf, size, be);
    } else {
        for (long start = 0; start + 2048 <= size; start += 1024)
            byteentropy_block(buf + start, 2048, be);
    }
}

typedef struct {
    unsigned int numstrings;
    double avlength;
    unsigned int printables;
    double entropy;
    unsigned int paths;
    unsigned int urls;
    unsigned int registry;
    unsigned int MZ;
} StringInfo;

/* 对齐 EMBER StringExtractor.raw_features 的字符串统计 */
static void extract_strings(const unsigned char *buf, long size, StringInfo *si) {
    memset(si, 0, sizeof(StringInfo));
    if (size <= 0) return;

    unsigned long long hist96[96];
    memset(hist96, 0, sizeof(hist96));
    unsigned long long csum = 0;

    /* 连续 [0x20-0x7f] 且长度 >= 5 的串 */
    long i = 0;
    while (i < size) {
        unsigned char c = buf[i];
        if (c >= 0x20 && c <= 0x7F) {
            long start = i;
            while (i < size && buf[i] >= 0x20 && buf[i] <= 0x7F) i++;
            long len = i - start;
            if (len >= 5) {
                si->numstrings++;
                csum += (unsigned long long)len;
                for (long k = start; k < i; k++) hist96[buf[k] - 0x20]++;
            }
        } else {
            i++;
        }
    }
    si->printables = (unsigned int)csum;
    if (si->numstrings > 0) {
        si->avlength = (double)csum / (double)si->numstrings;
        double H = 0.0;
        for (int b = 0; b < 96; b++) {
            if (hist96[b]) {
                double p = (double)hist96[b] / (double)csum;
                H -= p * log2(p);
            }
        }
        si->entropy = H;
    }

    /* paths: 非重叠数 "c:\"（不分大小写） */
    for (long k = 0; k + 3 <= size; ) {
        unsigned char c0 = buf[k];
        if ((c0 == 'c' || c0 == 'C') && buf[k + 1] == ':' && buf[k + 2] == '\\') { si->paths++; k += 3; }
        else k++;
    }
    /* urls: 非重叠数 "http://" 或 "https://"（不分大小写，先试 https） */
    for (long k = 0; k + 7 <= size; ) {
        int ishttp = (buf[k] == 'h' || buf[k] == 'H') &&
                     (buf[k + 1] == 't' || buf[k + 1] == 'T') &&
                     (buf[k + 2] == 't' || buf[k + 2] == 'T') &&
                     (buf[k + 3] == 'p' || buf[k + 3] == 'P');
        if (ishttp) {
            if (k + 8 <= size && (buf[k + 4] == 's' || buf[k + 4] == 'S') &&
                buf[k + 5] == ':' && buf[k + 6] == '/' && buf[k + 7] == '/') { si->urls++; k += 8; continue; }
            if (buf[k + 4] == ':' && buf[k + 5] == '/' && buf[k + 6] == '/') { si->urls++; k += 7; continue; }
        }
        k++;
    }
    /* registry: 非重叠数 "HKEY_"（大小写敏感） */
    for (long k = 0; k + 5 <= size; ) {
        if (buf[k] == 'H' && buf[k + 1] == 'K' && buf[k + 2] == 'E' && buf[k + 3] == 'Y' && buf[k + 4] == '_') { si->registry++; k += 5; }
        else k++;
    }
    /* MZ: 非重叠计数 */
    for (long k = 0; k + 2 <= size; ) {
        if (buf[k] == 'M' && buf[k + 1] == 'Z') { si->MZ++; k += 2; }
        else k++;
    }
}

/* ============================================================
 * 主提取函数
 * ============================================================ */

int extract_features(const char *filepath, double *features) {
    FILE *fp = fopen(filepath, "rb");
    if (!fp) return 0;
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (fsize <= 0) { fclose(fp); return 0; }
    unsigned char *buf = (unsigned char *)malloc(fsize);
    if (!buf) { fclose(fp); return 0; }
    size_t got = fread(buf, 1, fsize, fp);
    fclose(fp);
    if ((long)got != fsize) { free(buf); return 0; }

    int ok = extract_features_buf(buf, fsize, features);
    free(buf);
    return ok;
}

/* 从内存缓冲提取（stream_scan 用；与文件版逻辑完全一致） */
int extract_features_buf(const unsigned char *cbuf, long fsize, double *features) {
    const unsigned char *buf = cbuf;
    memset(features, 0, sizeof(double) * FEATURE_DIM);

    /* 1. histogram 256 维（原始字节计数） */
    unsigned int hist[256];
    extract_histogram(buf, fsize, hist);
    for (int i = 0; i < 256; i++) features[i] = (double)hist[i];

    /* 2. byteentropy 256 维（EMBER 16x16 联合直方图：熵箱*16 + 高半字节） */
    double be[256];
    extract_byteentropy(buf, fsize, be);
    for (int i = 0; i < 256; i++) features[256 + i] = be[i];

    /* 3. strings 9 维 */
    StringInfo si;
    extract_strings(buf, fsize, &si);
    features[512] = (double)si.numstrings;
    features[513] = si.avlength;
    features[514] = (double)si.printables;
    features[515] = 0.0;                      /* printable_ratio：训练端字段缺失恒 0 */
    features[516] = si.entropy;
    features[517] = (double)si.paths;
    features[518] = (double)si.urls;
    features[519] = (double)si.registry;
    features[520] = (double)si.MZ;

    /* 4. general 10 维 */
    PEInfo pe;
    parse_pe((unsigned char *)buf, fsize, &pe);
    features[521] = (double)fsize;
    features[522] = (double)pe.vsize;
    features[523] = (double)pe.num_imports;
    features[524] = (double)pe.num_exports;
    features[525] = pe.has_debug;
    features[526] = pe.has_relocations;
    features[527] = pe.has_resources;
    features[528] = pe.has_signature;
    features[529] = pe.has_tls;
    features[530] = (double)pe.num_symbols;

    /* 5. header 17 维（machine/subsystem/magic 已是映射枚举） */
    features[531] = (double)pe.machine;
    features[532] = (double)pe.subsystem;
    features[533] = (double)pe.magic;
    features[534] = (double)pe.characteristics_len;
    features[535] = (double)pe.dll_characteristics_len;
    features[536] = (double)pe.timestamp;
    features[537] = (double)pe.major_image_version;
    features[538] = (double)pe.minor_image_version;
    features[539] = (double)pe.major_linker_version;
    features[540] = (double)pe.minor_linker_version;
    features[541] = (double)pe.major_os_version;
    features[542] = (double)pe.minor_os_version;
    features[543] = (double)pe.major_subsystem_version;
    features[544] = (double)pe.minor_subsystem_version;
    features[545] = (double)pe.sizeof_code;
    features[546] = (double)pe.sizeof_headers;
    features[547] = (double)pe.sizeof_heap_commit;

    /* 6. section 1 维（entry 为字符串，float() 失败恒 0） */
    features[548] = 0.0;

    return 1;
}

/* 计算文件字节熵（用于加壳检测） */
double calc_file_entropy(const char *filepath) {
    FILE *fp = fopen(filepath, "rb");
    if (!fp) return 0.0;
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (size <= 0) { fclose(fp); return 0.0; }
    unsigned char *buf = (unsigned char *)malloc(size);
    if (!buf) { fclose(fp); return 0.0; }
    fread(buf, 1, size, fp);
    fclose(fp);
    double e = shannon_entropy(buf, size);
    free(buf);
    return e;
}

/* 内存缓冲版字节熵（流模式用） */
double calc_entropy_buf(const unsigned char *buf, long size) {
    return shannon_entropy(buf, size);
}
