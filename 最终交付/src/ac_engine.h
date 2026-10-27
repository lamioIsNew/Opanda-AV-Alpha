/* ac_engine.h -- Aho-Corasick 特征码自动机（纯 C，独立模块）
 *
 * 用途：为 signature_scan.c 的"逐条 memcmp"提供 O(n) 的多模式匹配后端。
 * 数据源与 signatures.db 完全一致：
 *   name \t is_hex(0/1) \t severity \t caro \t pattern
 *   · is_hex=0：pattern 是原始文本字节（按 UTF-8/ASCII 逐字节匹配，大小写敏感）
 *   · is_hex=1：pattern 是十六进制串（长度必须是偶数，最多 64 字节，与
 *     signature_scan.c 的加载上限一致）
 *
 * 本模块只负责"哪些模式命中"，不改变现有 signature_scan.c 的对外行为。
 * 需要接入时用 ac_scan_first_match() 取 DB 行序最靠前的命中下标，再回查
 * ac_pattern_name()/ac_pattern_caro()/ac_pattern_severity()，即可保持
 * "外部库优先 + first-match-wins" 的既有契约。
 *
 * 线程模型：ac_init/ac_free 不可与 ac_scan 并发；初始化完成后 ac_scan
 * 只读，可多线程并发调用。本模块不持有任何文件句柄。
 */
#ifndef AC_ENGINE_H
#define AC_ENGINE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 从 db_path 逐行加载特征并构建自动机。
 * 返回 0 成功（包括库为空）；-1 参数错误/文件打不开/内存不足/格式错误。
 * 重复调用会先释放旧自动机，再按新文件重建。
 * 失败时自动机保持为空，ac_scan 返回 0。 */
int ac_init(const char *db_path);

#ifdef _WIN32
/* 宽字符路径版（Windows）：内部用 _wfopen，支持中文/空格/`#` 路径。 */
int ac_init_w(const wchar_t *db_path);
#endif

/* 释放全部节点、模式字节与元数据。可重复调用；之后 ac_scan 返回 0。 */
void ac_free(void);

/* 是否命中任意一条特征。1=命中，0=未命中/未初始化/参数非法。 */
int ac_scan(const uint8_t *buffer, size_t size);

/* 按 signatures.db 的行序返回最早命中的模式。
 * 返回 1 命中，*out_index 写入下标（out_index 可为 NULL）；
 * 返回 0 未命中，*out_index 置 -1。 */
int ac_scan_first_match(const uint8_t *buffer, size_t size, int *out_index);

/* 适配 signature_scan_buf_ex() 的返回语义：命中时按 first-match 写出
 * 特征名、CARO 名与严重度（未命中时输出参数保持不变）。
 * 字符串缓冲区容量为 0 或指针为 NULL 时跳过该字段。 */
int ac_scan_ex(const uint8_t *buffer, size_t size,
               char *matched_name, size_t name_cap,
               int *severity, char *caro, size_t caro_cap);

/* 已加载的模式条数。 */
int ac_pattern_count(void);

/* 模式元数据；index 越界返回 NULL / -1。 */
const char *ac_pattern_name(int index);
const char *ac_pattern_caro(int index);
int ac_pattern_severity(int index);

#ifdef __cplusplus
}
#endif

#endif /* AC_ENGINE_H */
