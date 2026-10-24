/* scanner_api.h -- 扫描引擎 C ABI（scanner.dll）
 *
 * 设计原则：
 *   · 只暴露 C ABI，不把内部结构体/全局变量带给调用方；
 *   · 结果用固定长度字符数组，跨编译器/跨 CRT 安全；
 *   · 字符串一律 UTF-8（对外），路径同时提供宽字符入口；
 *   · 同一进程内串行扫描（内部加锁），GUI 用工作线程调用即可。
 *
 * 版本：1（2026-10-23 首个 DLL 里程碑）
 */
#ifndef SCANNER_API_H
#define SCANNER_API_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCANNER_ABI_VERSION 1

#if defined(SCANNER_BUILD_DLL)
#  define SCANNER_API __declspec(dllexport)
#elif defined(SCANNER_STATIC)
#  define SCANNER_API
#else
#  define SCANNER_API __declspec(dllimport)
#endif

/* 与 scan_main.c 内部 ScanOutcome 逐字段一致（固定布局，勿随意改序） */
typedef struct ScannerResult {
    char   bracket[48];   /* 结论： [HIGH RISK] / [SUSPICIOUS] / [NORMAL] / [TRUSTED] / [PACKED] / [SKIP] */
    char   kind[24];      /* PE / 文本脚本 / 快捷方式 / 未知 */
    char   layer[32];     /* 信任 / 特征码 / 加壳 / 模型 / 脚本启发 / LNK启发 / 缓存 / 跳过 / 错误 */
    double score;         /* 0..100；-1 表示无评分 */
    char   caro[64];      /* 检测名，可为空 */
    char   detail[512];   /* 触发规则 / 命中特征 / 签名者 / 备注 */
    char   sha[65];       /* SHA256（已知时），64 位十六进制 + 结尾 0 */
} ScannerResult;

/* 版本信息 */
SCANNER_API unsigned int scanner_abi_version(void);
SCANNER_API const char  *scanner_version(void);

/* 扫描单个文件。
 * 返回：
 *    0  已扫描（结论见 out->bracket，可能是 NORMAL/TRUSTED/PACKED/SKIP）
 *    1  参数错误
 *    2  引擎错误（特征提取失败/路径转换失败等，out->detail 有原因）
 *   -1  路径编码转换失败
 *
 * 线程安全：内部串行；可在多个线程调用，但不会并行执行。
 */
SCANNER_API int scanner_scan_file_w(const wchar_t *path, ScannerResult *out);
SCANNER_API int scanner_scan_file_u8(const char *path_utf8, ScannerResult *out);
SCANNER_API int scanner_scan_file_a(const char *path_ansi, ScannerResult *out);

/* 把 bracket 映射成机器可读等级：
 *   0=未知/错误 1=正常/可信 2=疑似 3=高危 4=加壳 5=跳过 */
SCANNER_API int scanner_result_level(const ScannerResult *r);

/* 当前已加载的外部特征库条数（不含 DLL 内置兜底表） */
SCANNER_API int scanner_signature_db_count(void);

/* 重新读取 signatures.db（返回新的外部库条数；扫描进行中调用会被串行化） */
SCANNER_API int scanner_reload_signature_db(void);

#ifdef __cplusplus
}
#endif

#endif /* SCANNER_API_H */
