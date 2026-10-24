/* scan_output.h -- 扫描引擎统一输出出口
 *
 * CLI 模式：默认写到 stdout，逐字保持原有排版；
 * DLL 模式：由 scanner_api.c 关闭，避免 GUI 进程里无控制台时浪费 I/O。
 */
#ifndef SCAN_OUTPUT_H
#define SCAN_OUTPUT_H

#ifdef __cplusplus
extern "C" {
#endif

void scan_out(const char *fmt, ...);
void scan_out_set_enabled(int enabled);
int  scan_out_enabled(void);

#ifdef __cplusplus
}
#endif

#endif /* SCAN_OUTPUT_H */
