/* hardware.h -- CPUID / TBS 硬件安全环境探测（任务 3）
 *
 * 只读探测，不修改系统状态，不参与扫描判定。
 */
#ifndef SCANNER_HARDWARE_H
#define SCANNER_HARDWARE_H

#include "scanner_api.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 填充 out；调用方负责清零。返回 0 成功。 */
int hardware_query(ScannerHardwareInfo *out);

#ifdef __cplusplus
}
#endif

#endif /* SCANNER_HARDWARE_H */
