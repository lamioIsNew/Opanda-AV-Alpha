/* hardware.c -- 硬件安全环境探测（任务 3）
 *
 * 1) Intel SGX : CPUID.(EAX=7,ECX=0):EBX[2]
 * 2) Intel PT  : CPUID.(EAX=7,ECX=0):EBX[25]
 * 3) TPM 2.0   : TBS API Tbsi_GetDeviceInfo()
 * 4) Hypervisor: CPUID.(EAX=1):ECX[31]
 *
 * 说明：这些结果只用于“安全性概览”展示，不参与恶意判定，
 *       也不被任何样本分析/规避逻辑使用。
 */
#define _WIN32_WINNT 0x0A00

#include <windows.h>
#include <intrin.h>
#include <tbs.h>
#include <stdio.h>
#include <string.h>

#include "hardware.h"

static void cpuid_ex(int leaf, int subleaf, int regs[4]) {
    __cpuidex(regs, leaf, subleaf);
}

static const char *tpm_iface_name(unsigned int v) {
    switch (v) {
    case TPM_IFTYPE_1:        return "I/O port / MMIO (TPM 1.2)";
    case TPM_IFTYPE_TRUSTZONE:return "TrustZone";
    case TPM_IFTYPE_HW:       return "Hardware TPM";
    case TPM_IFTYPE_EMULATOR: return "Software emulator";
    case TPM_IFTYPE_SPB:      return "SPB attached";
    default:                  return "Unknown";
    }
}

static void query_tpm(ScannerHardwareInfo *o) {
    TPM_DEVICE_INFO info;
    TBS_RESULT rc;

    memset(&info, 0, sizeof(info));
    rc = Tbsi_GetDeviceInfo((UINT32)sizeof(info), &info);
    if (rc == TBS_SUCCESS) {
        o->tpm_interface = info.tpmInterfaceType;
        if (info.tpmVersion == TPM_VERSION_20) {
            o->tpm_version = 20;
            o->tpm20 = 1;
            snprintf(o->detail, sizeof(o->detail),
                     "TBS: TPM 2.0, interface=%s", tpm_iface_name(info.tpmInterfaceType));
        } else if (info.tpmVersion == TPM_VERSION_12) {
            o->tpm_version = 12;
            o->tpm20 = 0;
            snprintf(o->detail, sizeof(o->detail),
                     "TBS: TPM 1.2, interface=%s", tpm_iface_name(info.tpmInterfaceType));
        } else {
            o->tpm_version = 0;
            o->tpm20 = 0;
            snprintf(o->detail, sizeof(o->detail),
                     "TBS: TPM version unknown (raw=%u)", (unsigned)info.tpmVersion);
        }
    } else {
        o->tpm_version = 0;
        o->tpm20 = 0;
        o->tpm_interface = TPM_IFTYPE_UNKNOWN;
        snprintf(o->detail, sizeof(o->detail),
                 "TBS: query failed (0x%08X); TPM absent, disabled, or blocked",
                 (unsigned)rc);
    }
}

int hardware_query(ScannerHardwareInfo *o) {
    int r[4];

    if (!o) return 1;
    memset(o, 0, sizeof(*o));

    /* 先确认 CPUID 最大基础 leaf，避免在老 CPU 上取到垃圾值。 */
    __cpuid(r, 0);
    if ((unsigned)r[0] >= 7) {
        cpuid_ex(7, 0, r);
        o->sgx = ((unsigned)r[1] >> 2) & 1u;   /* EBX bit 2  */
        o->pt  = ((unsigned)r[1] >> 25) & 1u;  /* EBX bit 25 */
    }

    __cpuid(r, 1);
    o->hypervisor = ((unsigned)r[2] >> 31) & 1u; /* ECX bit 31 */

    query_tpm(o);

    /* 把 CPU 侧结果追加到 detail 末尾，方便 GUI 单行展示。 */
    {
        size_t n = strlen(o->detail);
        if (n < sizeof(o->detail)) {
            snprintf(o->detail + n, sizeof(o->detail) - n,
                     " | SGX=%s PT=%s Hypervisor=%s",
                     o->sgx ? "yes" : "no",
                     o->pt ? "yes" : "no",
                     o->hypervisor ? "yes" : "no");
        }
    }
    return 0;
}
