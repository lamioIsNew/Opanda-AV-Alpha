/* qtn_crypto.h -- QTN 隔离文件加密（AES-256-GCM + TPM 封装密钥）
 *
 * 新格式 QTNA v3（流式）：
 *   magic "QTNA" + version 3 + flags（3=TPM, 5=SGX, 9=DPAPI 降级）
 *   8B nonce 盐 + 8B 保留 + 8B original_size + wrapped_len + chunk_size(65536)
 *   TPM(RSA-OAEP-SHA256) / SGX sealed blob / DPAPI blob
 *   之后按 64 KB 分块：[密文块][16B GCM tag]，块 nonce = 盐 || 块序号
 *
 * v2（单 nonce 一次性 GCM）与旧 QTN1（XOR 0x5A）仍可解密，用于兼容已有隔离项。
 * 加密与解密均为恒定 64 KB 内存占用；明文 AES 密钥与 CNG 密钥对象锁页并强制清零。
 * AES 密钥/盐优先取 TPM 2.0 RNG，无 TPM 时回退系统 RNG 并记录；无 TPM 时
 * 密钥封装自动降级 DPAPI（当前用户作用域）。
 */
#ifndef QTN_CRYPTO_H
#define QTN_CRYPTO_H

#include <string>

/* 密钥后端：0=TPM 2.0（默认），1=SGX（实验，需 CPU 支持 + SGX enclave 后端）。 */
bool qtn_set_key_mode(int mode);
int  qtn_get_key_mode(void);
bool qtn_sgx_cpu_support(void);   /* 仅检查 CPUID.7:EBX[2] */
bool qtn_sgx_available(void);     /* CPUID + 编译开关 + enclave DLL */

bool qtn_is_encrypted(const std::wstring &path);

/* 加密/解密单个文件（不含移动/删除）。
 * 注意：加密成功时 err 可能包含非致命诊断（TPM RNG 回退 / DPAPI 降级），
 * 调用方应只在返回 false 时把 err 当作错误展示。 */
bool qtn_encrypt_file(const std::wstring &src, const std::wstring &dst, std::wstring &err);
bool qtn_decrypt_file(const std::wstring &src, const std::wstring &dst, std::wstring &err);

/* 隔离：加密 -> 生成 .qtn -> 删除原文件；失败回滚。 */
bool qtn_quarantine_file(const std::wstring &src, const std::wstring &stored, std::wstring &err);

/* 恢复：QTNA/QTN1 解密 -> 原路径；旧明文 .qtn 直接移动。 */
bool qtn_restore_file(const std::wstring &stored, const std::wstring &original, std::wstring &err);

#endif /* QTN_CRYPTO_H */
