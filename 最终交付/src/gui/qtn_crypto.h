/* qtn_crypto.h -- QTN 隔离文件加密（AES-256-GCM + TPM 封装密钥）
 *
 * 新格式 QTNA：
 *   magic "QTNA" + version 2 + flags（3=TPM, 5=SGX）
 *   12B nonce + 16B GCM tag + 8B original_size
 *   wrapped_len + TPM(RSA-OAEP-SHA256) 或 SGX sealed blob
 *   AES-256-GCM 密文
 *
 * 旧格式 QTN1（XOR 0x5A）仍可解密，用于兼容已有隔离项。
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

/* 加密/解密单个文件（不含移动/删除）。 */
bool qtn_encrypt_file(const std::wstring &src, const std::wstring &dst, std::wstring &err);
bool qtn_decrypt_file(const std::wstring &src, const std::wstring &dst, std::wstring &err);

/* 隔离：加密 -> 生成 .qtn -> 删除原文件；失败回滚。 */
bool qtn_quarantine_file(const std::wstring &src, const std::wstring &stored, std::wstring &err);

/* 恢复：QTNA/QTN1 解密 -> 原路径；旧明文 .qtn 直接移动。 */
bool qtn_restore_file(const std::wstring &stored, const std::wstring &original, std::wstring &err);

#endif /* QTN_CRYPTO_H */
