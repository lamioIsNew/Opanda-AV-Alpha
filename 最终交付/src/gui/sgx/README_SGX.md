# SGX 密钥后端（可选，默认关闭）

## 1. 当前机器结论

- `CPUID.(EAX=7,ECX=0):EBX[2]` = **0**（SGX 不可用）。
- 未安装 Intel SGX SDK / PSW。
- 因此当前只能验证 TPM 2.0 路径；SGX 按钮在“安全设置 → 隔离密钥”中不可用。

这不是代码回退，而是硬件/工具链限制。不要在本机伪造 SGX 结果。

## 2. 代码结构

- `qtn_crypto.cpp` 默认使用 TPM 2.0（Microsoft Platform Crypto Provider）。
- `qtn_sgx_available()` 同时检查：
  1. CPUID SGX 位；
  2. 构建时是否定义 `OPANDA_WITH_SGX`；
  3. 同目录是否存在 `qtn_sgx_enclave.dll`，且导出 `QtnSgxSeal` / `QtnSgxUnseal`。
- 只有三者都满足，UI 的 SGX 选项才可用。
- 隔离文件头 `flags` 区分后端：`3=TPM`，`5=SGX`。恢复时按文件头自动选择，不依赖当前设置。

## 3. Host ↔ enclave ABI

`qtn_sgx_enclave.dll` 必须导出（`extern "C"`、`WINAPI`）：

```c
HRESULT WINAPI QtnSgxSeal(const BYTE *key, DWORD keyLen,
                          BYTE *sealed, DWORD *sealedLen);
HRESULT WINAPI QtnSgxUnseal(const BYTE *sealed, DWORD sealedLen,
                            BYTE *key, DWORD *keyLen);
```

约定：

- 第一次调用传 `sealed = NULL, *sealedLen = 0`，返回所需长度；
- 第二次调用传实际缓冲区；
- `keyLen` 固定 32 字节（AES-256）；
- 成功返回 `S_OK`。

## 4. Enclave 侧建议实现

在 EDL 中暴露：

```text
public int qtn_sgx_seal(
    [in, size=32] const uint8_t* key,
    [out, size=sealed_len] uint8_t* sealed,
    uint32_t sealed_len,
    [out] uint32_t* out_len);

public int qtn_sgx_unseal(
    [in, size=sealed_len] const uint8_t* sealed,
    uint32_t sealed_len,
    [out, size=32] uint8_t* key,
    [out] uint32_t* out_len);
```

Trusted bridge 直接调用 SGX SDK：

```c
sgx_status_t sgx_seal_data(
    uint32_t additional_MACtext_length, const uint8_t *p_additional_MACtext,
    uint32_t text2encrypt_length, const uint8_t *p_text2encrypt,
    uint32_t sealed_data_size, sgx_sealed_data_t *p_sealed_data);

sgx_status_t sgx_unseal_data(
    const sgx_sealed_data_t *p_sealed_data,
    uint8_t *p_additional_MACtext, uint32_t *p_additional_MACtext_length,
    uint8_t *p_decrypted_text, uint32_t *p_decrypted_text_length);
```

建议：

- 使用 `sgx_seal_data` 把 32 字节 AES key 封到当前 enclave；
- 保持稳定的 MRSIGNER/产品签名密钥，否则 enclave 升级后旧隔离文件可能无法解封；
- 不要把裸 AES key 从 enclave 返回到不可信 host（本设计里 host 需要 key 做 AES-GCM，属于已知折中；更高安全等级应把 AES-GCM 也放进 enclave）。

## 5. 构建步骤（需另一台支持 SGX 的机器）

1. BIOS 开启 SGX；安装 Intel SGX SDK + PSW。
2. 用 SDK 构建 enclave（`.signed.so` / Windows `.dll`），实现上面的 EDL。
3. 构建 host bridge `qtn_sgx_enclave.dll`，导出 `QtnSgxSeal/QtnSgxUnseal`。
4. 重新编译 GUI：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\build\build_gui_msvc.ps1
```

在 `build_gui_msvc.ps1` 的 `cl` 参数中加入 `/DOPANDA_WITH_SGX`。

5. 把 `qtn_sgx_enclave.dll` 放到 `ScannerUI.exe` 同目录。
6. 打开“安全设置 → 隔离密钥”，此时 SGX 按钮可用；默认仍是 TPM。

## 6. 失败语义

- SGX 不可用：`qtn_set_key_mode(1)` 返回 false，UI 保持 TPM；不会静默伪造 SGX。
- 已有 SGX 隔离文件在无 SGX 的机器上：按文件头检测为 SGX 后端，解封失败并明确报错；不会回退 TPM 解密。
- 已有 TPM 隔离文件在切换到 SGX 后仍可恢复（按文件头走 TPM）。
