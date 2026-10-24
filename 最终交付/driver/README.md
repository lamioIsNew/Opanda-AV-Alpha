# Opanda HIPS Driver（测试用内核执行端）

> 仅用于独立 VM + 测试签名 + 可回滚快照。**绝不在宿主机加载未签名驱动。**

## 1. 能力

| IOCTL | 作用 | 关键实现 |
| --- | --- | --- |
| `HIPS_IOCTL_QUERY_VERSION` | 返回驱动版本 | `HIPS_VERSION_INFO` |
| `HIPS_IOCTL_TERMINATE_PROCESS` | 强制结束进程 | `ZwOpenProcess` + `ZwTerminateProcess` |
| `HIPS_IOCTL_DELETE_FILE` | 强制删除文件 | `ZwDeleteFile`，失败后 `FILE_DISPOSITION_INFORMATION_EX` + POSIX 语义 |

设备：

```text
\Device\HipsDriver
\DosDevices\HipsDriver
用户态：\\.\HipsDriver
```

设备 ACL：

```text
D:P(A;;GA;;;SY)
```

只有 `SYSTEM` 可以打开设备；管理员直接运行客户端会被拒绝，必须通过计划任务/服务以 SYSTEM 运行。

## 2. 构建

前置：VS BuildTools + WDK 10.0.26100（`km\wdm.h`、`ntoskrnl.lib`、`wdmsec.lib`）。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\build_driver_msvc.ps1
```

产物：

```text
HipsDriver.sys
HipsClient.exe
HipsTestTarget.exe
```

## 3. 测试签名

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\sign_test_driver.ps1
```

脚本会：

1. 在当前用户证书库创建/复用 `CN=Opanda Test Driver` 代码签名证书；
2. 导出 `OpandaTest.pfx` / `OpandaTest.cer`；
3. 用 `signtool` 对 `HipsDriver.sys` 做 SHA256 签名。

私钥 `.pfx` 和公钥 `.cer` 已被 `.gitignore` 排除，不会进入仓库。

## 4. VM 安装

VM 要求：

- Secure Boot **关闭**；
- 允许测试签名；
- 有可回滚快照；
- 已关闭共享文件夹、拖放、剪贴板、网络、VMCI（按项目安全要求）。

以管理员身份：

```bat
bcdedit /set testsigning on
certutil -addstore -f Root OpandaTest.cer
certutil -addstore -f TrustedPublisher OpandaTest.cer
copy /Y HipsDriver.sys %SystemRoot%\System32\drivers\
sc create HipsDriver type= kernel start= demand binPath= %SystemRoot%\System32\drivers\HipsDriver.sys
sc start HipsDriver
```

如果 `sc start` 返回 577/1275，重启后再启动。

## 5. 用户态调用

```bat
:: 必须以 SYSTEM 运行
HipsClient.exe version
HipsClient.exe kill <pid>
HipsClient.exe delete <win32-or-nt-path>
HipsClient.exe selftest
```

`HipsTestTarget.exe` 是良性测试目标：创建并映射一个测试文件，保持 10 分钟，供删除/结束进程测试。

## 6. 限制（诚实版）

1. **PPL / 受保护进程**：`ZwTerminateProcess` 会返回权限错误，驱动不会绕过 PPL。
2. **被其他进程独占打开的文件**：如果目标句柄不允许 `FILE_SHARE_DELETE`，`ZwOpenFile` 会返回共享冲突；驱动不会枚举/关闭任意进程句柄。
3. **被映射的文件**：优先使用 POSIX disposition，通常可以立即 unlink；已存在的映射仍可继续访问，直到最后一个句柄关闭。
4. **不做**：任意内核读写、任意进程内存读写、句柄枚举、SSDT/Hook、自保护、实时监控。
5. 设备 ACL 为 SYSTEM-only；没有给 Administrators 留后门。
6. 生产分发需要 WHQL/attestation 签名；测试证书只用于 VM。
