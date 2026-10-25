# ScannerUI.exe（WD 风格极简 GUI）

版本：`1.1.0-night-20261025`  
构建：MSVC x64（VS BuildTools 18 + Windows SDK 10.0.26100）  
引擎：`scanner.dll`（ABI 1，含硬件检测附加导出）

## 1. 技术栈

- Win32 原生窗口，Direct2D 绘制，DirectWrite 文字；
- 无第三方 UI 框架，单文件自绘；
- Per-Monitor V2 DPI awareness（manifest 编译进 EXE）；
- Windows 11 通过 `DWMWA_WINDOW_CORNER_PREFERENCE` 设置原生圆角；失败静默回退；
- 全局只使用黑/白/灰，跟随系统浅色/深色，可在设置中手动切换；
- 左侧图标使用 Segoe Fluent Icons（失败回退 Segoe MDL2 Assets）字体字形，不自绘图标；
- 通过 `LoadLibraryW` 加载同目录 `scanner.dll`，UI 线程不阻塞；
- 目录扫描先在后台线程枚举文件，再用最多 16 个 worker 并发调用 `scanner_scan_file_w`；
- 基准（良性 System32，500 文件 / 174.5 MB）：1 线程 7.14 s，16 线程 1.07 s，约 6.7x，结果计数一致。

## 2. 页面（仅 5 项）

| 页面 | 内容 |
| --- | --- |
| 安全性概览 | 引擎状态、快速扫描、病毒库/隔离区/历史统计、硬件环境检测、最近活动 |
| 病毒和威胁防护 | 快速扫描、选择文件/文件夹、停止、结果列表、隔离选中、打开位置、清空 |
| 隔离区 | 恢复选中、永久删除、刷新；显示隔离时间、原路径、结论、检测名 |
| 保护历史记录 | 扫描历史、刷新、清空、打开日志目录 |
| 安全设置 | 主题、动画、最大扫描文件、病毒库重载、数据目录、内核执行端状态、关于 |

“驱动与内核”不再单独占菜单；驱动状态放在“安全设置”中展示。

## 3. 硬件环境检测（任务 3）

“安全性概览”卡片展示：

| 项目 | 来源 |
| --- | --- |
| Intel SGX | `CPUID.(EAX=7,ECX=0):EBX[2]` |
| Intel PT | `CPUID.(EAX=7,ECX=0):EBX[25]` |
| TPM 2.0 | TBS `Tbsi_GetDeviceInfo()` |
| 虚拟化环境 | `CPUID.(EAX=1):ECX[31]` |

结果只用于安全态势展示，不参与扫描判定，也不用于规避分析。

## 4. 启动参数

```bat
ScannerUI.exe
ScannerUI.exe --scan "C:\path\to\file-or-folder"
ScannerUI.exe --page overview
ScannerUI.exe --page protection
ScannerUI.exe --page quarantine
ScannerUI.exe --page history
ScannerUI.exe --page settings
```

兼容旧别名：`scan` → protection，`logs` → history，`driver` → settings。

## 5. 数据目录

GUI 以自身 EXE 所在目录为数据目录：

```text
bin/
  config/settings.ini        主题、动画、最大文件大小等
  logs/history.tsv           扫描历史（UTF-8，制表符分隔）
  quarantine/index.tsv       隔离索引
  quarantine/<时间>_<文件名>.qtn   隔离文件（AES-256-GCM，TPM/SGX 封装密钥）
```

## 6. 隔离文件格式

新格式 `QTNA`：

```text
0..3    "QTNA"
4..7    version = 2
8..11   flags: bit0=AES-256-GCM, bit1=TPM-RSA-OAEP, bit2=SGX-sealed
12..23  nonce (12)
24..39  GCM tag (16)
40..47  original_size (uint64)
48..51  wrapped_len
52..55  reserved
56..    wrapped key (TPM RSA-2048 密文，或 SGX sealed blob)
之后     AES-256-GCM 密文
```

- 默认 TPM 2.0：每个文件随机生成 AES-256 数据密钥，用 TPM 内持久化 RSA-2048 公钥做 RSA-OAEP(SHA-256) 封装；私钥不出 TPM。
- SGX 可选、**默认关闭**：只有 `CPUID.7:EBX[2]=1`、构建时定义 `OPANDA_WITH_SGX`、且存在 `qtn_sgx_enclave.dll` 导出 `QtnSgxSeal/QtnSgxUnseal` 时才可用。
- 旧 `QTN1`（XOR 0x5A）仍可恢复；已有文件按文件头自动选择 TPM/SGX 解密。
- TPM 键名 `OpandaQtnKey`；TPM 被清除或键被删除后，已有隔离文件不可恢复。
- 单文件上限 512 MB。

## 7. 构建

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\build\build_gui_msvc.ps1
```

前置：`bin\scanner.dll`、`bin\scaler.txt`、`db\signatures.db` 存在。构建前请关闭正在运行的 GUI。

## 8. 已知限制

- 无安装程序、无开机自启、无托盘常驻；
- 无实时监控、无服务；驱动执行端为独立测试组件，GUI 不加载；
- 无自动隔离（仅手动）；
- 未做 Authenticode 签名；
- 仅 x64。
