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
- 通过 `LoadLibraryW` 加载同目录 `scanner.dll`，工作线程调用扫描，UI 线程不阻塞。

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
  quarantine/<时间>_<文件名>.qtn   隔离文件（QTN1 轻量加密）
```

## 6. 隔离文件格式（任务 5）

```text
0..3    "QTN1"
4..7    version = 1
8..11   flags   = 1 (XOR 0x5A)
12..19  original_size (uint64)
20..31  reserved (0)
32..    原始文件逐字节 XOR 0x5A
```

- 新隔离文件写入前加密，恢复时自动解密；
- 旧版明文 `.qtn` 仍可恢复（按魔数自动识别）；
- XOR 只是**轻量混淆**，不是密码学加密；敏感环境请配合 BitLocker/EFS。

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
