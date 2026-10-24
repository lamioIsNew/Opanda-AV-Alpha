# ScannerUI.exe（WD 风格 GUI）

## 1. 技术栈

- Win32 原生窗口，Direct2D 绘制，DirectWrite 文字；
- 无第三方 UI 框架，单文件自绘；
- Per-Monitor V2 DPI awareness（manifest 编译进 EXE）；
- 伪毛玻璃/渐变背景；Windows 11 尝试圆角与 Mica/Acrylic，失败静默回退；
- 深浅色主题、跟随系统、平滑过渡；
- 通过 `LoadLibraryW` 加载同目录 `scanner.dll`，工作线程调用扫描，UI 线程不阻塞。

## 2. 页面

| 页面 | 内容 |
| --- | --- |
| 主页 | 状态、快速扫描、防护摘要、最近记录 |
| 扫描 | 选择文件/文件夹、快速扫描、进度、结果列表、隔离、打开位置 |
| 防护 | 当前为手动扫描模式；实时保护/行为监控/驱动/计划扫描均标注未启用 |
| 隔离区 | 恢复选中、删除选中（二次确认）、刷新；显示隔离时间、原路径、结论、检测名 |
| 日志 | 扫描历史、刷新、清空、打开日志目录 |
| 驱动与内核 | 服务状态、能力边界、未安装原因；不含未签名驱动 |
| 设置 | 主题、动画、最大文件大小、病毒库重载、打开数据目录、数据与边界 |

## 3. 启动参数

```bat
ScannerUI.exe
ScannerUI.exe --scan "C:\path\to\file-or-folder"
ScannerUI.exe --page scan
ScannerUI.exe --page protection
ScannerUI.exe --page quarantine
ScannerUI.exe --page logs
ScannerUI.exe --page driver
ScannerUI.exe --page settings
```

`--scan` 会直接开始扫描并切到扫描页；`--page` 用于测试/集成。

## 4. 数据目录

GUI 以自身 EXE 所在目录为数据目录：

```text
bin/
  config/settings.ini        主题、动画、最大文件大小等
  logs/history.tsv           扫描历史（UTF-8，制表符分隔）
  quarantine/index.tsv       隔离索引
  quarantine/<时间>_<文件名>.qtn 隔离文件（按原文件保存，扩展名改为 .qtn）
```

设置页“打开数据目录”可直接打开；日志页“打开日志目录”打开 `logs`。

## 5. 交互与键盘

- 点击结果行选中；扫描结束后自动选中最高等级结果；
- 扫描页右侧按钮：隔离选中、打开位置、清空；
- 隔离区删除会弹出系统确认框，确认后不可恢复；
- `Esc`：停止扫描；`F5`：刷新驱动状态与病毒库计数；
- 支持把文件拖入窗口（取第一个文件）；
- 窗口最小约 1000 × 640 DIPs，按 DPI 实际缩放。

## 6. 目录扫描与限制

- 递归扫描，跳过重解析点/符号链接；
- 跳过系统缓存、WinSxS、Installer、`node_modules`、`.git` 等目录；
- 跳过自身文件（`scanner.dll`、`ScannerUI.exe`、`signatures.db`、日志/索引等）；
- 超过设置页“最大扫描文件”的文件直接跳过，不读入内存；
- 扫描线程串行调用 DLL；点击“停止扫描”后，已完成条目仍保留；
- 关闭窗口时会取消扫描并等待工作线程结束，避免在 DLL 仍被使用时卸载。

## 7. 已知限制

- 无安装程序、无开机自启、无托盘常驻；
- 无实时监控、无服务、无驱动执行端；
- 隔离文件当前未加密；
- 无自动隔离（仅手动）；
- 未做 Authenticode 签名；
- 32 位系统不支持（DLL/EXE 均为 x64）。
