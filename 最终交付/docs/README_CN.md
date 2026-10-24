# 恶意软件扫描器 · 交付说明

版本：`1.1.0-night-20261025`  
平台：Windows 10/11 x64  
交付日期：2026-10-25

## 1. 这是什么

这是一套**静态**恶意软件扫描器：

- `scanner.dll`：扫描引擎，C ABI，供 GUI 或其他程序调用；
- `db/signatures.db`：外部特征库（当前 53 条），优先级高于 DLL 内置兜底表；
- `ScannerUI.exe`：Win32 + Direct2D/DirectWrite 自绘的 WD 风格极简 GUI（5 页、纯灰阶）；
- `scanner_test.exe`：最小调用示例 / 自检工具；
- `sigdb_builder.exe`：把内置特征导出为 `signatures.db` 的工具；
- `src/hardware.c`：SGX / PT / TPM 2.0 / Hypervisor 硬件检测；
- `driver/`：可选的 HIPS 内核执行端源码（测试签名、仅 VM）；
- `tests/vm/`：VM 隔离测试脚本与只读 ISO 生成脚本；
- `src/`、`sdk/`、`build/`：源码、头文件、MSVC 重建脚本。

**扫描过程中绝不执行样本。** `pe_vm` 在 DLL 模式强制关闭；GUI 只调用单文件静态扫描接口。

## 2. 快速开始

双击根目录的 `start_gui.cmd`，或直接运行：

```text
bin\ScannerUI.exe
```

启动后：

1. 点“选择文件”或“选择文件夹”；
2. 点“快速扫描”；
3. 高危/疑似结果可以“隔离选中”或“打开位置”；
4. 左侧“隔离区”可恢复或永久删除；左侧“保护历史记录”查看历史；
5. “安全性概览”的“硬件环境检测”卡片展示 SGX / PT / TPM 2.0 / 虚拟化环境。

命令行自检：

```bat
cd bin
scanner_test.exe "C:\path\to\sample.exe"
```

预期输出包含 `dll=1.0.0-dll-20261023 abi=1 db=53`。

## 3. 目录结构

```text
MalwareScanner_Release/
  start_gui.cmd              GUI 启动器（GBK + CRLF）
  VERSION.txt                版本与交付内容
  SHA256SUMS.txt             文件校验值
  bin/
    ScannerUI.exe            WD 风格 GUI
    scanner.dll              扫描引擎（x64）
    scanner_test.exe         最小调用示例
    sigdb_builder.exe        特征库导出工具
    scaler.txt               模型标准化参数
  db/
    signatures.db            外部特征库（53 条，UTF-8 文本）
  sdk/
    scanner_api.h            C ABI 头文件
  src/                       可重建源码快照
    gui/                     GUI 源码、manifest、资源脚本
  build/
    build_scanner_msvc.ps1   重建 scanner.dll（MSVC）
    build_gui_msvc.ps1       重建 ScannerUI.exe（MSVC）
    build_all.ps1            依次重建
    build_scanner_dll.ps1    旧 MinGW 脚本（参考）
    build_gui.ps1            旧 MinGW 脚本（参考）
  driver/                    可选 HIPS 驱动源码、客户端、INF、构建/签名脚本
  tests/vm/                  VM 隔离测试脚本、只读 ISO 生成脚本
  docs/
    SCANNER_DLL.md           DLL ABI、特征库格式、构建
    GUI.md                   GUI 页面、参数、数据目录
    TEST_REPORT.md           验证记录
    DRIVER_BOUNDARY.md       驱动/服务边界说明
```

## 4. 已验证结果

| 样本/场景 | 结果 |
| --- | --- |
| `666.exe` | `[NORMAL]`，模型评分 0.24 |
| `Ransom.Win32.Phobos.exe` | `[HIGH RISK - SIGNATURE]`，100 分，`Ransom.Win32.Phobos` |
| `notepad.exe`（微软签名） | `[TRUSTED]`，-1 |
| `scan_any.ps1` | `[SUSPICIOUS - SCRIPT]`，55 分，`Trojan.Script.Dropper` |
| 中文路径 / 中文文件名 | 正常扫描与隔离 |
| 文件夹递归 + 取消 | 正常；取消后显示“扫描已停止” |
| 隔离 → 恢复 | 正常，原路径恢复，SHA256 写入索引 |
| 深浅色 / 跟随系统 | 正常切换并持久化 |
| 缺少 `scanner.dll` | 启动时明确提示，不静默失败 |
| MSVC x64 构建 | `scanner.dll` / `ScannerUI.exe` / `HipsDriver.sys` / `pe_vm_msvc.exe` 均编译通过 |
| 隔离文件 | QTN1 头 + XOR 0x5A；旧明文 `.qtn` 兼容 |

## 5. 安全边界（重要）

- **静态扫描不等于沙箱行为分析**；不执行、不调试、不注入样本。
- 加壳文件显示 `[PACKED]`，不直接判恶意；`pe_vm` 不在 DLL 中运行。
- 隔离区是**用户主动操作**：文件被移动到 `quarantine/`，使用 QTN1 轻量加密（XOR 0x5A）；索引为 `quarantine/index.tsv`。XOR 只是混淆，不是密码学加密；敏感环境请配合 BitLocker/EFS。
- GUI 不安装驱动、不注册服务、不常驻监控；实时拦截、自保护未启用。
- `driver/` 提供可选的 HIPS 内核执行端源码与测试签名脚本，**只允许在 VM + 测试签名 + 快照**中加载；生产分发需要 WHQL/attestation 签名。
- 驱动能力边界：普通进程可结束，PPL/受保护进程受系统限制；被独占打开的文件可能只能返回共享冲突；不提供任意内核读写。
- 正式分发前请对 `ScannerUI.exe`、`scanner.dll` 做 Authenticode 签名；当前包未签名。
- 不要在生产机直接双击未知样本测试；请使用隔离虚拟机。

## 6. 常见问题

**Q：提示“无法加载扫描引擎”？**  
确认 `bin\scanner.dll` 与 `ScannerUI.exe` 同目录，且 `bin\scaler.txt` 存在。

**Q：病毒库显示 0 或不是 53？**  
确认 `db\signatures.db` 存在。GUI 会在 `bin`、`bin\db`、`..\db` 等位置查找；也可在“设置”里点“重新加载”。

**Q：日志/隔离区在哪里？**  
默认在 `bin\logs\history.tsv`、`bin\quarantine\`、`bin\config\settings.ini`。设置页有“打开数据目录”。

**Q：为什么没有实时防护？**  
当前交付静态扫描 + 极简 GUI；`driver/` 只是可选的测试用执行端，不注册服务、不做实时监控。实时防护仍需要用户态服务 + minifilter，见 `docs/DRIVER_BOUNDARY.md`。

**Q：能扫描大于 256 MB 的文件吗？**  
设置页可调最大文件大小；超过限制的文件会跳过并计入“跳过”，不会读入内存。
