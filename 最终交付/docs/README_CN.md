# 恶意软件扫描器 · 交付说明

版本：`1.0.0-dll-gui-20261024`  
平台：Windows 10/11 x64  
交付日期：2026-10-24

## 1. 这是什么

这是一套**静态**恶意软件扫描器：

- `scanner.dll`：扫描引擎，C ABI，供 GUI 或其他程序调用；
- `db/signatures.db`：外部特征库（当前 53 条），优先级高于 DLL 内置兜底表；
- `ScannerUI.exe`：Win32 + Direct2D/DirectWrite 自绘的 WD 风格 GUI；
- `scanner_test.exe`：最小调用示例 / 自检工具；
- `sigdb_builder.exe`：把内置特征导出为 `signatures.db` 的工具；
- `src/`、`sdk/`、`build/`：源码、头文件、重建脚本。

**扫描过程中绝不执行样本。** `pe_vm` 在 DLL 模式强制关闭；GUI 只调用单文件静态扫描接口。

## 2. 快速开始

双击根目录的 `start_gui.cmd`，或直接运行：

```text
bin\ScannerUI.exe
```

启动后：

1. 点“选择文件”或“选择文件夹”；
2. 点“开始扫描”；
3. 高危/疑似结果可以“隔离选中”或“打开位置”；
4. 左侧“隔离区”可恢复或永久删除；左侧“日志”查看历史。

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
    build_scanner_dll.ps1    重建 DLL / 测试程序 / 特征库
    build_gui.ps1            重建 GUI
    build_all.ps1            依次重建
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

## 5. 安全边界（重要）

- **静态扫描不等于沙箱行为分析**；不执行、不调试、不注入样本。
- 加壳文件显示 `[PACKED]`，不直接判恶意；`pe_vm` 不在 DLL 中运行。
- 隔离区是**用户主动操作**：文件被移动到 `quarantine/`，当前版本按原文件保存并改为 `.qtn` 扩展名，未加密；索引为 `quarantine/index.tsv`。请把交付目录放在受控账户/目录下。
- 当前不安装驱动、不注册服务、不常驻监控；因此实时拦截、强杀、强删、自保护均未启用。
- 驱动执行端需要 WHQL/attestation 签名和 minifilter altitude，由交付方/使用方自行完成签名与测试；本包不包含未签名驱动二进制。
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
当前里程碑只交付静态扫描 + GUI；实时防护需要服务与驱动，见 `docs/DRIVER_BOUNDARY.md`。

**Q：能扫描大于 256 MB 的文件吗？**  
设置页可调最大文件大小；超过限制的文件会跳过并计入“跳过”，不会读入内存。
