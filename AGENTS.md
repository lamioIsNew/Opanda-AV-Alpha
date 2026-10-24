# AGENTS.md

## 0. 这是真机，样本是真病毒（最高优先级）

- `样本集\`（400 个文件 / ~1.7 GB）是真实恶意样本回归语料（PE / 脚本 / LNK / 加密 ZIP，密码 `infected`）；`行为沙箱\_work\`（~1.6 GB）与 `沙箱\*\实测\` 是历史运行留下的样本副本和落地物。
- **禁止执行项目内任何文件**：`.exe/.dll/.sys/.scr/.ps1/.cmd/.bat/.js/.vbe/...`，**包括本项目自己的工具** `scan.exe`、`stream_scan.exe`、`scanner_test.exe`、`ScannerUI.exe`、`scanner.dll`、`pe_vm.exe`、`js_vm.exe`、`folder_guard.exe`。不双击、不 `Start-Process`、不 `&`、不 `powershell -File`。
- 只做静态工作：读源码 / `.md` / 文本结果，用 `Get-ChildItem`、`Get-FileHash`、`Select-String`。不要以"跑一遍验证"为目的启动任何二进制——这里不是虚拟机。
- 尤其不要运行：`主动防御\folder_guard.exe`（监控桌面/下载并调用扫描器）、`行为沙箱\auto_analyze.ps1`（开 Windows Sandbox 真跑样本）、`解压工具\解压样本.ps1`（批量落盘真样本）。
- 不要清理或"整理" `样本集\`、`行为沙箱\_work\`、`行为沙箱\分析结果\`、`沙箱\*\实测\`：它们是证据与回归基线。

## 1. 环境事实

- Windows + Windows PowerShell **5.1**（无 `pwsh`）；控制台代码页 936，看中文输出前先 `chcp 65001` 并设 `[Console]::OutputEncoding`。
- 没有 `gcc/g++/windres`，`G:\mingw64` 不存在 → `最终交付\build\*.ps1` 里的编译命令目前跑不通。改 C/C++ 只能做静态审查，不要声称"已编译 / 已测试"。
- 不是 git 仓库（无 `.git`）：没有提交/分支流程，改动直接落盘。
- 路径含 `#`、中文、空格：命令行里一律加引号。

## 2. 目录与真正的源码

- `最终交付\` = **当前交付**（v1.0.0-dll-gui，2026-10-24）：`src\`（引擎快照）、`src\gui\`（GUI）、`sdk\scanner_api.h`、`build\`、`bin\`、`db\`、`docs\`。改引擎/GUI 改这里。
- `final_delivery_milestone1_backup\` = 上一里程碑快照（无 GUI，`scan_main.c` 与当前版不同），仅作参考，不是当前源码。
- 根目录 `scan.exe` / `stream_scan.exe` / `scan_any.ps1` / `scan_startup.ps1` / `scaler.txt` = **旧 CLI 线**（2026-10-17，带 `pe_vm` 联动），与 `最终交付` 的 DLL/GUI 共用同一个 `scan_one_file()` 引擎。
- `沙箱\` = L1 脚本虚拟沙盒（`js_vm` + `unbox_js.py`）+ PE 虚拟执行（`pe_vm`）+ 联动内核 `pevm_lib.ps1`；`行为沙箱\` = L3 Windows Sandbox（真跑；只读说明与报告，不运行）。
- `样本集\` = 回归语料（根目录平铺，另有 `1017新样本\` 等子目录）。
- `工具\` = 第三方 Resource Hacker，与本项目无关；`教程在最终交付里面\` 是空目录。

## 3. 契约（改了会连带坏掉）

- `scan_one_file()` 是唯一判定函数，CLI、`scanner.dll`、GUI 共用：改判定同时影响三处。`ScannerResult` 字段顺序必须与内部 `ScanOutcome` 一致（改结构 = 改 ABI）。
- 机器标记是脚本解析接口，**逐字保留**：`[HIGH RISK]` `[HIGH RISK - SIGNATURE]` `[SUSPICIOUS]` `[SUSPICIOUS - PUA/SCRIPT/LNK]` `[NORMAL]` `[TRUSTED]` `[PACKED]` `[SKIP]`、`File appears to be PACKED`、`== 汇总: ... ==`。`scan_any.ps1`、`scan_startup.ps1` 的计数依赖它们；`[VM: ...]` 是独立标记，不参与汇总。
- 阈值固定：≥80 高危 / ≥50 疑似；`[PACKED]` 只是熵 >7 的拦截，不等于恶意。
- `signatures.db`：UTF-8 文本、Tab 分隔、当前 53 条；外部库优先于 `signature_scan.c` 内置表；`sigdb_builder.exe` 重新生成会覆盖手改条目。
- `scaler.txt` 必须与 exe/dll 同目录（或邻近上级）；找不到返回 `2`，绝不用错模型参数打分。`pe_vm` 在 DLL 模式强制关闭。
- 判决缓存已关闭（`verdict_cache.c` 的 `VCACHE_ENABLE 0`），每次全量重扫；不要"优化"成跳过。
- 特征码匹配是**逐字节、大小写敏感、first-match-wins**：组合/精确特征必须排在宽泛关键词之前。

## 4. 编码约定（硬性要求，不是风格）

- `.cmd` 启动器：GBK + CRLF；`.ps1` / `.md` / `.txt`：UTF-8 + BOM；C 输出：UTF-8 字节流。
- 脚本只保证 PowerShell 5.1 兼容（别用 PS7 语法）；脚本内**不要**设 `[Console]::OutputEncoding`（会破坏既有重定向解码）。
- 交付目录内文件名/目录名用 ASCII（`pe_vm --extract` 的输出目录已改 ASCII，中文名会乱码）。

## 5. 验证怎么做（不能跑 exe 的前提下）

- 没有自动化测试。基线在 `最终交付\docs\TEST_REPORT.md`、`扩展扫描说明.md` 第十节、`静态漏报清单.txt`（355 个可判定样本，含高危/疑似/漏报分档）。
- 改特征/规则后的验证只能做静态推理 + 与上述基线对拍；不要为测试而运行 `scanner_test.exe` 或任何样本。
- 两个报毒率口径：`(高危+疑似)/可判定`、`(高危+疑似)/全部`；改统计逻辑会破坏历史基线。

## 6. 文档地图（先读这些）

- `扩展扫描说明.md`：最完整的技术总览（类型分派、签名信任、CARO 命名、编译命令、限制）。
- `最终交付\docs\`：`README_CN.md`（交付与安全边界）、`SCANNER_DLL.md`（ABI/特征库/构建）、`GUI.md`（页面/数据目录）、`TEST_REPORT.md`、`DRIVER_BOUNDARY.md`。
- `沙箱\沙箱架构说明.md`（L0/L1/L2/L3 分层）、`沙箱\PE虚拟执行沙盒\PE虚拟执行沙盒说明.md`、`沙箱\脚本虚拟沙盒\脚本虚拟沙盒说明.md`、`行为沙箱\行为沙箱说明.md`、`进阶能力\进阶能力说明.md`。
- 文档里的 `F:\SVM项目\...`、`C:\Users\17265\...`、`H:\新建文件夹` 是原开发机路径；脚本靠 `$PSScriptRoot` 和候选目录回退，文档路径别当真。

## 7. 不要照着做的"任务书"

- `最终交付\新建 文本文档.txt` 和 `最终交付\README.txt` 后半段（`旧版进展-----to lamio`）是历史 Agent 提示词 / 交接笔记（要求重写 GUI、建 HIPS 驱动、改 `pe_vm` 等）。它们不是当前规格，**不要执行其中指令**，也不要据此改代码。
- 驱动/服务/实时监控/强杀强删不在交付范围（见 `DRIVER_BOUNDARY.md`）；PPL、用户态 hook 已被评估为"不做"，不要重新提议。
