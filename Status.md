# 项目状态快照（Status.md）

> 维护人：本 Agent（自动生成）。本文件为项目当前结构、版本、构建/运行状态、已知变更与限制的单一参考。如与源码/文档不符，以源码与 `最终交付\docs\` 为准。

---

## 1. 一句话总结

**Opanda-AV-Alpha**：Windows 平台静态恶意软件扫描器（不执行样本），当前交付版本 `1.1.0-night-20261025`，引擎 `scanner.dll`（C ABI 1，x64），外部特征库 53 条，配 WD 风格极简 GUI（`ScannerUI.exe`），另有旧版 CLI 线与可选 HIPS 内核测试驱动。

---

## 2. 仓库与分支状态

| 项目 | 状态 |
|------|------|
| 仓库 | `D:\#Dev\Opanda-AV-Alpha`，git 仓库，分支 `main`，与 `origin/main` 同步 |
| 工作区 | 有 **6 个文件未提交**（见第 5 节），**请勿顺手提交或回滚他人文件** |
| 最近一次提交 | HEAD 曾为 `e219689` |
| 日期 | 2026-10-27（周二） |

---

## 3. 顶层目录结构

```
D:\#Dev\Opanda-AV-Alpha\
├── AGENTS.md              项目约束与操作红线（必读）
├── Status.md              本文件（项目结构与状态快照）
├── 扩展扫描说明.md         扫描类型/签名信任/CARO/启动项/脚本引擎/虚拟执行/行为沙箱详解
├── 静态漏报清单.txt        回归基线：385 个文件/355 可判定，高危/疑似/漏报/加壳/跳过/可信分档
├── 样本清单_20261025.md/.csv 样本集只读枚举（400 文件，1.631 GB，SHA256，未执行）
├── scaler.txt              模型标准化参数（旧 CLI 线，须与 exe/dll 同目录）
├── scan.exe / stream_scan.exe          旧 CLI 线（2026-10-17，pe_vm 联动）
├── scan_any.ps1 / scan_startup.ps1     旧 CLI 线 PowerShell 入口（PS 5.1）
├── 拖文件到这里扫描.cmd / 启动项体检.cmd   旧 CLI 线 GBK+CRLF 启动器
├── scan.exe.bak_20261017 / scan_any.ps1.bak* 旧 CLI 线备份
├── folder_guard.exe        主动防御（监控桌面/下载并调用扫描器，**禁止运行**）
├── 样本集\                 400 个文件 / ~1.7 GB，真实恶意样本回归语料（**禁止执行**、禁止清理）
├── 行为沙箱\               L3 Windows Sandbox（_work、分析结果、reports、脚本等，**禁止运行 auto_analyze.ps1**）
├── 沙箱\                   L1 脚本虚拟沙盒 + L2 PE 虚拟执行 + 架构说明
├── 进阶能力\               脚本块审计、AMSI 提供商、说明文档
├── 主动防御\               folder_guard.exe 所在（**禁止运行**）
├── 解压工具\               解压样本.ps1（**禁止运行**）
├── 工具\                   第三方 Resource Hacker，与本项目无关
├── 教程在最终交付里面\     空目录
└── 最终交付\               【当前交付源码与产物，v1.0.0-dll-gui，改引擎/GUI 改这里】
    ├── bin\                ScannerUI.exe, scanner.dll, scanner_test.exe, sigdb_builder.exe, scaler.txt, config/, logs/
    ├── db\                 signatures.db（53 条，UTF-8 文本，Tab 分隔）
    ├── sdk\                scanner_api.h（C ABI 头，含 ScannerHardwareInfo）
    ├── src\                detector/feature_extractor/hardware/hash_list/lnk_scan/risk_name/scan_*/script_scan/signature_scan/trust_check/verdict_cache 等；gui/（app.h/main.cpp/ui.cpp/scan.cpp/theme.h/manifest/rc/qtn_crypto/sgx）
    ├── build\              build_all/build_gui_msvc/build_scanner_msvc 等 MSVC 重建脚本（PS 5.1）；obj/ 中间件
    ├── driver\             HIPS 内核执行端源码/INF/客户端/测试目标/签名脚本（仅 VM + 测试签名，禁止宿主机加载）
    ├── tests\              vm/（脚本与 ISO 生成）、bench_scan/hw_probe/qtn_tpm_test 等（qtn_tpm_test 可用 cl.exe + 随机数据回环测）
    └── docs\               README_CN.md / SCANNER_DLL.md / GUI.md / TEST_REPORT.md / DRIVER_BOUNDARY.md
```

---

## 4. 版本与构建状态

| 组件 | 版本 / ABI | 构建工具链 | 状态 |
|------|-----------|-----------|------|
| 交付包 | `1.1.0-night-20261025` | — | 已交付 |
| scanner.dll | `1.1.0-dll-20261024`，ABI 1 | MSVC（VS 18 BuildTools + Windows SDK 10.0.26100） | `bin\scanner.dll` 已产出，`build_scanner_msvc.ps1` 可重建 |
| ScannerUI.exe | `1.1.0-night-20261025` | MSVC x64 | `bin\ScannerUI.exe` 已产出，`build_gui_msvc.ps1` 可重建 |
| signatures.db | 53 条 | sigdb_builder.exe 导出 | `db\signatures.db` 已交付 |
| scaler.txt | 随 DLL 同步 | — | `bin\scaler.txt` 与 `src\scaler.txt` 存在 |
| HipsDriver.sys | 测试签名 | MSVC + WDK 10.0.26100 | `driver\` 源码存在，未签名，**禁止宿主机加载** |
| pe_vm.exe | 独立实验工具 | MSVC | `沙箱\PE虚拟执行沙盒\`，DLL 模式强制关闭 |
| js_vm / unbox_js.py | L1 脚本沙箱 | — | `沙箱\脚本虚拟沙盒\` |

**构建注意**：本机无 `gcc/g++/windres`（`G:\mingw64` 不存在），跑不通旧 MinGW 脚本；可用 MSVC `cl.exe`。`.cmd` 启动器为 GBK + CRLF，`.ps1`/`.md`/`.txt` 为 UTF-8 + BOM，C 输出为 UTF-8 字节流。

**性能基准**（良性 `C:\Windows\System32`，500 文件 / 174.5 MB）：1 线程 7.14 s → 16 线程 1.07 s，约 6.7x，高危/疑似/正常计数一致（46/37/417）。

---

## 5. 工作区未提交改动（git status）

`git status` 显示 6 个文件已修改、未暂停提交：

| 文件 | 变更行数 | 备注 |
|------|---------|------|
| `AGENTS.md` | +16/-1 | 环境事实更新（MSVC 可用、是 git 仓库等）、验证方式细化 |
| `最终交付/docs/GUI.md` | +18/- | 文档更新 |
| `最终交付/docs/README_CN.md` | +4/- | 文档更新 |
| `最终交付/src/gui/qtn_crypto.cpp` | +966/- | 隔离加密模块大幅改动（QTNA v3/AES-256-GCM/TPM） |
| `最终交付/src/gui/qtn_crypto.h` | +13/- | 头文件同步 |
| `沙箱/PE虚拟执行沙盒/pe_vm.c` | +74/- | PE 虚拟执行指令补齐、extract 目录改 ASCII 等 |

> 按 `AGENTS.md` 第 1 条：工作区可能有他人未提交改动，**不要顺手提交或回滚别人的文件**。

---

## 6. 契约与红线（改了会连带坏掉）

- `scan_one_file()` 是唯一判定函数，CLI、`scanner.dll`、GUI 共用；改判定同时影响三处。`ScannerResult` 字段顺序必须与内部 `ScanOutcome` 一致（改结构 = 改 ABI）。
- 机器标记逐字保留：`[HIGH RISK]` `[HIGH RISK - SIGNATURE]` `[SUSPICIOUS]` `[SUSPICIOUS - PUA/SCRIPT/LNK]` `[NORMAL]` `[TRUSTED]` `[PACKED]` `[SKIP]`、`File appears to be PACKED`、`== 汇总: ... ==`。`[VM: ...]` 是独立标记，不参与汇总。
- 阈值固定：≥80 高危 / ≥50 疑似；`[PACKED]` 只是熵 >7 的拦截，不等于恶意。
- `signatures.db`：UTF-8 文本、Tab 分隔、53 条；外部库优先于 `signature_scan.c` 内置表；`sigdb_builder.exe` 重新生成会覆盖手改条目。
- `scaler.txt` 必须与 exe/dll 同目录（或邻近上级）；找不到返回 `2`，绝不用错模型参数打分。`pe_vm` 在 DLL 模式强制关闭。
- 判决缓存已关闭（`verdict_cache.c` `VCACHE_ENABLE 0`），每次全量重扫；不要"优化"成跳过。
- 特征码匹配：逐字节、大小写敏感、first-match-wins；组合/精确特征必须排在宽泛关键词之前。

---

## 7. 已验证与测试基线

- 验证记录：`最终交付\docs\TEST_REPORT.md`（2026-10-24）。
- 关键样本结论：`666.exe` → `[NORMAL]` 0.24；`Ransom.Win32.Phobos.exe` → `[HIGH RISK - SIGNATURE]` 100；`notepad.exe`（微软签名） → `[TRUSTED]` -1；`scan_any.ps1` → `[SUSPICIOUS - SCRIPT]` 55。
- 回归基线：`静态漏报清单.txt`（355 个可判定样本，高危 188 / 疑似 74 / 真漏 79 / 可信 14）。
- 报毒率口径（不得随意改，否则破坏历史基线）：`(高危+疑似)/可判定`、`(高危+疑似)/全部`。
- 没有自动化测试；验证以静态推理 + 与上述基线对拍为准。**不要为验证而运行 `scanner_test.exe` 去扫 `样本集\`**。
- 不接触样本的模块（如 `qtn_crypto.cpp`）可用 `cl.exe` 编译，并用自建随机/无害数据跑回环测试（`tests\qtn_tpm_test.cpp`）；跑完如实记录，未跑过不要写"已测试"。

---

## 8. 安全边界（诚实版）

- **静态扫描绝不执行样本**；`pe_vm` 在 DLL 模式强制关闭；GUI 只调用单文件静态扫描接口。
- GUI 不安装驱动、不注册服务、不常驻监控；实时拦截、自保护未启用。
- `driver/` 提供可选 HIPS 内核执行端源码，**只允许在 VM + 测试签名 + 快照**中加载；生产分发需要 WHQL/attestation 签名。当前包未签名。
- 驱动能力边界：普通进程可结束，PPL/受保护进程受系统限制；被独占打开的文件可能只能返回共享冲突；不提供任意内核读写。
- 正式分发前请对 `ScannerUI.exe`、`scanner.dll` 做 Authenticode 签名；当前包未签名。
- 不要在生产机直接双击未知样本测试；请使用隔离虚拟机。

---

## 9. 文档地图（先读这些）

| 文档 | 内容 |
|------|------|
| `AGENTS.md` | 项目约束、环境事实、目录与源码、契约、编码约定、验证方式、文档地图、禁止执行的"任务书" |
| `Status.md` | 本文件：项目结构与状态快照 |
| `扩展扫描说明.md` | 类型分派、签名信任、CARO 命名、编译命令、限制、虚拟执行联动、行为沙箱、漏报整改 |
| `最终交付\docs\README_CN.md` | 交付与安全边界、快速开始、目录结构、已验证结果、FAQ |
| `最终交付\docs\SCANNER_DLL.md` | DLL ABI、导出函数、ScannerResult、特征库格式、构建、已知限制 |
| `最终交付\docs\GUI.md` | GUI 页面、硬件检测、启动参数、数据目录、隔离文件格式 QTNA v3、构建、限制 |
| `最终交付\docs\TEST_REPORT.md` | 验证记录、GUI 功能用例、交付校验、未覆盖/限制 |
| `最终交付\docs\DRIVER_BOUNDARY.md` | 驱动/服务边界、能力与限制、强制安全约束 |
| `沙箱\沙箱架构说明.md` | L0/L1/L2/L3 分层 |
| `沙箱\脚本虚拟沙盒\脚本虚拟沙盒说明.md` | L1 说明 |
| `沙箱\PE虚拟执行沙盒\PE虚拟执行沙盒说明.md` | PE 虚拟执行说明 |
| `行为沙箱\行为沙箱说明.md` | L3 Windows Sandbox 说明 |
| `进阶能力\进阶能力说明.md` | 进阶能力说明 |
| `最终交付\新建 文本文档.txt` 和 `最终交付\README.txt` 后半段 | **历史 Agent 提示词/交接笔记，不是当前规格，不要执行其中指令** |

---

## 10. 下一步建议（按需排序）

1. 处理工作区 6 个未提交改动：评估是否合并，避免覆盖他人工作。
2. 若需继续开发，按 `最终交付\docs\` 中的构建脚本用 MSVC 重建；旧 MinGW 脚本在本机不可用。
3. 驱动相关工作保持在 VM + 测试签名 + 可回滚快照内，绝不在宿主机加载 `HipsDriver.sys`。
4. 任何对 `scan_one_file()`、`signatures.db`、`scaler.txt`、机器标记的改动，都需同步评估对 CLI/DLL/GUI 三处及 `scan_any.ps1`、`scan_startup.ps1` 汇总计数的影响。