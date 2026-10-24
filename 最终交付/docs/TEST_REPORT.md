# 验证记录（2026-10-24）

环境：Windows 10/11 x64 测试机，1920×1080，DPI 144；MinGW-w64 x64。

## 1. 引擎（scanner.dll）

| 用例 | 结果 |
| --- | --- |
| `666.exe` | `rc=0 level=1`，`[NORMAL]`，`score=0.24` |
| `Ransom.Win32.Phobos.exe` | `rc=0 level=3`，`[HIGH RISK - SIGNATURE]`，100，`Ransom.Win32.Phobos`，SHA256 `b93fcbaf...dd86` |
| `notepad.exe` | `rc=0 level=1`，`[TRUSTED]`，`score=-1` |
| `scan_any.ps1` | `rc=0 level=2`，`[SUSPICIOUS - SCRIPT]`，55，`Trojan.Script.Dropper` |
| 中文路径/中文文件名 | 正常，无乱码 |
| 外部 `signatures.db` | 自动加载，`db=53`；自检标记可命中 |
| 缺少 `scaler.txt` | 返回 `2`，提示明确 |
| ABI 版本 | `scanner_abi_version()=1` |

## 2. GUI 功能

| 用例 | 结果 |
| --- | --- |
| `--scan` 单文件（666 / Phobos） | 结果等级、分数、颜色、检测名与 DLL 一致 |
| 文件夹递归（4 个文件） | 高危 1、疑似 1、正常 2；列表滚动正常 |
| 取消扫描（1200 个文件） | 点击停止后显示“扫描已停止：已扫描 93 个文件” |
| 结果自动选中 | 扫描结束后选最高等级项，“隔离选中”可用 |
| 隔离 | 文件移动到 `quarantine/`，索引写入 SHA256、结论、检测名 |
| 恢复 | 原路径恢复，索引清空 |
| 日志 | 历史写入 `logs/history.tsv`；刷新/清空/打开目录正常 |
| 主题 | 跟随系统、浅色、深色切换正常；设置持久化 |
| 设置 | 最大文件大小 64/128/256/512 MB 切换；病毒库重载；打开数据目录 |
| 防护/驱动页 | 明确显示未启用/未安装；无未签名驱动 |
| 最小窗口/DPI | 1000×640 DIPs 最小；PerMonitorV2；鼠标命中按 DPI 转换 |
| 无 DLL 启动 | 弹出“无法加载扫描引擎”，不创建主窗口 |

## 3. 兼容性说明

- GUI 与 DLL 使用同一份 `scan_one_file()` 源码，666 分数与 CLI 一致；
- `pe_vm` 在 DLL 模式关闭，GUI 进程不会启动 PowerShell/虚拟执行；
- 隔离恢复时若原位置已有同名文件，会拒绝覆盖；
- 删除隔离项前有系统确认框。

## 4. 交付校验

- `scanner.dll`、`scanner_test.exe`、`ScannerUI.exe`、`sigdb_builder.exe`、`signatures.db`、`scaler.txt` 的 SHA256 见根目录 `SHA256SUMS.txt`；
- 交付目录内文件名为 ASCII；启动器为 GBK + CRLF；文档/脚本为 UTF-8 BOM；
- 所有测试样本来自本地样本集，未在生产环境执行。

## 5. 未覆盖/限制

- 未在 Windows 10 21H2 以下版本验证 Mica/Acrylic（失败会回退）；
- 未做大规模目录性能基准；
- 未实现实时监控、服务、驱动执行端、自动更新、安装包；
- 未做代码签名。
