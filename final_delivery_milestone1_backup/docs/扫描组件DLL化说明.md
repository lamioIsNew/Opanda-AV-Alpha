# 扫描组件 DLL 化说明（里程碑 1）

日期：2026-10-23  
产物目录：`C:\Users\17265\Desktop\恶意软件扫描器\最终交付`

## 1. 这一版做了什么

把原来只能在 `scan.exe` 里跑的扫描逻辑，原样封装成 `scanner.dll`：

- 同一个判定函数 `scan_one_file()`，CLI 与 GUI 不会出现两套结论；
- 新增 C ABI：`scanner_scan_file_w / _u8 / _a`；
- 新增统一输出出口：CLI 仍然打印原文，DLL 模式自动静默；
- 新增外部特征库 `signatures.db`（UTF-8 文本），DLL 启动后自动查找并优先使用；
- 新增 `scaler.txt` 自动查找，保证 DLL 的模型评分与 CLI 一致；
- `pe_vm` 在 DLL 模式下强制关闭，避免 GUI 进程里弹 PowerShell / 跑虚拟执行。

## 2. 交付物

| 文件 | 说明 |
| --- | --- |
| `bin\scanner.dll` | 扫描引擎（x64，673 KB） |
| `bin\scanner_test.exe` | 最小调用示例 / 自检工具 |
| `bin\sigdb_builder.exe` | 把内置特征导出为 `signatures.db` |
| `bin\scaler.txt` | 模型标准化参数（必须与 DLL 一起交付） |
| `db\signatures.db` | 外部特征库（当前 53 条） |
| `sdk\scanner_api.h` | C ABI 头文件 |
| `src\` | 可重建源码快照 |
| `build\build_scanner_dll.ps1` | PowerShell 5.1 构建脚本 |

## 3. 调用方式

```c
#include "scanner_api.h"

ScannerResult r;
int rc = scanner_scan_file_w(L"C:\\samples\\a.exe", &r);
if (rc == 0) {
    printf("%s  %.2f  %s\n", r.bracket, r.score, r.caro);
}
```

- `scanner_scan_file_w`：宽字符路径，GUI 首选；
- `scanner_scan_file_u8`：UTF-8 路径；
- `scanner_scan_file_a`：系统 ANSI 路径（兼容旧代码）；
- 返回 `0` 已扫描，`1` 参数错误，`2` 引擎错误（如缺少 `scaler.txt`），`-1` 路径转换失败；
- `scanner_result_level()`：`1=正常/可信 2=疑似 3=高危 4=加壳 5=跳过`；
- 同一进程内串行扫描（内部 `SRWLOCK`），GUI 用工作线程调用即可。

`ScannerResult` 使用固定长度字符数组，跨编译器/跨 CRT 安全；字段与引擎内部 `ScanOutcome` 完全一致。

## 4. 运行时文件查找顺序

`scanner.dll` 会按以下顺序找 `scaler.txt`：

1. DLL 同目录
2. `config\scaler.txt`
3. 上级目录
4. 上两级目录
5. 上级 `config\scaler.txt`

`signatures.db` 的查找顺序：

1. DLL 同目录
2. `db\signatures.db`
3. 上级 `db\signatures.db`
4. 上两级 `db\signatures.db`
5. `config\signatures.db`
6. 上级 `config\signatures.db`

找不到 `signatures.db` 时使用 DLL 内置兜底特征表；找不到 `scaler.txt` 时返回引擎错误，避免用错误的模型参数给出评分。

## 5. signatures.db 格式

UTF-8 文本，一行一条，制表符分隔：

```
# SCANNER_SIGDB 1
name<TAB>is_hex(0/1)<TAB>severity<TAB>caro<TAB>pattern
```

示例：

```
Phobos_VSSADMIN	0	100	Ransom.Win32.Phobos	vssadmin delete shadows
Phobos_Magic_S	1	100	Ransom.Win32.Phobos	125EA7F0
DLL_DB_SELFTEST	0	100	Test.DllDb	SCANNER_DB_SELFTEST_MARKER
```

- `is_hex=0`：`pattern` 是原始文本，可含空格，不能含制表符/换行；
- `is_hex=1`：`pattern` 是十六进制串；
- 外部库优先于内置表；删除/修改外部条目会影响结论；
- 生成初始库：`bin\sigdb_builder.exe db\signatures.db`；
- 新增特征直接编辑 `signatures.db`，DLL 下次启动生效（当前不支持热重载）。

## 6. 构建

在 `最终交付` 目录执行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\build\build_scanner_dll.ps1
```

脚本会重建 `scanner.dll`、`scanner_test.exe`、`sigdb_builder.exe`，并重新生成 `signatures.db`。  
编译器：`G:\mingw64\bin\gcc.exe`（MinGW-w64，x86_64）。

## 7. 已验证

| 用例 | 结果 |
| --- | --- |
| `notepad.exe` | `[TRUSTED]`，数字签名 Microsoft Windows |
| `666.exe` | `[NORMAL]`，模型 0.24，与 CLI 一致 |
| `scan_any.ps1` | `[SUSPICIOUS - SCRIPT]`，55 分 |
| 加壳样本（中文文件名） | `[PACKED]`，熵 7.2043 |
| `Ransom.Win32.Phobos.exe` | `[HIGH RISK - SIGNATURE]`，100 分，`Ransom.Win32.Phobos` |
| 外部库唯一标记测试 | 命中 `DLL_DB_SELFTEST`，证明 db 生效 |
| 缺少 scaler.txt | 返回 2，明确提示，不用错误参数打分 |

CLI 兼容性：同一份源码重建的 `scan_cli_test.exe` 与旧 `scan.exe` 在 `notepad.exe`、`666.exe` 上逐字一致；加壳样本仅因可执行文件所在目录不同，`pe_vm` 联动路径不同。

## 8. 已知限制（诚实版）

1. 当前 DLL 是 **串行扫描**，不是线程池；GUI 需要自己排队。
2. 路径入口最终转系统 ANSI（GBK）；Windows 11 开启“UTF-8 全局代码页”时也兼容，但建议 GUI 用 `scanner_scan_file_w`。
3. 只导出单文件扫描；目录递归、进度回调、取消接口下一版再加。
4. `pe_vm` 在 DLL 模式强制关闭；虚拟执行仍只作为独立实验工具。
5. `signatures.db` 目前是文本格式，不是 SQLite；后续迁移时 ABI 不变。
6. 内置特征表仍保留作兜底；外部库删除某条时，内置表可能仍命中。等 db 稳定后再移除内置表。
7. 仅提供 x64 DLL；32 位需单独构建。
8. 未做代码签名；正式交付前建议 Authenticode 签名。

## 9. 下一步

1. GUI：Win32 + Direct2D/DirectWrite 自绘（大圆角卡片、柔和阴影、毛玻璃、深浅色、侧边导航、过渡动画）。
2. DLL：目录扫描 / 异步任务 / 取消 / 进度回调。
3. 特征库：编辑、版本号、热重载；必要时迁 SQLite。
4. 服务化 + 驱动执行端（强杀/强删/自保护）。
