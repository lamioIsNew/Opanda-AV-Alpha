# scanner.dll（C ABI）说明

版本：`1.0.0-dll-20261023`  
ABI：`1`  
平台：Windows 10/11 x64

## 1. 设计

- 复用 CLI 的同一个 `scan_one_file()`，GUI、DLL、CLI 不会出现两套判定；
- 只暴露 C ABI 和固定长度字符数组，跨编译器/跨 CRT 安全；
- 同一进程内串行扫描（内部 `SRWLOCK`）；GUI 使用工作线程排队调用；
- DLL 模式关闭控制台输出与 `pe_vm` 联动，静态扫描绝不执行样本；
- `ScannerResult` 与引擎内部 `ScanOutcome` 字段顺序一致。

## 2. 导出函数

```c
unsigned int scanner_abi_version(void);
const char  *scanner_version(void);
int          scanner_scan_file_w(const wchar_t *path, ScannerResult *out);
int          scanner_scan_file_u8(const char *path_utf8, ScannerResult *out);
int          scanner_scan_file_a(const char *path_ansi, ScannerResult *out);
int          scanner_result_level(const ScannerResult *r);
int          scanner_signature_db_count(void);
int          scanner_reload_signature_db(void);
```

返回码：

| 返回值 | 含义 |
| --- | --- |
| `0` | 扫描完成，`out` 已填充 |
| `1` | 参数错误 |
| `2` | 引擎错误（常见：缺少 `scaler.txt`，或结果为空） |
| `-1` | 路径编码转换失败 |

`scanner_result_level()`：

| 值 | 含义 |
| --- | --- |
| `1` | 正常 / 可信 |
| `2` | 疑似 |
| `3` | 高危 |
| `4` | 加壳 |
| `5` | 跳过 |
| `0` | 未知 / 错误 / 空结果 |

## 3. ScannerResult

```c
typedef struct ScannerResult {
    char   bracket[48];   /* [HIGH RISK ...] / [SUSPICIOUS ...] / [NORMAL] ... */
    char   kind[24];      /* PE / 文本脚本 / 快捷方式 / 未知 */
    char   layer[32];     /* 信任 / 特征码 / 加壳 / 模型 / 脚本启发 / ... */
    double score;         /* 0..100；-1 表示无评分 */
    char   caro[64];      /* 检测名 */
    char   detail[512];   /* 触发规则 / 命中特征 / 签名者 / 备注 */
    char   sha[65];       /* SHA256 小写十六进制；未计算时为空 */
} ScannerResult;
```

字符串一律 UTF-8，固定长度、以 `\0` 结尾。`sha` 在特征码命中、加壳、脚本/模型等路径会尽量填充；可信文件可能为空。

## 4. 运行时文件查找

`scanner.dll` 以自身目录为基准：

`scaler.txt`：

1. `bin\scaler.txt`
2. `bin\config\scaler.txt`
3. `bin\..\scaler.txt`
4. `bin\..\..\scaler.txt`
5. `bin\..\config\scaler.txt`
6. `bin\..\..\config\scaler.txt`

`signatures.db`：

1. `bin\signatures.db`
2. `bin\db\signatures.db`
3. `bin\..\db\signatures.db`
4. `bin\..\..\db\signatures.db`
5. `bin\config\signatures.db`
6. `bin\..\config\signatures.db`

找不到外部 `signatures.db` 时使用 DLL 内置兜底特征表；找不到 `scaler.txt` 时返回 `2`，避免用错误模型参数给出评分。

## 5. signatures.db 格式

UTF-8 文本，一行一条，制表符分隔：

```text
# SCANNER_SIGDB 1
name<TAB>is_hex(0/1)<TAB>severity<TAB>caro<TAB>pattern
```

示例：

```text
Phobos_VSSADMIN	0	100	Ransom.Win32.Phobos	vssadmin delete shadows
Phobos_Magic_S	1	100	Ransom.Win32.Phobos	125EA7F0
```

- `is_hex=0`：原始文本，可含空格，不能含制表符/换行；
- `is_hex=1`：十六进制串；
- 外部库优先于内置表；
- 当前共 **53 条**；
- GUI“设置 → 重新加载”或 API `scanner_reload_signature_db()` 可热重载；
- 重新运行 `sigdb_builder.exe db\signatures.db` 会按内置表重新生成，手工添加的条目需另存。

## 6. 构建

在交付根目录：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\build\build_scanner_dll.ps1
```

脚本重建：

- `bin\scanner.dll`
- `bin\scanner_test.exe`
- `bin\sigdb_builder.exe`
- `db\signatures.db`
- `bin\scaler.txt`

编译器默认 `G:\mingw64\bin\gcc.exe`；找不到时回退 PATH 中的 `gcc`。构建前请关闭正在使用 DLL 的 GUI。

## 7. 已知限制（诚实版）

1. DLL 是**串行扫描**，不是线程池；GUI 需要自己排队。
2. 宽字符入口最终转系统 ANSI（GBK）；Windows 11 开启 UTF-8 全局代码页时也兼容；GUI 使用 `scanner_scan_file_w`。
3. 只导出单文件扫描；目录递归、进度回调、取消接口由调用方实现（GUI 已实现）。
4. `pe_vm` 在 DLL 模式强制关闭；虚拟执行仍只作为独立实验工具。
5. `signatures.db` 是文本格式，不是 SQLite；后续迁移时 ABI 不变。
6. 内置特征表保留作兜底；删除外部库条目时，内置表可能仍命中。
7. 仅提供 x64 DLL；32 位需单独构建。
8. 未做代码签名；正式交付前建议 Authenticode 签名。
9. 未实现服务化、实时文件监控、进程保护与驱动执行端。
