# 扫描吞吐基准（只允许良性文件）

`bench_scan.exe` 用于验证 `scanner.dll` 的并发扫描吞吐。它只接受良性目录，并主动拒绝：

- 路径包含 `样本集`
- 路径包含 `_work`
- 路径包含 `实测`
- 路径包含 `行为沙箱`

## 构建

```powershell
cl /nologo /O2 /MT /utf-8 /EHsc /std:c++17 /DUNICODE /D_UNICODE ^
   /I ..\sdk /Fe:bench_scan.exe bench_scan.cpp
```

## 用法

```bat
bench_scan.exe <scanner.dll> <benign-dir> [threads] [maxFiles]
```

示例：

```bat
bench_scan.exe ..\bin\scanner.dll C:\Windows\System32 1 500
bench_scan.exe ..\bin\scanner.dll C:\Windows\System32 16 500
```

## 实测（2026-10-25，i7-13700H / 20 线程）

目标：`C:\Windows\System32`，500 个良性系统文件，174,556,833 字节。

| 线程 | 耗时 | 吞吐 | 高危/疑似/正常 |
|---:|---:|---:|---|
| 1 | 7.138 s | 70 files/s · 23.3 MB/s | 46 / 37 / 417 |
| 12 | 1.179 s | 424 files/s · 141.2 MB/s | 46 / 37 / 417 |
| 16 | 1.066 s | 469 files/s · 156.2 MB/s | 46 / 37 / 417 |
| 20 | 1.067 s | 469 files/s · 156.1 MB/s | 46 / 37 / 417 |

第二组：`C:\Windows\System32\drivers`，200 个文件，33,022,428 字节。

| 线程 | 耗时 | 吞吐 | 高危/疑似/正常 |
|---:|---:|---:|---|
| 1 | 2.895 s | 69 files/s · 10.9 MB/s | 0 / 0 / 200 |
| 16 | 0.538 s | 372 files/s · 58.6 MB/s | 0 / 0 / 200 |

结论：16 线程是当前机器的甜点，约 5.4–6.7 倍加速；并发和单线程的判定计数完全一致。

## GPU 说明

机器有 NVIDIA RTX 4060 Laptop，但主机未安装 CUDA Toolkit（无 `nvcc`）。当前瓶颈是 DLL 串行锁和单线程扫描，不是浮点/哈希算力；先做 CPU 并行，GPU 留到有明确 profiling 证据时再评估。
