# PE 虚拟执行沙盒（pe_vm）— 阶段一 + 阶段二

> **方向声明（重要）**：本项目**不走 Hyper-V / 虚拟机**路线。
> 依据 `火绒“脚本行为沙盒”简介.pdf`，脚本类与 PE 类样本统一到**用户态虚拟执行**：
> 指令由本进程内的解释器逐条执行，内存访问全部校验，Windows API 全部是"假实现"，
> 与真实系统**零接触**——因此不存在"漏洞脚本穿透"的问题（这正是火绒文档第 7 页强调的架构优势）。
> E 盘已有的两台 Hyper-V 分析机**保持原状、不启用**（宿主 8GB 内存 + Defender 不健康，开 VM 有风险）。

程序形态：`pe_vm.exe`（MinGW-w64 静态编译，纯 C，无第三方依赖，PS 无关，可直接命令行调用）。

> 当前构建：**2026-10-23**（10-18 基线：x86-64 解释器上线、API 表第三轮、空转检测；10-22/10-23 修补：
> 假 API 语义修复（CRT 初始化用的 `InitializeCriticalSectionEx`、`GetProcessHeap` 等返回 0 导致样本自毁）、
> `GetStartupInfo` 写越界、x64 PEB `ProcessParameters`、自身文件只读虚拟化、PyInstaller 解包所需安全描述符 API）。
> `pe_vm.exe` SHA256 `5EFB6864B507BA7CDA74630A5128D052019E6BABC4246296FA011FA8BFCA7DAF`（304,385 字节）
> `pe_vm.c`   SHA256 `0561C88EDE3A8E3A6D988896D16D5A552FA74777F3E13F779578ED49FCFE8B42`（289,978 字节）

---

## 一、火绒文档关键结论 → 我们的落地

| 文档要点 | 落地方式 |
| --- | --- |
| 混淆成本低，静态特征必然失效，只能靠"动态虚拟执行"还原 | 静态引擎（`scan.exe`）只做 L0 选靶，真正的还原交给虚拟执行 |
| 主流做法＝引擎内嵌脚本解释器 + 有限模拟（作者指出两大缺陷：可被穿透、仿真度低） | 不引入真解释器宿主；JS 侧用 `jscript.dll` 但**不提供任何真宿主对象** |
| 火绒做法＝把**脚本问题转成 PE 问题**，宿主建在自家虚拟内核上，执行完全隔离 | 统一为"虚拟执行沙盒"：脚本走 `js_vm`，PE 走 `pe_vm`，都在自家虚拟机内 |
| 能还原"外层脚本释放 PE → PE 执行完"的完整链路 | 阶段一＝静态释放体还原；阶段二＝x86-32 / x86-64 解释器真正把壳跑开 |

---

## 二、阶段一（已实现并实测）：虚拟装载 / 导入表虚拟化 / 释放体还原

### 1. 虚拟内存（安全底座）
- 4GB 地址空间，**4KB 惰性分页**（与 PE 节对齐），每页带 `R/W/X` 保护位与"是否被写过"标记。
- 所有访问走 `vm_read / vm_write`：未映射读取被拒、只读页写入被拒（自检已证）。
- 样本再怎么越界/自改，也只能打到自己进程内的虚拟页，**不可能碰到宿主真实内存**。

### 2. PE 装载器
- 解析 DOS/NT/可选头/节表；PE32 完整装载，PE32+ 正确识别。
- 实测（只解析、不执行）：`1.exe` 镜像仅 0x8000 → 2MB 全在 overlay；`3.exe` 导入 `mscoree.dll!_CorExeMain`（.NET）；`…9e9ffe160.sys` PE32+ 驱动，`.data` 虚拟 0xC3560 原始 0；`libcef.dll` 正常 DLL。

### 3. 导入表虚拟化（全假 API）
- 每个导入函数分配"假 API 桩"（`0x7F000000` 起，每条 16 字节），IAT 改写指向桩；桩反查表存 `dll!函数名`。

### 4. 静态释放体还原（`--extract`）
对样本集 **108 个 PE**（52 exe / 24 dll / 30 sys / 2 scr）全量运行：
- 抠出释放体 **79 个**；结构自洽的内嵌 **PE32/PE64 共 12 个**（含**驱动套驱动**：`FLTMGR.SYS` / `ntoskrnl.exe` 导入）；
- overlay 最大 131 MB，熵 8.00 / 7.99 → 加密载荷或压缩壳；
- 释放体直接交 `scan.exe` 复扫，**新增检出**（旧引擎只统计 `MZ` 次数、不还原，故均为新增面）：

| 释放体 | 判定 | 说明 |
| --- | --- | --- |
| `njRAT_释放体\01_PE32_off0x539.bin` | `[HIGH RISK - SIGNATURE]` 100.00 | 风险名 **njRAT_Artifact**（家族级命中） |
| `njRAT_释放体\02_PE32_off0xE0D3E.bin` | `[HIGH RISK]` 97.49 | 同类载荷（变体特征） |
| `dump1_释放体\01_PE32_off0x293F.bin` | `[SUSPICIOUS]` 76.28 | 待人工确认 |
| `deepseek…_x64_释放体\04/05_PE32_*` | `[PACKED]` | 内层仍是壳，可再交阶段二脱壳 |

> 阶段二改动后已回归验证：上述释放体**偏移/长度/判定完全一致**（见 `实测\回归_释放体复扫.csv`）。

---

## 三、阶段二：x86-32 + x86-64 解释器 + 全虚拟 API + 行为还原

### 1. 执行模型
`fetch → decode → execute` 三段式，全部跑在虚拟内存上：
- **CPU 状态**：`EAX ECX EDX EBX ESP EBP ESI EDI` + `EIP` + `EFLAGS`（CF/PF/AF/ZF/SF/IF/DF/OF 全部真算，含 add/adc/sub/sbb/logic/shift 的正确进位与溢出）；支持 `0x66/0x67/F2/F3/段前缀/lock`。
- **译码**：完整 ModRM/SIB/disp8/disp32 与段基址（`fs:`/`gs:`）计算。
- **护栏**：取指越界、未映射读写、除零、栈越界都会**安全停机并如实报告**，绝不会跑飞。
- **预算**：`--max-insn`（默认 4000 万条）+ `--max-sec`（默认 30 秒）双保险；联动脚本按 3000 万条 / 60 秒跑（`-PevmMaxInsn` / `-PevmMaxSec` 可调）。

### 2. 指令覆盖（按解壳常用度排序）
| 组 | 覆盖内容 |
| --- | --- |
| 数据传送 | `mov`(全部 6 种形态)、`movsx/movzx`、`lea`、`xchg`、`mov moffs`、`bswap`、`xlat` 类 |
| 算术/逻辑 | `add/or/adc/sbb/and/sub/xor/cmp`（r/m↔r、累加器、group1 imm8/imm32）、`test`、`inc/dec`、`not/neg/mul/imul/div/idiv`、`imul` 双操作数与三操作数 |
| 移位 | `shl/shr/sar/rol/ror/rcl/rcr`（含 CL 与 imm8 两种）、`shld/shrd` |
| 位操作 | `bt/bts/btr/btc`、`bsf/bsr`、`cmpxchg`、`xadd` |
| 栈/帧 | `push/pop`(r/m/imm)、`pushad/popad`、`pushfd/popfd`、`enter/leave`、`mov sreg`、段寄存器 push/pop |
| 流程 | `call/jmp`（rel8/rel32、r/m、间接）、`ret/retn`、`jcc`(16 种)、`loop/loope/loopne/jecxz`、`cmovcc`、`setcc` |
| 串操作 | `movs/stos/lods/scas/cmps` + `rep/repne`（DF 方向） |
| 系统/杂项 | `cpuid`、`rdtsc`、`nop/lea nop`、`sahf/lahf`、`cbw/cwde/cdq`、`daa/das/aaa/aas`、`aam/aad`（BCD 调整，混淆壳常拿它藏字节） |
| 标志位控制 | `clc/stc/cmc`（清/置/翻转 CF）、`cld/std`（串操作方向，必须真实现）、`cli/sti`（虚拟环境无中断，改 IF 即可） |
| x87 浮点 | 8 层 FPU 栈；`fld/fst/fstp/fild/fist/fistp`、实数/整数四则、`fld1/fldz/fldpi`、`fabs/fchs/fsqrt/fsin/fcos`、`fnstsw ax/fninit` 等 |
| SSE | XMM×8；`movups/movaps/movdqa/movdqu/movlps/movhps/movd/movq`、`xorps/andps/orps/nandps`、`pxor/padd/psub`、`addps/mulps/subps/divps/sqrtps`、`pshufd/shufps`、`cvtsi2sd/cvttsd2si/cvtdq2ps`、`comiss/ucomiss/movmskps` |
| 反分析指令 | `in/out`（按"非虚拟机"假返回）、`icebp`（跳过）、`int3/int/hlt/ud2`（如实停机） |

> 解壳 stub 里最常见的 `mov/lea/push/pop/jcc/call/ret/rep movs/xor/add/子串/shift` 已全部可用；
> 现代编译器产物需要的 `cmovcc/setcc/bt 族/shld-shrd/sse` 也已补齐（这是本批样本能否跑通的关键）。

### 3. 全虚拟 API（只记录行为，绝不真调用）
- 覆盖 **150+ 函数**：内存（`VirtualAlloc/Protect/Free/Query`、堆 `HeapAlloc` 等）、模块与动态解析（`LoadLibrary*/GetProcAddress/GetModuleHandle*`）、文件（`CreateFile/WriteFile/ReadFile/GetFileSize`）、注册表（`RegCreateKeyEx/RegSetValueEx/RegQueryValueEx`）、进程（`CreateProcess/WinExec/ShellExecute`）、网络（`URLDownloadToFile/InternetOpenUrl/InternetConnect/WinHttpConnect/socket/connect`）、反调试（`IsDebuggerPresent/CheckRemoteDebuggerPresent/NtQueryInformationProcess`）、环境（`GetTickCount/QueryPerformanceCounter/GetSystemInfo/GlobalMemoryStatus/GetVersion`）、CRT 辅助（`lstrlen/memcpy/memset/RtlZeroMemory`）。
- **参数个数表**是关键：stdcall 参数个数错一个就会栈错位、`ret` 跑飞（早期实测已踩到 `InitializeCriticalSection` 这个坑）。未登记的函数按 0 参数处理并明确记录"栈可能错位"。
- 环境伪装：`PEB->ImageBaseAddress` 填真实镜像基址、`BeingDebugged=0`、`NtGlobalFlag=0`、`GetTickCount` 递增、内存/版本信息合理；`GetModuleHandle("")` 返回镜像基址。

### 4. 行为记录与"落地物"
- 中文行为日志（`API 调用次数` + 逐条），`--trace` 输出 TSV（`API/文件/注册表/网络/执行/落盘/DUMP/STOP`），可直接喂给报表或 `auto_analyze.ps1`。
- **虚拟文件系统**：样本 `CreateFile+WriteFile` 写出来的文件全部留在内存里（从未碰真盘），运行结束导出为 `落地_<文件名>`——这就是"释放的载荷"。
- **写后执行（OEP）检测**：页级"被写过 + 变为可执行"即判定为疑似 OEP（`VirtualProtect` 改成可执行、或执行流进入已写过的可执行页），自动 dump 该区域。
- 结束前还会**扫描整个虚拟内存找内嵌 PE**（`MZ` + 合法 `PE\0\0` + 节表自洽）并落盘。

### 5. 线程环境（让壳能跑起来）
- 栈 1MB、`ESP` 顶部压**返回哨兵** `0x7FFFFFF0`：样本从入口 `ret` 回来即干净收场；
- 合成 `TEB/PEB/Ldr`：`fs:[0x30]`→PEB、`PEB+0x08`→镜像基址、`PEB+0x02`→BeingDebugged=0、`PEB+0x68`→NtGlobalFlag=0。

### 6. 解释器自检（`--selftest`，全部通过）
不跑真实样本，用手写机器码验证行为：
- 循环累加 → `EDX=0x5B05B058`（期望一致）；
- 内存写后读回、内存真实被写；
- **写后执行被检出**（疑似 OEP 命中 1 次）→ 跳进去的假载荷被执行（`EAX=0x41414141`）→ 返回哨兵生效；
- 加上阶段一的虚拟分配/未映射拒绝/只读拒绝/桩复用与反查。

### 7. 全量实测（样本集 114 个 PE，预算 300 万条 / 3 秒）
| 取向 | 数量 | 说明 |
| --- | --- | --- |
| PE32+（x64）跳过 | 65 | 需 x64 解释器，本轮仅静态视图 |
| **已虚拟执行** | **35** | 计划内真实运行，累计 **18,318,517 条指令** |
| .NET 程序集 | 12 | 入口即 `mscoree.dll!_CorExeMain`，如实标注"需 IL 分析" |
| 非法/空文件 | 2 | 含 1 个 0 字节的 `zhuru.dll`（样本集本身的问题，值得记录） |

- 其中 **6 个**跑到指令上限仍未结束（疑似反沙箱空转或长解密循环）；加大预算后：`Ransom.HydraCrypt .exe` 跑到 **2212 万条**，`win33.exe` 跑到 **529 万条**。
- **有 API 行为记录**：16 个样本；**有 ★ 敏感行为**：13 个。
- **2026-10-18 起**：上表 65 个「PE32+（x64）跳过」不再跳过 —— x86-64 解释器上线后可直接执行
  （41 批次里 26 个 x64 已全部真跑，见「2026-10-18 增量」节）。

### 8. 真实行为证据（虚拟执行的收获）
`win33.exe`（静态只有分数）在虚拟执行中给出**可落地证据**：
```
[注册表] ★写入 LowRiskFileTypes = ".exe;.bat;.reg;.vbs;"     ← 降低系统"打开文件"安全提示（常见于下载者/勒索）
[注册表] ★写入 Digit = ""      [注册表] ★写入 S = ""      [注册表] ★写入 1806 = <4 字节> 00 00 00 00
[执行]   ★样本企图启动进程
```
这类"注册表持久化 + 放宽安全提示 + 起进程"的组合，是静态特征很难稳定命中的行为面，现在由虚拟执行直接给出。

---

## 四、已知边界（如实标注，不美化）

1. **PE32+（64 位）**：已支持（2026-10-18）—— x86-64 解释器按 ImageBase 低 32 位装载进 4GB 沙盒直接执行；`syscall`/`ud2`/`sysenter` 等系统指令仍如实停机（不猜、不硬走）。
2. **.NET 程序集**：x86 解释器不适用（入口是 `_CorExeMain`），需按 IL 静态/仿真另开一路（13 个样本）。
3. **未登记参数个数的 API**：按 0 参数处理，可能造成栈错位——已在日志中明确标注。
4. 部分样本停在 `0x00000000` / 离谱地址（如 `0xFC7C12E9`）：多属**反沙箱/异常处理（SEH）**路径——本沙盒不模拟 SEH/异常派发，故如实停机而非强行走下去。
5. 两个同族样本停在 `FF /7`（Intel 未定义编码，真实 CPU 会 `#UD`）：判定为**混淆/垃圾字节陷阱**，已输出机器码字节供人工核对。
6. 少数样本跳到 `imagebase+0xC`（即 DOS 头）执行：其 OEP 依赖被我们伪造的环境值（TEB/PEB/API 返回值），属于**环境仿真精度**问题，不是解释器崩溃。
7. `dump1.exe` 走的是**资源加载**路线（`FindResourceW/LoadResource/LockResource`），本沙盒尚未实现资源 API，故提前停机（其载荷已由阶段一 `--extract` 静态找回并判 `[SUSPICIOUS] 76.28`）。
8. 本沙盒**绝不执行真实机器码**：所有指令由解释器虚拟执行，所有 API 是假实现，落盘物只写自己的输出目录。
9. **"不属于 x86-32 的字节"**（真机必 `#UD` 的 `FF /7`、系统指令 `0F 00` 等）：解密后的数据被误当代码执行时会撞上，本沙盒如实停机并输出该处机器码字节供人工核对——不猜、不硬走。

---

## 七、2026-10-17 下午增量：加壳 PE 批量实测 + 接入扫描器主流程

### 1. 先补 9 条指令
`0xF8/0xF9/0xF5/0xFA/0xFB/0xFC/0xFD`（标志位控制）和 `0xD4/0xD5`（`aam/aad`）此前落在"未实现"分支——
凡是**一进壳就先清方向/进位标志**的样本，会在最开头就停机。补齐后同一批样本明显往前走：
`9f72fdfd….exe` 由"停在 `0xF8`"变为"越过 `aam` 混淆段、跑到 61.5 万条指令才遇 `取指越界 @0`"。
`--selftest`（阶段一 + 解释器两段）仍全绿。

### 2. 加壳 PE 批量实测（`H:\新建文件夹\_已解压` 中 41 个 `[PACKED]` PE）
| 取向 | 数量 | 说明 |
| --- | --- | --- |
| PE32+（x64） | 26 | 已用 PE 头 `Machine` 字段**逐一确认**（不是猜的），需 x64 解释器 |
| .NET 程序集 | 4 | CLR 数据目录非空，需 IL 分析 |
| 预算耗尽 | 4 | 15,000,000 条指令内未收尾（长解密循环或反沙箱空转） |
| 跳 `0x00000000` | 4 | 疑似依赖 SEH / 被伪造的环境返回值 |
| 未实现编码 | 3 | `FF /7`、`0F 00` 等"未定义编码陷阱" |
| **解出载荷 / 命中 OEP** | **0** | 本批没有能在预算内脱壳的 |

> **诚实结论**：这 41 个"加壳"里 26 个是 x64、4 个是 .NET，真正能喂给 x86-32 解释器的只有 15 个，
> 且这 15 个大多用"未定义编码 + SEH"挡路。**本轮虚拟执行没能在这一批上直接解出载荷**；
> 收获是把它归了类（x64 / .NET / 陷阱），并补齐了 9 条指令。

### 3. 2026-10-17 夜增量：INS/OUTS 按"非虚拟机"处理 + 输出目录名 ASCII 化

- 单字节 `0x6C..0x6F`（`INS/INSB/INSD`、`OUTS/OUTSB/OUTSD`）此前落到"未实现指令"分支——**这是误判**：
  32 位模式下它们是**合法真指令**（字符串端口 I/O），常被壳用来做反 VM 探测。现与 `IN/OUT` 一致，
  按"非虚拟机/空操作"处理（并写一条 `[反虚拟机]` 轨迹）。
- 实测证明有效：`2acc3c29….exe` 由"停在 `0x6E`（11.1 万条）"变为"越过 `0x6E`、跑到 11.2 万条才停在 `0F 00`"
  （`0F 00` 是 `SLDT/STR/LLDT…` 系统指令组，又一处反 VM 探测）。
- 41 个加壳 PE 的**分类未变**（x64 26 / .NET 4 / 预算耗尽 4 / 跳 `0` 4 / 未实现编码 3）—— 这是 10-17 当时（无 x64 解释器）的口径；
  原始日志与 `分类.csv` 在 `实测\加壳PE批量41_20261017夜\`。**10-18 起 x64 已可执行，终版分类见「2026-10-18 增量」节。**
- `--extract` 的输出子目录名 `_释放体` 改为 ASCII **`_extracted`**：旧中文名经 `fopen`（ANSI 路径）
  落盘会变成乱码目录名，改 ASCII 后路径干净、便于脚本引用（`njRAT_extracted\01_PE32_….bin`）。

### 3. 接入扫描器主流程（`scan_any.ps1`）
- **新增开关**：`-NoPevm`（关闭）、`-PevmAll`（所有 PE 都跑）、`-PevmMaxInsn N`、`-PevmMaxSec N`、`-PevmOutDir 路径`。
- **触发条件**：静态判定为 `[PACKED]` 的 PE（默认），或 `-PevmAll` 时的任意 PE；压缩包内的成员同样适用。
- **入口即分流**：只读 PE 头判断类型 —— `x86` 与 `x64` 都真跑（x64 走 x86-64 通路）；仅 `.NET` 只写一行"跳过 + 原因"，不做无谓的复制与执行。
- **输出**：独立标记 `[VM: 恶意行为]` / `[VM: 未见异常]` / `[VM: 无法定论]`，**不碰**既有机器标记，也不改 `== 汇总: … ==` 行；
  另给 `== 虚拟执行: … ==` 与 `== 动态找回: … ==` 两行独立统计。
- **闭环**：解壳产物自动再交 `scan.exe` 复扫，报毒的记为「动态找回」；产物另存到 `<目标>\_虚拟执行\<样本名>\`。
- **安全**：全程用户态解释器内完成，未加载真 DLL、未访问真注册表/网络；目录扫描会跳过 `_虚拟执行` 目录本身。

### 4. 验证记录
| 场景 | 结果 |
| --- | --- |
| 单文件 · x86 加壳（92 MB） | `[PACKED]` → 虚拟执行 61.5 万条 → `[VM: 未见异常]`；汇总/报毒率行与改前一致 |
| 单文件 · x64 加壳 | `[PACKED]` → 用户态 x86-64 解释执行 → `[VM: 未见异常]`（2026-10-18 起；此前为「跳过 → 无法定论」） |
| AES 加密 zip（密码 `infected`） | 成员管道扫描 `[PACKED]` → 解到临时目录 → 虚拟执行 → `[VM: 未见异常]` |
---

## 2026-10-18 增量：x86-64 解释器上线 + 41 批次重跑（终版）

### 1. x86-64 通路（独立自包含）
- 自有 64 位寄存器组 / `RIP` / `REX` 译码；**复用**同一套 4KB 惰性分页虚拟内存、区域与 API 桩子系统。
- PE32+ 按 **ImageBase 低 32 位**装载进 4GB 沙盒（如首选 0x140000000 → 沙盒 0x40000000，重定位照做）。
- `syscall` / `ud2` / `sysenter` / 未实现编码一律如实停机 —— 不猜、不硬走。

### 2. API 表第三轮补齐（以 ★ 点名为准）
- 新增 ~30 条表项 + 一批处理函数：宽字符 CRT（`lstrlenW/lstrcpyW/lstrcatW/lstrcmpA/W/lstrcmpiA/W`）、WinINet
  （`HttpOpenRequest` 及配套）、线程/句柄（`CreateThread` 环境、`DuplicateHandle`）、GUID（`CoCreateGuid/UuidToString`）、
  资源 API（先按"查无资源"语义登记：`FindResource/LoadResource/LockResource/SizeofResource` 全返回 0）、`RtlDecompressBuffer` 等。
- 收敛证据：`win33.exe` 的「未登记参数个数的 API」由 **54,583 → 0**；41 批次里只剩 fax / invoice 的 `Ordinal_*`
  （MFC42/SHLWAPI 序号导出，无法按名映射，如实保留点名）。

### 3. 41 批次重跑（新二进制，15,000,000 条 / 60 秒）
**41/41 全部真实执行**（26 x64 + 15 x86），终版分类：

| 类别 | 数量 | 说明 |
| --- | --- | --- |
| 正常结束 | 12 | 入口正常返回 / 正常退出（x64 里 5 个带 1 个已运行的工作线程） |
| 越界停机 | 10 | 取指/取数越界（多为自解码指针或数据区执行，逐样本日志可查） |
| .NET(需IL) | 4 | CLR 头非空 |
| 自毁(int0x29) | 4 | `__fastfail`，反调试/反篡改主动自毁 |
| 空转检测 | 3 | `pause/jmp` 自旋且不推进内存 —— 新空转判据直接收割 |
| 未实现编码 | 3 | 预解码指针指进 ASCII 数据等（如实停机） |
| 预算耗尽 | 3 | 15M 条内未收尾（长解密 / 反沙箱空转） |
| 主动退出 | 2 | `ExitProcess(0/2)`；其一跑了 889 万条指令才退出 |

x86 侧对比 10-17 夜版：4 个由「跳 0 / 未实现 / 预算耗尽」变为**正常结束**（705 ~ 1,899 条内）；
2 个由「跳 0」固化为 **int 0x29 自毁**。

> 产物：`实测\加壳PE批量41_20261018\`（41 份日志 + `分类.csv` + 与夜版差异清单）。

---

## 五、用法

```
pe_vm.exe --selftest                                  # 自检（虚拟内存 + 解释器）
pe_vm.exe --load   <样本>                             # 只解析装载视图，不执行
pe_vm.exe --extract <样本> [--outdir 目录]            # 静态释放体还原（不执行）
pe_vm.exe <样本> [--outdir 目录] [--trace 日志] \
         [--max-insn N] [--max-sec 秒]                # 虚拟执行 + 行为还原 + OEP/落地物
```

---

## 六、下一步

1. **x64 解释器（PE32+）—— 已完成（2026-10-18）**：41 批次里 26 个 x64 全部真跑（8 个正常结束，含 889 万条才退出的实活样本；
   2 个 int 0x29 自毁、3 个空转检测、2 个取指越界）。后续：x64 侧 SSE 整数完备与系统指令最小实现（`syscall` 等仍如实停机）。
2. **资源 API**（`FindResource/LoadResource/LockResource/SizeofResource`）—— 直接解锁 `dump1.exe` 这类"资源里藏载荷"的样本。
3. **SEH / 异常派发**最小实现 —— 把靠 `int3`+SEH 反调试的样本（`Setup_…`、`cmd.exe` 等）继续跑下去；
   本批另有 4 个停在 `取指越界 @0x00000000`，大概率也走这条路。
4. **.NET IL 旁路**（4 个）—— 入口即 `_CorExeMain`，需按 IL 静态/仿真另开一路，复用同一套虚拟内存与 API 层。
5. 释放体输出带正确扩展名（`.exe/.dll/.sys`）+ 父子清单，接入 `auto_analyze.ps1` 选靶。
6. **空转检测 —— 已完成（2026-10-18）**：相同 EIP 环 + `pause` 且不推进内存即判空转；
   本轮 41 批次里 3 个 x64 样本命中（此前它们要耗满预算才停）。
